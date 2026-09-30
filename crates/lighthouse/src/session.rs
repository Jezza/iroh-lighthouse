//! A topic membership that keeps itself registered and watches the others.

use std::collections::BTreeSet;
use std::time::Duration;
#[cfg(feature = "dht-fallback")]
use std::sync::Arc;

use iroh::{Endpoint, EndpointAddr, EndpointId, Watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::client::{Error, Lighthouse};
#[cfg(feature = "dht-fallback")]
use crate::client::Announced;
use crate::protocol::Peer;
use crate::topic::Topic;
#[cfg(feature = "dht-fallback")]
use crate::fallback::DhtFallback;

/// How often a session polls the topic for membership changes unless
/// [`Lighthouse::join_with`] says otherwise.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Shortest interval between scheduled re-announces or polls.
const MIN_REFRESH: Duration = Duration::from_secs(1);
/// Backoff bounds when the lighthouse is unreachable.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long to let address changes settle before re-announcing.
const ADDR_DEBOUNCE: Duration = Duration::from_millis(500);
/// Stand-in deadline when `now + interval` would overflow.
const FAR_FUTURE: Duration = Duration::from_secs(30 * 365 * 24 * 3600);

/// A node's live registration on one topic.
///
/// Created by [`Lighthouse::join`] or [`Lighthouse::join_with`]. A background
/// task re-announces at half the granted TTL, re-announces when the endpoint's
/// address changes, retries with backoff when the lighthouse is unreachable,
/// and polls the topic on a fixed interval so [`Session::watch_peers`] sees
/// members come, go, and move long before the next keep-alive. Dropping the
/// session stops the task without unregistering; the entry then ages out on
/// the lighthouse.
///
/// With the `dht-fallback` feature and [`Lighthouse::join_with_fallback`], the
/// same session also publishes to and reads from the mainline DHT whenever the
/// lighthouse is unreachable, so a topic survives the server being down.
#[derive(Debug)]
pub struct Session {
    lighthouse: Lighthouse,
    endpoint: Endpoint,
    topic: Topic,
    requested_ttl: Duration,
    peers: watch::Sender<Vec<Peer>>,
    task: JoinHandle<()>,
}

impl Session {
    pub(crate) async fn start(
        lighthouse: Lighthouse,
        endpoint: Endpoint,
        topic: Topic,
        ttl: Duration,
        poll_interval: Option<Duration>,
        #[cfg(feature = "dht-fallback")] fallback: Option<Arc<DhtFallback>>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "dht-fallback")]
        let announced = match lighthouse
            .announce(endpoint.secret_key(), Some(&topic), endpoint.addr(), ttl)
            .await
        {
            Ok(announced) => announced,
            // The lighthouse is already down at join time. With a fallback
            // configured that is survivable rather than fatal: seed from the
            // DHT and let the background task keep trying the lighthouse.
            Err(err) => match &fallback {
                Some(dht) => {
                    warn!(topic = %topic.id(), %err, "lighthouse unreachable, joining via dht");
                    seed_from_dht(dht, endpoint.addr(), ttl).await?
                }
                None => return Err(err),
            },
        };
        #[cfg(not(feature = "dht-fallback"))]
        let announced = lighthouse
            .announce(endpoint.secret_key(), Some(&topic), endpoint.addr(), ttl)
            .await?;

        let (peers, _) = watch::channel(announced.peers);
        let task = tokio::spawn(run(Task {
            lighthouse: lighthouse.clone(),
            endpoint: endpoint.clone(),
            topic: topic.clone(),
            requested_ttl: ttl,
            granted_ttl: announced.ttl,
            poll_interval: poll_interval.map(|interval| interval.max(MIN_REFRESH)),
            peers: peers.clone(),
            #[cfg(feature = "dht-fallback")]
            fallback,
        }));
        Ok(Self {
            lighthouse,
            endpoint,
            topic,
            requested_ttl: ttl,
            peers,
            task,
        })
    }

    /// The topic this session is registered on.
    pub fn topic(&self) -> &Topic {
        &self.topic
    }

    /// The other members as of the last successful announce or poll.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers.borrow().clone()
    }

    /// A receiver that wakes whenever another member joins, leaves, or changes
    /// address. The list it holds is always the latest one, so `expires_in_secs`
    /// can move without a wake-up.
    pub fn watch_peers(&self) -> watch::Receiver<Vec<Peer>> {
        self.peers.subscribe()
    }

    /// Announce now, outside the regular schedule, and return the peers.
    pub async fn refresh(&self) -> Result<Vec<Peer>, Error> {
        let announced = self
            .lighthouse
            .announce(
                self.endpoint.secret_key(),
                Some(&self.topic),
                self.endpoint.addr(),
                self.requested_ttl,
            )
            .await?;
        publish(&self.peers, announced.peers.clone());
        Ok(announced.peers)
    }

    /// Unregister from the topic and stop the background task.
    pub async fn leave(self) -> Result<(), Error> {
        self.task.abort();
        self.lighthouse
            .announce(
                self.endpoint.secret_key(),
                Some(&self.topic),
                self.endpoint.addr(),
                Duration::ZERO,
            )
            .await?;
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Store `latest` and wake watchers only if membership or an address changed.
fn publish(peers: &watch::Sender<Vec<Peer>>, latest: Vec<Peer>) {
    peers.send_if_modified(|current| {
        let changed = addrs(current) != addrs(&latest);
        *current = latest;
        changed
    });
}

fn addrs(peers: &[Peer]) -> BTreeSet<&EndpointAddr> {
    peers.iter().map(|peer| &peer.addr).collect()
}

fn without(peers: Vec<Peer>, id: EndpointId) -> Vec<Peer> {
    peers
        .into_iter()
        .filter(|peer| peer.addr.id != id)
        .collect()
}

fn refresh_interval(granted: Duration) -> Duration {
    (granted / 2).max(MIN_REFRESH)
}

fn deadline(after: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(after).unwrap_or(now + FAR_FUTURE)
}

struct Task {
    lighthouse: Lighthouse,
    endpoint: Endpoint,
    topic: Topic,
    requested_ttl: Duration,
    granted_ttl: Duration,
    poll_interval: Option<Duration>,
    peers: watch::Sender<Vec<Peer>>,
    #[cfg(feature = "dht-fallback")]
    fallback: Option<Arc<DhtFallback>>,
}

/// Read the topic from the DHT, then publish into it.
///
/// Shaped like an [`Announced`] so the caller cannot tell which path produced
/// the peers. The TTL reported is the one that was requested: the DHT has no
/// grant to return, and pretending otherwise would make the keep-alive
/// schedule jump around when the lighthouse comes back.
///
/// **Read before write, and it must stay that way.** All publishers on a topic
/// share one BEP44 mutable item, and a storing node keeps a single value per
/// `(key, salt)`. Publishing therefore tends to displace what is already
/// there. Measured against the live DHT with the announce first: the second
/// node to publish saw *zero* peers, because its own write had replaced the
/// record it was about to read. Reading first makes the same exchange
/// symmetric. This is also why the tracker's own bootstrap loop reads before
/// it publishes.
#[cfg(feature = "dht-fallback")]
async fn seed_from_dht(
    dht: &DhtFallback,
    addr: EndpointAddr,
    ttl: Duration,
) -> Result<Announced, Error> {
    let peers = dht
        .lookup()
        .await
        .map_err(|err| Error::Iroh(format!("dht fallback: {err}")))?;

    // Publishing is best-effort: the tracker declines to write when the
    // current minute's slot is already full, which is not a failure.
    if let Err(err) = dht.announce(addr).await {
        debug!(%err, "dht fallback: publish skipped");
    }
    Ok(Announced { ttl, peers })
}

async fn run(task: Task) {
    let Task {
        lighthouse,
        endpoint,
        topic,
        requested_ttl,
        granted_ttl,
        poll_interval,
        peers,
        #[cfg(feature = "dht-fallback")]
        fallback,
    } = task;
    let mut addr_watcher = endpoint.watch_addr();
    let mut backoff = INITIAL_BACKOFF;
    // Both timers are reset explicitly rather than recreated each iteration,
    // so a poll firing never pushes back the keep-alive or vice versa.
    let announce_at = tokio::time::sleep_until(deadline(refresh_interval(granted_ttl)));
    tokio::pin!(announce_at);
    let poll = poll_interval.unwrap_or(MIN_REFRESH);
    let poll_at = tokio::time::sleep_until(deadline(poll));
    tokio::pin!(poll_at);

    loop {
        let announce = tokio::select! {
            _ = &mut announce_at => true,
            changed = addr_watcher.updated() => {
                if changed.is_err() {
                    debug!(topic = %topic.id(), "endpoint closed, session task ending");
                    return;
                }
                tokio::time::sleep(ADDR_DEBOUNCE).await;
                true
            }
            _ = &mut poll_at, if poll_interval.is_some() => false,
        };

        if announce {
            match lighthouse
                .announce(
                    endpoint.secret_key(),
                    Some(&topic),
                    endpoint.addr(),
                    requested_ttl,
                )
                .await
            {
                Ok(announced) => {
                    publish(&peers, announced.peers);
                    backoff = INITIAL_BACKOFF;
                    announce_at
                        .as_mut()
                        .reset(deadline(refresh_interval(announced.ttl)));
                    // The announce just returned fresh peers; space the next poll from here.
                    poll_at.as_mut().reset(deadline(poll));
                }
                Err(err) => {
                    // The lighthouse is unreachable. Keep the topic alive over
                    // the DHT if one is configured, then retry the lighthouse
                    // on the usual backoff — the fallback is a stand-in, not a
                    // replacement, so we never stop trying to get back.
                    #[cfg(feature = "dht-fallback")]
                    if let Some(dht) = &fallback {
                        match seed_from_dht(dht, endpoint.addr(), requested_ttl).await {
                            Ok(announced) => {
                                debug!(
                                    topic = %topic.id(),
                                    peers = announced.peers.len(),
                                    "announced over dht while the lighthouse is down"
                                );
                                publish(&peers, without(announced.peers, endpoint.id()));
                            }
                            Err(dht_err) => {
                                warn!(topic = %topic.id(), %dht_err, "dht fallback failed too");
                            }
                        }
                    }
                    warn!(topic = %topic.id(), %err, retry_in = ?backoff, "announce failed");
                    announce_at.as_mut().reset(deadline(backoff));
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        } else {
            match lighthouse.lookup(&topic).await {
                Ok(members) => publish(&peers, without(members, endpoint.id())),
                Err(err) => {
                    debug!(topic = %topic.id(), %err, "poll failed");
                    // A failed poll is the other place the lighthouse's absence
                    // shows up. Read the DHT so membership keeps moving rather
                    // than freezing at the last known list.
                    #[cfg(feature = "dht-fallback")]
                    if let Some(dht) = &fallback {
                        match dht.lookup().await {
                            Ok(members) => publish(&peers, without(members, endpoint.id())),
                            Err(dht_err) => {
                                debug!(topic = %topic.id(), %dht_err, "dht poll failed too");
                            }
                        }
                    }
                }
            }
            poll_at.as_mut().reset(deadline(poll));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::SecretKey;

    use super::*;

    fn peer(port: u16, expires_in_secs: u32) -> Peer {
        Peer {
            addr: EndpointAddr::new(SecretKey::generate().public())
                .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port))),
            expires_in_secs,
        }
    }

    fn aged(peer: &Peer, expires_in_secs: u32) -> Peer {
        Peer {
            addr: peer.addr.clone(),
            expires_in_secs,
        }
    }

    #[test]
    fn publish_wakes_only_when_membership_or_addresses_change() {
        let (a, b) = (peer(1, 60), peer(2, 60));
        let (tx, mut rx) = watch::channel(vec![a.clone(), b.clone()]);

        publish(&tx, vec![aged(&b, 50), aged(&a, 40)]);
        assert!(
            !rx.has_changed().unwrap(),
            "reordering and ageing are not changes"
        );
        assert_eq!(
            tx.borrow()[1].expires_in_secs,
            40,
            "but the list is updated"
        );

        publish(&tx, vec![aged(&a, 30)]);
        assert!(rx.has_changed().unwrap(), "a member left");
        rx.mark_unchanged();

        let moved = Peer {
            addr: EndpointAddr::new(a.addr.id).with_ip_addr(SocketAddr::from(([10, 0, 0, 1], 9))),
            expires_in_secs: 30,
        };
        publish(&tx, vec![moved]);
        assert!(rx.has_changed().unwrap(), "a member changed address");
        rx.mark_unchanged();

        publish(&tx, vec![aged(&a, 20), peer(3, 60)]);
        assert!(rx.has_changed().unwrap(), "a member joined");
    }

    #[test]
    fn without_drops_only_the_given_id() {
        let (a, b) = (peer(1, 60), peer(2, 60));
        let rest = without(vec![a.clone(), b.clone()], a.addr.id);
        assert_eq!(rest, vec![b]);
    }
}
