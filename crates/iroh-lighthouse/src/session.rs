//! A topic membership that keeps itself registered.

use std::time::Duration;

use iroh::{Endpoint, Watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::client::{Error, Lighthouse};
use crate::protocol::Peer;
use crate::topic::Topic;

/// Shortest interval between scheduled re-announces.
const MIN_REFRESH: Duration = Duration::from_secs(1);
/// Backoff bounds when the lighthouse is unreachable.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long to let address changes settle before re-announcing.
const ADDR_DEBOUNCE: Duration = Duration::from_millis(500);

/// A node's live registration on one topic.
///
/// Created by [`Lighthouse::join`]. A background task re-announces at half the
/// granted TTL, re-announces when the endpoint's address changes, and retries
/// with backoff when the lighthouse is unreachable. Dropping the session stops
/// the task without unregistering; the entry then ages out on the lighthouse.
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
    ) -> Result<Self, Error> {
        let announced = lighthouse
            .announce(endpoint.secret_key(), Some(&topic), endpoint.addr(), ttl)
            .await?;
        let (peers, _) = watch::channel(announced.peers);
        let task = tokio::spawn(run(
            lighthouse.clone(),
            endpoint.clone(),
            topic.clone(),
            ttl,
            announced.ttl,
            peers.clone(),
        ));
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

    /// The other members as of the last successful announce.
    pub fn peers(&self) -> Vec<Peer> {
        self.peers.borrow().clone()
    }

    /// A receiver that yields the peer list after every successful announce.
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
        self.peers.send_replace(announced.peers.clone());
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

fn refresh_interval(granted: Duration) -> Duration {
    (granted / 2).max(MIN_REFRESH)
}

async fn run(
    lighthouse: Lighthouse,
    endpoint: Endpoint,
    topic: Topic,
    requested_ttl: Duration,
    granted_ttl: Duration,
    peers: watch::Sender<Vec<Peer>>,
) {
    let mut addr_watcher = endpoint.watch_addr();
    let mut backoff = INITIAL_BACKOFF;
    let mut next_wait = refresh_interval(granted_ttl);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(next_wait) => {}
            changed = addr_watcher.updated() => {
                if changed.is_err() {
                    debug!(topic = %topic.id(), "endpoint closed, session task ending");
                    return;
                }
                tokio::time::sleep(ADDR_DEBOUNCE).await;
            }
        }
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
                peers.send_replace(announced.peers);
                backoff = INITIAL_BACKOFF;
                next_wait = refresh_interval(announced.ttl);
            }
            Err(err) => {
                warn!(topic = %topic.id(), %err, retry_in = ?backoff, "announce failed");
                next_wait = backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
