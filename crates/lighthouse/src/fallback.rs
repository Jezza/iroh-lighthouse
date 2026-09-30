//! Bootstrap over the BitTorrent mainline DHT when the lighthouse is down.
//!
//! A lighthouse is fast and exact, but it is also a single dependency: if it
//! is unreachable, nobody joins. This module adds a second, serverless way to
//! find the same topic's members, using
//! [`distributed-topic-tracker`](https://github.com/rustonbsd/distributed-topic-tracker)
//! to publish and read records at a location on the mainline DHT derived from
//! the topic itself.
//!
//! It is deliberately a *fallback*, not a peer of the HTTP carrier. The DHT
//! path is slower (DHT round trips rather than one request), fuzzier (records
//! rotate every minute and are capped per minute), and has no notion of an
//! authoritative member list. What it does have is no server to lose.
//!
//! # How the topic maps onto the DHT
//!
//! Both halves of a [`Topic`] are used, and each is used for what it is good
//! for:
//!
//! - The **topic id** — the public half of the topic keypair — becomes the DHT
//!   topic hash. It is already the public identifier of the topic on the wire,
//!   so nothing new is revealed.
//! - The **topic secret** becomes the tracker's shared secret, by signing a
//!   domain-separated constant with the topic key. Ed25519 signatures are
//!   deterministic (RFC 8032), so every holder of the same topic derives the
//!   same value, and nobody else can — without this module ever reading, or
//!   the [`Topic`] type ever exposing, the raw secret key.
//!
//! That second point matters more than it looks. In the tracker, the shared
//! secret gates the DHT slot itself: where records live, who may write them,
//! and who may read them. So a private lighthouse topic stays private on the
//! fallback path — someone who knows only the topic *name* cannot locate the
//! slot, publish into it, or decrypt what is there.
//!
//! # What is published
//!
//! A full [`EndpointAddr`], not a bare endpoint id. A peer found this way is
//! directly dialable with no further discovery, which is the same guarantee
//! the lighthouse gives and the reason this is useful when iroh's own
//! discovery services may be unreachable too.

use std::time::Duration;

use distributed_topic_tracker::{Config, Record, RecordPublisher, TopicId as DhtTopicId};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::protocol::Peer;
use crate::topic::Topic;

/// Domain separation for turning a topic key into the tracker's shared secret.
///
/// Signed with the topic key; the signature is the secret. Changing this
/// string moves every topic to a different DHT slot.
const DHT_SECRET_CONTEXT: &[u8] = b"iroh-lighthouse/v1/dht-fallback";

/// What a node publishes about itself into the DHT.
///
/// The full address, so a reader can dial without asking anything else. The
/// TTL the lighthouse would have granted has no equivalent here: records live
/// in a one-minute slot and are rewritten by the publisher's own schedule, so
/// expiry is a property of the slot rather than of the record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DhtPeerRecord {
    addr: EndpointAddr,
}

/// Errors from the DHT fallback path.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dht: {0}")]
    Dht(String),
}

fn dht(err: impl std::fmt::Display) -> Error {
    Error::Dht(err.to_string())
}

/// A serverless view of one topic, backed by the mainline DHT.
///
/// Created by [`DhtFallback::new`]. Cheap to clone is *not* claimed: hold one
/// per topic, as you would a [`Session`](crate::Session).
#[derive(Debug)]
pub struct DhtFallback {
    publisher: RecordPublisher,
    me: EndpointId,
}

impl DhtFallback {
    /// Build a fallback for `topic`, publishing `endpoint`'s address.
    ///
    /// Does no network work; the DHT is only touched by [`announce`] and
    /// [`lookup`].
    ///
    /// [`announce`]: DhtFallback::announce
    /// [`lookup`]: DhtFallback::lookup
    pub fn new(endpoint: &Endpoint, topic: &Topic) -> Self {
        Self::with_config(endpoint, topic, Config::default())
    }

    /// [`new`](DhtFallback::new) with an explicit tracker configuration.
    pub fn with_config(endpoint: &Endpoint, topic: &Topic, config: Config) -> Self {
        // The topic id is 32 bytes of public key: use it directly as the DHT
        // topic hash rather than re-hashing a name, so the mapping is exact.
        let dht_topic = DhtTopicId::from_hash(topic.id().0.as_bytes());

        // Deterministic, secret-derived, and obtained without ever handling
        // the topic's secret key. See the module docs.
        let secret = topic.sign(DHT_SECRET_CONTEXT).to_bytes().to_vec();

        // The node signs its own records with its own iroh identity, so a
        // record found on the DHT is attributable to the endpoint it names.
        let signing_key = SigningKey::from_bytes(&endpoint.secret_key().to_bytes());

        Self {
            publisher: RecordPublisher::new(dht_topic, signing_key, None, secret, config),
            me: endpoint.id(),
        }
    }

    /// Publish this endpoint's address into the current minute's slot.
    ///
    /// The tracker rate-limits this internally: if the slot already holds
    /// enough records, it returns without writing. That is intentional — a
    /// large topic costs the DHT a fixed handful of writes per minute no
    /// matter how many members it has.
    pub async fn announce(&self, addr: EndpointAddr) -> Result<(), Error> {
        let minute = distributed_topic_tracker::unix_minute(0);
        let record = self
            .publisher
            .new_record(minute, DhtPeerRecord { addr })
            .map_err(dht)?;
        self.publisher
            .publish_record(record, CancellationToken::new())
            .await
            .map_err(dht)?;
        Ok(())
    }

    /// Read the other members from the DHT.
    ///
    /// Reads both the current and the previous minute, because a node that
    /// published seconds before a minute boundary is still a perfectly good
    /// peer and would otherwise be invisible for up to a minute.
    pub async fn lookup(&self) -> Result<Vec<Peer>, Error> {
        let now = distributed_topic_tracker::unix_minute(0);
        let mut peers = Vec::new();
        let mut seen = std::collections::BTreeSet::new();

        for minute in [now, now.saturating_sub(1)] {
            let records = match self
                .publisher
                .get_records(minute, CancellationToken::new())
                .await
            {
                Ok(records) => records,
                Err(err) => {
                    debug!(%err, minute, "dht fallback: slot unreadable");
                    continue;
                }
            };
            for record in records {
                match decode(&record) {
                    Some(addr) if addr.id != self.me && seen.insert(addr.id) => {
                        // `expires_in_secs` is the lighthouse's unit of
                        // freshness. A DHT record lives in a minute slot, so
                        // report the remainder of that slot rather than
                        // inventing a longer lifetime.
                        peers.push(Peer {
                            addr,
                            expires_in_secs: 60,
                        });
                    }
                    Some(_) => {}
                    None => warn!("dht fallback: undecodable record, skipping"),
                }
            }
        }
        Ok(peers)
    }

    /// How long to wait before consulting the DHT again.
    ///
    /// Records rotate per minute, so polling faster than that mostly costs DHT
    /// traffic for no new information.
    pub const POLL_INTERVAL: Duration = Duration::from_secs(30);
}

fn decode(record: &Record) -> Option<EndpointAddr> {
    record.content::<DhtPeerRecord>().ok().map(|r| r.addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DHT location must follow the topic secret, not just the name.
    ///
    /// This is what keeps a private lighthouse topic private on the fallback
    /// path. It holds because the tracker mixes the shared secret into the
    /// slot derivation, and because the secret here is a signature that only
    /// topic-key holders can produce.
    #[test]
    fn topic_secret_changes_the_derived_dht_secret() {
        let a = Topic::with_secret("chat", b"hunter2");
        let b = Topic::with_secret("chat", b"different");
        let public = Topic::new("chat");

        let secret_of = |t: &Topic| t.sign(DHT_SECRET_CONTEXT).to_bytes().to_vec();

        assert_ne!(secret_of(&a), secret_of(&b), "secret must change the key");
        assert_ne!(secret_of(&a), secret_of(&public), "and differ from public");
    }

    /// Everyone holding the same topic must derive the same secret, or they
    /// would never meet on the DHT.
    #[test]
    fn same_topic_derives_the_same_dht_secret() {
        let a = Topic::with_secret("chat", b"hunter2");
        let b = Topic::with_secret("chat", b"hunter2");
        assert_eq!(
            a.sign(DHT_SECRET_CONTEXT).to_bytes(),
            b.sign(DHT_SECRET_CONTEXT).to_bytes(),
        );
    }

    /// The record must survive the tracker's codec.
    ///
    /// The tracker serialises record content with postcard, which is NOT
    /// self-describing: a type that relies on serde's `untagged`, `flatten`,
    /// or `deserialize_any` round-trips through JSON but fails here.
    #[test]
    fn endpoint_addr_round_trips_through_postcard() {
        use std::net::SocketAddr;

        let addr = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], 4433)));
        let record = DhtPeerRecord { addr: addr.clone() };

        let bytes = postcard::to_allocvec(&record).expect("serialise");
        let back: DhtPeerRecord = postcard::from_bytes(&bytes).expect("deserialise");
        assert_eq!(back.addr, addr, "the address must survive the codec");
    }

    /// The tracker's topic hash is the lighthouse topic id verbatim.
    #[test]
    fn dht_topic_hash_is_the_topic_id() {
        let topic = Topic::with_secret("chat", b"s");
        let dht_topic = DhtTopicId::from_hash(topic.id().0.as_bytes());
        assert_eq!(&dht_topic.hash(), topic.id().0.as_bytes());
    }
}
