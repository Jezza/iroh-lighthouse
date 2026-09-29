//! In-memory registry of topic members and directory entries.
//!
//! All times are unix seconds. The registry is pure data: it never reads the
//! clock itself, which keeps expiry logic deterministic in tests.

use std::collections::HashMap;

use iroh::{EndpointAddr, EndpointId};
use iroh_lighthouse::TopicId;
use iroh_lighthouse::protocol::Peer;
use serde::{Deserialize, Serialize};

/// One registered node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub addr: EndpointAddr,
    /// Unix seconds after which the entry is dead.
    pub expires_at: u64,
    /// Unix seconds of the last successful announce, for ordering.
    pub refreshed_at: u64,
}

impl Entry {
    /// Expiry is exclusive: an entry whose `expires_at` equals `now` is dead.
    pub fn is_live(&self, now: u64) -> bool {
        self.expires_at > now
    }

    fn to_peer(&self, now: u64) -> Peer {
        Peer {
            addr: self.addr.clone(),
            expires_in_secs: u32::try_from(self.expires_at.saturating_sub(now)).unwrap_or(u32::MAX),
        }
    }
}

/// Size limits enforced on registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimits {
    pub max_peers_per_topic: usize,
    pub max_topics: usize,
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("topic already holds the maximum number of peers")]
    TopicFull,
    #[error("lighthouse already holds the maximum number of topics")]
    TooManyTopics,
}

/// Topic members plus the directory. Serialisable as the snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    topics: HashMap<TopicId, HashMap<EndpointId, Entry>>,
    directory: HashMap<EndpointId, Entry>,
    #[serde(skip)]
    dirty: bool,
}

impl Registry {
    /// Register `addr` on `topic`, or in the directory when `topic` is `None`.
    ///
    /// Refreshing a live entry always succeeds; only new or expired entries
    /// count against the per-topic limit. A topic counts against the topic
    /// limit until a sweep removes it.
    pub fn announce(
        &mut self,
        topic: Option<TopicId>,
        addr: EndpointAddr,
        now: u64,
        expires_at: u64,
        limits: SizeLimits,
    ) -> Result<(), RegistryError> {
        let id = addr.id;
        let entry = Entry {
            addr,
            expires_at,
            refreshed_at: now,
        };
        match topic {
            None => {
                self.directory.insert(id, entry);
            }
            Some(topic) => {
                match self.topics.get(&topic) {
                    None if self.topics.len() >= limits.max_topics => {
                        return Err(RegistryError::TooManyTopics);
                    }
                    None => {}
                    Some(members) => {
                        let already_live = members.get(&id).is_some_and(|e| e.is_live(now));
                        if !already_live {
                            let live = members.values().filter(|e| e.is_live(now)).count();
                            if live >= limits.max_peers_per_topic {
                                return Err(RegistryError::TopicFull);
                            }
                        }
                    }
                }
                self.topics.entry(topic).or_default().insert(id, entry);
            }
        }
        self.dirty = true;
        Ok(())
    }

    /// Remove `id` from `topic`, or from the directory when `topic` is `None`.
    /// Returns whether anything was removed.
    pub fn unregister(&mut self, topic: Option<TopicId>, id: &EndpointId) -> bool {
        let removed = match topic {
            None => self.directory.remove(id).is_some(),
            Some(topic) => match self.topics.get_mut(&topic) {
                Some(members) => {
                    let removed = members.remove(id).is_some();
                    if members.is_empty() {
                        self.topics.remove(&topic);
                    }
                    removed
                }
                None => false,
            },
        };
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Live members of a topic, most recently refreshed first.
    pub fn lookup(&self, topic: &TopicId, now: u64) -> Vec<Peer> {
        let Some(members) = self.topics.get(topic) else {
            return Vec::new();
        };
        let mut live: Vec<&Entry> = members.values().filter(|e| e.is_live(now)).collect();
        live.sort_by(|a, b| {
            b.refreshed_at
                .cmp(&a.refreshed_at)
                .then_with(|| a.addr.id.cmp(&b.addr.id))
        });
        live.into_iter().map(|e| e.to_peer(now)).collect()
    }

    /// Live directory entry for `id`.
    pub fn resolve(&self, id: &EndpointId, now: u64) -> Option<Peer> {
        self.directory
            .get(id)
            .filter(|e| e.is_live(now))
            .map(|e| e.to_peer(now))
    }

    /// Drop every expired entry and every empty topic. Returns how many entries went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let mut removed = 0;
        self.topics.retain(|_, members| {
            let before = members.len();
            members.retain(|_, e| e.is_live(now));
            removed += before - members.len();
            !members.is_empty()
        });
        let before = self.directory.len();
        self.directory.retain(|_, e| e.is_live(now));
        removed += before - self.directory.len();
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    /// Whether anything changed since the last call, and reset the flag.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Number of topics currently stored, including ones with only expired members.
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }

    /// Number of directory entries currently stored, including expired ones.
    pub fn directory_len(&self) -> usize {
        self.directory.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::SecretKey;
    use iroh_lighthouse::Topic;

    use super::*;

    const LIMITS: SizeLimits = SizeLimits {
        max_peers_per_topic: 2,
        max_topics: 2,
    };

    fn addr(port: u16) -> EndpointAddr {
        EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn ids(peers: &[Peer]) -> Vec<EndpointId> {
        peers.iter().map(|p| p.addr.id).collect()
    }

    #[test]
    fn announce_then_lookup_returns_peer_with_remaining_ttl() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let a = addr(1);
        reg.announce(Some(t), a.clone(), 100, 160, LIMITS).unwrap();

        let peers = reg.lookup(&t, 110);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, a);
        assert_eq!(peers[0].expires_in_secs, 50);
    }

    #[test]
    fn expired_entries_are_hidden_from_lookup_before_sweep() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        reg.announce(Some(t), addr(1), 100, 160, LIMITS).unwrap();
        assert!(reg.lookup(&t, 160).is_empty(), "expiry is exclusive");
        assert_eq!(reg.topic_count(), 1, "not yet swept");
    }

    #[test]
    fn lookup_orders_most_recently_refreshed_first() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let (a, b) = (addr(1), addr(2));
        reg.announce(Some(t), a.clone(), 100, 1000, LIMITS).unwrap();
        reg.announce(Some(t), b.clone(), 105, 1000, LIMITS).unwrap();
        assert_eq!(ids(&reg.lookup(&t, 110)), vec![b.id, a.id]);

        reg.announce(Some(t), a.clone(), 120, 1000, LIMITS).unwrap();
        assert_eq!(ids(&reg.lookup(&t, 125)), vec![a.id, b.id]);
    }

    #[test]
    fn refresh_replaces_address_and_expiry() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let a = addr(1);
        let moved = EndpointAddr::new(a.id).with_ip_addr(SocketAddr::from(([10, 0, 0, 1], 9)));
        reg.announce(Some(t), a, 100, 160, LIMITS).unwrap();
        reg.announce(Some(t), moved.clone(), 150, 400, LIMITS)
            .unwrap();

        let peers = reg.lookup(&t, 200);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, moved);
        assert_eq!(peers[0].expires_in_secs, 200);
    }

    #[test]
    fn topic_full_rejects_new_member_but_allows_refresh() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let (a, b, c) = (addr(1), addr(2), addr(3));
        reg.announce(Some(t), a.clone(), 100, 1000, LIMITS).unwrap();
        reg.announce(Some(t), b, 100, 1000, LIMITS).unwrap();
        assert_eq!(
            reg.announce(Some(t), c, 100, 1000, LIMITS),
            Err(RegistryError::TopicFull)
        );
        assert_eq!(reg.announce(Some(t), a, 101, 1000, LIMITS), Ok(()));
    }

    #[test]
    fn expired_members_do_not_count_toward_topic_limit() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        reg.announce(Some(t), addr(1), 100, 110, LIMITS).unwrap();
        reg.announce(Some(t), addr(2), 100, 110, LIMITS).unwrap();
        assert_eq!(reg.announce(Some(t), addr(3), 120, 1000, LIMITS), Ok(()));
    }

    #[test]
    fn too_many_topics_rejects_new_topic_but_allows_existing() {
        let mut reg = Registry::default();
        let (t1, t2, t3) = (
            Topic::new("1").id(),
            Topic::new("2").id(),
            Topic::new("3").id(),
        );
        reg.announce(Some(t1), addr(1), 100, 1000, LIMITS).unwrap();
        reg.announce(Some(t2), addr(2), 100, 1000, LIMITS).unwrap();
        assert_eq!(
            reg.announce(Some(t3), addr(3), 100, 1000, LIMITS),
            Err(RegistryError::TooManyTopics)
        );
        assert_eq!(reg.announce(Some(t1), addr(4), 100, 1000, LIMITS), Ok(()));
    }

    #[test]
    fn unregister_removes_only_that_member() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let (a, b) = (addr(1), addr(2));
        reg.announce(Some(t), a.clone(), 100, 1000, LIMITS).unwrap();
        reg.announce(Some(t), b.clone(), 100, 1000, LIMITS).unwrap();
        assert!(reg.unregister(Some(t), &a.id));
        assert!(!reg.unregister(Some(t), &a.id), "second removal is a no-op");
        assert_eq!(ids(&reg.lookup(&t, 100)), vec![b.id]);
    }

    #[test]
    fn directory_is_separate_from_topics() {
        let mut reg = Registry::default();
        let t = Topic::new("t").id();
        let (member, published) = (addr(1), addr(2));
        reg.announce(Some(t), member.clone(), 100, 1000, LIMITS)
            .unwrap();
        reg.announce(None, published.clone(), 100, 1000, LIMITS)
            .unwrap();

        assert_eq!(
            reg.resolve(&member.id, 100),
            None,
            "topic members are not resolvable"
        );
        let peer = reg.resolve(&published.id, 100).unwrap();
        assert_eq!(peer.addr, published);
        assert_eq!(peer.expires_in_secs, 900);
        assert_eq!(
            ids(&reg.lookup(&t, 100)),
            vec![member.id],
            "publish does not join topics"
        );

        assert!(reg.unregister(None, &published.id));
        assert_eq!(reg.resolve(&published.id, 100), None);
    }

    #[test]
    fn resolve_hides_expired_entries() {
        let mut reg = Registry::default();
        let a = addr(1);
        reg.announce(None, a.clone(), 100, 160, LIMITS).unwrap();
        assert!(reg.resolve(&a.id, 159).is_some());
        assert!(reg.resolve(&a.id, 160).is_none());
    }

    #[test]
    fn directory_ignores_topic_limits() {
        let mut reg = Registry::default();
        for port in 1..=5 {
            reg.announce(None, addr(port), 100, 1000, LIMITS).unwrap();
        }
        assert_eq!(reg.directory_len(), 5);
    }

    #[test]
    fn sweep_removes_expired_entries_and_empty_topics() {
        let mut reg = Registry::default();
        let (t1, t2) = (Topic::new("1").id(), Topic::new("2").id());
        reg.announce(Some(t1), addr(1), 100, 150, LIMITS).unwrap();
        reg.announce(Some(t1), addr(2), 100, 500, LIMITS).unwrap();
        reg.announce(Some(t2), addr(3), 100, 150, LIMITS).unwrap();
        reg.announce(None, addr(4), 100, 150, LIMITS).unwrap();
        reg.announce(None, addr(5), 100, 500, LIMITS).unwrap();

        assert_eq!(reg.sweep(200), 3);
        assert_eq!(reg.topic_count(), 1);
        assert_eq!(reg.lookup(&t1, 200).len(), 1);
        assert_eq!(reg.directory_len(), 1);
        assert_eq!(reg.sweep(200), 0);
    }

    #[test]
    fn dirty_flag_tracks_mutations() {
        let mut reg = Registry::default();
        assert!(!reg.take_dirty());
        let t = Topic::new("t").id();
        let a = addr(1);
        reg.announce(Some(t), a.clone(), 100, 150, LIMITS).unwrap();
        assert!(reg.take_dirty());
        assert!(!reg.take_dirty());
        reg.lookup(&t, 100);
        assert!(!reg.take_dirty(), "reads are not mutations");
        reg.unregister(Some(t), &a.id);
        assert!(reg.take_dirty());
        assert_eq!(reg.sweep(100), 0);
        assert!(
            !reg.take_dirty(),
            "a sweep that removes nothing is not a change"
        );
    }

    #[test]
    fn registry_round_trips_through_json() {
        let mut reg = Registry::default();
        reg.announce(Some(Topic::new("t").id()), addr(1), 100, 150, LIMITS)
            .unwrap();
        reg.announce(None, addr(2), 100, 150, LIMITS).unwrap();
        reg.take_dirty();
        let json = serde_json::to_string(&reg).unwrap();
        let back: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }
}
