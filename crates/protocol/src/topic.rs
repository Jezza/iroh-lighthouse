//! Topics and the keypair derived from them.

use std::fmt;
use std::str::FromStr;

use iroh::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

/// Domain separation context for deriving a topic key from a name and secret.
const TOPIC_KEY_CONTEXT: &str = "iroh-lighthouse/v1/topic";

/// The wire identifier of a topic: the public half of the derived topic key.
///
/// Safe to log. Knowing the id lets you verify topic signatures but not create them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TopicId(pub PublicKey);

impl fmt::Debug for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TopicId({})", self.0)
    }
}

impl fmt::Display for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for TopicId {
    type Err = iroh::KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_str(s).map(TopicId)
    }
}

/// A topic: a human-readable name plus an optional secret.
///
/// The topic keypair is derived deterministically from both, so every client that
/// knows the same name and secret arrives at the same [`TopicId`]. The lighthouse
/// only ever sees the id and signatures made with the key.
#[derive(Clone)]
pub struct Topic {
    name: String,
    key: SecretKey,
}

impl fmt::Debug for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Topic")
            .field("name", &self.name)
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl Topic {
    /// A public topic: anyone who knows the name can derive the same key.
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_secret(name, b"")
    }

    /// A private topic: only holders of the secret can derive the key.
    pub fn with_secret(name: impl Into<String>, secret: &[u8]) -> Self {
        let name = name.into();
        let mut hasher = blake3::Hasher::new_derive_key(TOPIC_KEY_CONTEXT);
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(secret);
        let key = SecretKey::from_bytes(hasher.finalize().as_bytes());
        Self { name, key }
    }

    /// The human-readable name this topic was created from.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The wire identifier of this topic.
    pub fn id(&self) -> TopicId {
        TopicId(self.key.public())
    }

    /// Sign a message with the topic key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key.sign(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_name_derives_same_id() {
        assert_eq!(Topic::new("chat").id(), Topic::new("chat").id());
    }

    #[test]
    fn different_names_derive_different_ids() {
        assert_ne!(Topic::new("chat").id(), Topic::new("chat2").id());
    }

    #[test]
    fn empty_secret_equals_public_topic() {
        assert_eq!(
            Topic::new("chat").id(),
            Topic::with_secret("chat", b"").id()
        );
    }

    #[test]
    fn secret_changes_id() {
        assert_ne!(
            Topic::new("chat").id(),
            Topic::with_secret("chat", b"hunter2").id()
        );
        assert_ne!(
            Topic::with_secret("chat", b"a").id(),
            Topic::with_secret("chat", b"b").id()
        );
    }

    #[test]
    fn name_and_secret_boundary_is_unambiguous() {
        // "ab" + "c" must not collide with "a" + "bc".
        assert_ne!(
            Topic::with_secret("ab", b"c").id(),
            Topic::with_secret("a", b"bc").id()
        );
    }

    #[test]
    fn topic_signature_verifies_against_id() {
        let topic = Topic::with_secret("chat", b"s");
        let sig = topic.sign(b"hello");
        assert!(topic.id().0.verify(b"hello", &sig).is_ok());
        assert!(Topic::new("chat").id().0.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn topic_id_round_trips_through_display() {
        let id = Topic::new("chat").id();
        let parsed: TopicId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }
}
