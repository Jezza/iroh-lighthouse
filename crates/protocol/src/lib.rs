//! Wire protocol and topic keys shared by the iroh-lighthouse client and server.
//!
//! Messages are JSON on both carriers. Signed bodies are encoded with postcard
//! before signing, prefixed by a domain string so a signature can never be
//! replayed as a different message type.

use iroh::{EndpointAddr, EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

pub mod topic;

pub use topic::{Topic, TopicId};

/// ALPN of the iroh carrier.
pub const ALPN: &[u8] = b"iroh-lighthouse/1";

/// Maximum encoded size of a single request or response on either carrier.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Domain prefix for announce signatures.
pub const ANNOUNCE_DOMAIN: &[u8] = b"iroh-lighthouse/v1/announce";
/// Domain prefix for lookup signatures.
pub const LOOKUP_DOMAIN: &[u8] = b"iroh-lighthouse/v1/lookup";

/// HTTP route of the announce request.
pub const HTTP_ANNOUNCE: &str = "/v1/announce";
/// HTTP route of the lookup request.
pub const HTTP_LOOKUP: &str = "/v1/lookup";
/// HTTP route prefix of the resolve request; the endpoint id is appended.
pub const HTTP_RESOLVE: &str = "/v1/resolve";
/// HTTP route of the info request.
pub const HTTP_INFO: &str = "/v1/info";
/// HTTP health route for reverse proxies.
pub const HTTP_HEALTH: &str = "/v1/health";

/// The signed part of an announce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnounceBody {
    /// Topic to register on, or `None` to publish to the directory.
    pub topic: Option<TopicId>,
    /// The announcing node's full address. Its id is the signing key.
    pub addr: EndpointAddr,
    /// Requested lifetime in seconds. Zero unregisters.
    pub ttl_secs: u32,
    /// Unix timestamp in seconds when the body was signed.
    pub ts: u64,
}

/// A signed announce request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    pub body: AnnounceBody,
    /// Signature by the key of `body.addr.id`.
    pub node_sig: Signature,
    /// Signature by the topic key; required exactly when `body.topic` is set.
    pub topic_sig: Option<Signature>,
}

/// The signed part of a lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupBody {
    pub topic: TopicId,
    pub ts: u64,
}

/// A signed lookup request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    pub body: LookupBody,
    pub topic_sig: Signature,
}

/// Every request the lighthouse understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Announce(Announce),
    Lookup(Lookup),
    Resolve { id: EndpointId },
    Info,
}

/// A registered node as returned to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub addr: EndpointAddr,
    pub expires_in_secs: u32,
}

/// Server description returned by the info request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub version: String,
    /// The lighthouse's own iroh address, if the iroh carrier is enabled.
    pub lighthouse: Option<EndpointAddr>,
    pub min_ttl_secs: u32,
    pub max_ttl_secs: u32,
    pub max_peers_per_topic: u32,
}

/// Machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Malformed,
    PayloadTooLarge,
    StaleTimestamp,
    BadSignature,
    NotFound,
    TopicFull,
    TooManyTopics,
    Internal,
}

impl ErrorCode {
    /// The HTTP status the HTTP carrier uses for this code.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Malformed => 400,
            ErrorCode::StaleTimestamp | ErrorCode::BadSignature => 401,
            ErrorCode::NotFound => 404,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::TopicFull | ErrorCode::TooManyTopics => 429,
            ErrorCode::Internal => 500,
        }
    }
}

/// An error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

/// Every response the lighthouse sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Announced { ttl_secs: u32, peers: Vec<Peer> },
    Peers { peers: Vec<Peer> },
    Resolved { peer: Peer },
    Info(Info),
    Error(ErrorBody),
}

impl Response {
    /// Shorthand for an error response.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error(ErrorBody {
            code,
            message: message.into(),
        })
    }
}

/// Why a signed request failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("node signature does not verify against the announced endpoint id")]
    NodeSignature,
    #[error("topic signature does not verify against the topic id")]
    TopicSignature,
    #[error("announce names a topic but carries no topic signature")]
    MissingTopicSignature,
    #[error("announce carries a topic signature but names no topic")]
    UnexpectedTopicSignature,
}

/// Domain prefix followed by the postcard encoding of `body`.
///
/// postcard is deterministic for our bodies: every field is a primitive, an
/// `Option`, a key encoded as raw bytes, or an ordered set of transport addresses.
fn signing_bytes<T: Serialize>(domain: &[u8], body: &T) -> Vec<u8> {
    let bytes = domain.to_vec();
    postcard::to_extend(body, bytes).expect("postcard encoding of an in-memory body cannot fail")
}

impl AnnounceBody {
    /// The exact bytes that get signed: domain prefix plus postcard encoding.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(ANNOUNCE_DOMAIN, self)
    }

    /// Sign with the node's key and, when a topic is set, the topic key.
    ///
    /// `topic` must be `Some` exactly when `self.topic` is set; the caller is
    /// expected to construct the body from the same topic.
    pub fn sign(self, node_key: &SecretKey, topic: Option<&Topic>) -> Announce {
        let bytes = self.signing_bytes();
        Announce {
            node_sig: node_key.sign(&bytes),
            topic_sig: topic.map(|t| t.sign(&bytes)),
            body: self,
        }
    }
}

impl Announce {
    /// Check every signature against the keys named in the body.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let bytes = self.body.signing_bytes();
        self.body
            .addr
            .id
            .verify(&bytes, &self.node_sig)
            .map_err(|_| VerifyError::NodeSignature)?;
        match (&self.body.topic, &self.topic_sig) {
            (Some(topic), Some(sig)) => topic
                .0
                .verify(&bytes, sig)
                .map_err(|_| VerifyError::TopicSignature),
            (Some(_), None) => Err(VerifyError::MissingTopicSignature),
            (None, Some(_)) => Err(VerifyError::UnexpectedTopicSignature),
            (None, None) => Ok(()),
        }
    }
}

impl LookupBody {
    /// The exact bytes that get signed: domain prefix plus postcard encoding.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(LOOKUP_DOMAIN, self)
    }

    /// Sign with the topic key.
    pub fn sign(self, topic: &Topic) -> Lookup {
        Lookup {
            topic_sig: topic.sign(&self.signing_bytes()),
            body: self,
        }
    }
}

impl Lookup {
    /// Check the topic signature against the topic id in the body.
    pub fn verify(&self) -> Result<(), VerifyError> {
        self.body
            .topic
            .0
            .verify(&self.body.signing_bytes(), &self.topic_sig)
            .map_err(|_| VerifyError::TopicSignature)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn node() -> (SecretKey, EndpointAddr) {
        let key = SecretKey::generate();
        let addr = EndpointAddr::new(key.public())
            .with_ip_addr("127.0.0.1:4433".parse::<SocketAddr>().unwrap());
        (key, addr)
    }

    fn announce_body(topic: Option<&Topic>, addr: EndpointAddr) -> AnnounceBody {
        AnnounceBody {
            topic: topic.map(Topic::id),
            addr,
            ttl_secs: 3600,
            ts: 1_757_850_000,
        }
    }

    #[test]
    fn signed_topic_announce_verifies() {
        let topic = Topic::with_secret("chat", b"s");
        let (key, addr) = node();
        let announce = announce_body(Some(&topic), addr).sign(&key, Some(&topic));
        assert!(announce.topic_sig.is_some());
        assert_eq!(announce.verify(), Ok(()));
    }

    #[test]
    fn signed_directory_announce_verifies_without_topic_signature() {
        let (key, addr) = node();
        let announce = announce_body(None, addr).sign(&key, None);
        assert!(announce.topic_sig.is_none());
        assert_eq!(announce.verify(), Ok(()));
    }

    #[test]
    fn tampered_body_fails_verification() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let mut announce = announce_body(Some(&topic), addr).sign(&key, Some(&topic));
        announce.body.ttl_secs += 1;
        assert_eq!(announce.verify(), Err(VerifyError::NodeSignature));
    }

    #[test]
    fn announce_signed_by_a_key_other_than_addr_id_fails() {
        let topic = Topic::new("chat");
        let (_victim, victim_addr) = node();
        let attacker = SecretKey::generate();
        let announce = announce_body(Some(&topic), victim_addr).sign(&attacker, Some(&topic));
        assert_eq!(announce.verify(), Err(VerifyError::NodeSignature));
    }

    #[test]
    fn announce_with_wrong_topic_key_fails() {
        let topic = Topic::with_secret("chat", b"right");
        let wrong = Topic::with_secret("chat", b"wrong");
        let (key, addr) = node();
        let announce = announce_body(Some(&topic), addr).sign(&key, Some(&wrong));
        assert_eq!(announce.verify(), Err(VerifyError::TopicSignature));
    }

    #[test]
    fn announce_naming_topic_without_topic_signature_fails() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let mut announce = announce_body(Some(&topic), addr).sign(&key, Some(&topic));
        announce.topic_sig = None;
        assert_eq!(announce.verify(), Err(VerifyError::MissingTopicSignature));
    }

    #[test]
    fn directory_announce_with_stray_topic_signature_fails() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let mut announce = announce_body(None, addr).sign(&key, None);
        announce.topic_sig = Some(topic.sign(b"whatever"));
        assert_eq!(
            announce.verify(),
            Err(VerifyError::UnexpectedTopicSignature)
        );
    }

    #[test]
    fn signed_lookup_verifies_and_rejects_wrong_topic() {
        let topic = Topic::with_secret("chat", b"s");
        let body = LookupBody {
            topic: topic.id(),
            ts: 1_757_850_010,
        };
        let lookup = body.clone().sign(&topic);
        assert_eq!(lookup.verify(), Ok(()));

        let wrong = body.sign(&Topic::new("chat"));
        assert_eq!(wrong.verify(), Err(VerifyError::TopicSignature));
    }

    #[test]
    fn signing_bytes_are_domain_separated() {
        let topic = Topic::new("chat");
        let announce = AnnounceBody {
            topic: Some(topic.id()),
            addr: node().1,
            ttl_secs: 1,
            ts: 1,
        };
        let lookup = LookupBody {
            topic: topic.id(),
            ts: 1,
        };
        assert!(announce.signing_bytes().starts_with(ANNOUNCE_DOMAIN));
        assert!(lookup.signing_bytes().starts_with(LOOKUP_DOMAIN));

        // A topic signature over the raw postcard body, without the domain,
        // must not verify as a lookup.
        let raw = postcard::to_allocvec(&lookup).unwrap();
        let forged = Lookup {
            body: lookup,
            topic_sig: topic.sign(&raw),
        };
        assert_eq!(forged.verify(), Err(VerifyError::TopicSignature));
    }

    #[test]
    fn signing_bytes_are_deterministic_across_round_trip() {
        let topic = Topic::new("chat");
        let body = announce_body(Some(&topic), node().1);
        let json = serde_json::to_string(&body).unwrap();
        let decoded: AnnounceBody = serde_json::from_str(&json).unwrap();
        assert_eq!(body.signing_bytes(), decoded.signing_bytes());
    }

    #[test]
    fn request_json_is_tagged_and_round_trips() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let requests = vec![
            Request::Announce(announce_body(Some(&topic), addr.clone()).sign(&key, Some(&topic))),
            Request::Lookup(
                LookupBody {
                    topic: topic.id(),
                    ts: 5,
                }
                .sign(&topic),
            ),
            Request::Resolve { id: addr.id },
            Request::Info,
        ];
        for req in requests {
            let json = serde_json::to_value(&req).unwrap();
            assert!(json.get("type").is_some(), "missing tag in {json}");
            let back: Request = serde_json::from_value(json).unwrap();
            assert_eq!(back, req);
        }
        assert_eq!(
            serde_json::to_value(Request::Info).unwrap(),
            serde_json::json!({ "type": "info" })
        );
    }

    #[test]
    fn response_json_is_tagged_and_round_trips() {
        let (_, addr) = node();
        let peer = Peer {
            addr: addr.clone(),
            expires_in_secs: 30,
        };
        let responses = vec![
            Response::Announced {
                ttl_secs: 60,
                peers: vec![peer.clone()],
            },
            Response::Peers { peers: vec![] },
            Response::Resolved { peer },
            Response::Info(Info {
                version: "0.1.0".into(),
                lighthouse: Some(addr),
                min_ttl_secs: 10,
                max_ttl_secs: 604_800,
                max_peers_per_topic: 256,
            }),
            Response::error(ErrorCode::NotFound, "nope"),
        ];
        for resp in responses {
            let json = serde_json::to_value(&resp).unwrap();
            assert!(json.get("type").is_some(), "missing tag in {json}");
            let back: Response = serde_json::from_value(json).unwrap();
            assert_eq!(back, resp);
        }
        assert_eq!(
            serde_json::to_value(Response::error(ErrorCode::TopicFull, "full")).unwrap(),
            serde_json::json!({ "type": "error", "code": "topic_full", "message": "full" })
        );
    }

    #[test]
    fn keys_serialize_as_strings_in_json() {
        let (_, addr) = node();
        let json = serde_json::to_value(Request::Resolve { id: addr.id }).unwrap();
        assert!(json["id"].is_string());
        let topic_json = serde_json::to_value(Topic::new("t").id()).unwrap();
        assert!(topic_json.is_string());
    }

    #[test]
    fn error_codes_map_to_http_statuses() {
        assert_eq!(ErrorCode::Malformed.http_status(), 400);
        assert_eq!(ErrorCode::PayloadTooLarge.http_status(), 413);
        assert_eq!(ErrorCode::StaleTimestamp.http_status(), 401);
        assert_eq!(ErrorCode::BadSignature.http_status(), 401);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::TopicFull.http_status(), 429);
        assert_eq!(ErrorCode::TooManyTopics.http_status(), 429);
        assert_eq!(ErrorCode::Internal.http_status(), 500);
    }
}
