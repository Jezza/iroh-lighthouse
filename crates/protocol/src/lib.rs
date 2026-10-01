//! Wire protocol and topic keys shared by the iroh-lighthouse client and server.
//!
//! Messages are JSON on both carriers.
//!
//! # Signing: sign the bytes you send
//!
//! A signed request carries its body as a **base64url string** (`payload`), and
//! the signature covers exactly:
//!
//! ```text
//! domain ‖ "." ‖ payload
//! ```
//!
//! all of it ASCII. The verifier checks the signature against the `payload`
//! string **as received** and never re-encodes anything, so there is no
//! canonical form for the two sides to agree on.
//!
//! That is the whole point of the design. The earlier scheme re-serialized the
//! parsed body with postcard and signed that, which meant every implementation
//! had to reproduce postcard byte-for-byte — varint widths, `BTreeSet`
//! ordering, and the fact that an iroh `PublicKey` serializes as a hex string
//! in JSON but as 32 raw bytes in a binary format. Now a client needs
//! `JSON.stringify`, base64url, and ed25519.
//!
//! Two further properties fall out of it:
//!
//! - **Unknown fields survive.** A newer client that adds a field still
//!   verifies against an older server, because the signature covers the bytes
//!   rather than the parse.
//! - **Field order stops mattering**, so any JSON library will do.
//!
//! The domain prefix keeps a signature from being replayed as a different
//! message type.

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
///
/// Carried on the wire inside [`Announce::payload`] as base64url JSON, not as
/// a nested object — the signature covers those bytes verbatim.
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
    /// base64url of the JSON [`AnnounceBody`]. Signed as received.
    pub payload: String,
    /// Signature by the key of the body's `addr.id`.
    pub node_sig: Signature,
    /// Signature by the topic key; required exactly when the body names a topic.
    pub topic_sig: Option<Signature>,
}

/// The signed part of a lookup.
///
/// Carried on the wire inside [`Lookup::payload`] as base64url JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupBody {
    pub topic: TopicId,
    pub ts: u64,
}

/// A signed lookup request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    /// base64url of the JSON [`LookupBody`]. Signed as received.
    pub payload: String,
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
    #[error("payload is not valid base64url")]
    Payload,
    #[error("payload is not a valid JSON body")]
    Body,
    #[error("node signature does not verify against the announced endpoint id")]
    NodeSignature,
    #[error("topic signature does not verify against the topic id")]
    TopicSignature,
    #[error("announce names a topic but carries no topic signature")]
    MissingTopicSignature,
    #[error("announce carries a topic signature but names no topic")]
    UnexpectedTopicSignature,
}

/// base64url, no padding: the alphabet every JWS-style scheme uses, and the
/// one `btoa`-free browser code reaches for.
const B64: data_encoding::Encoding = data_encoding::BASE64URL_NOPAD;

/// Encode a body as the `payload` string that gets signed and sent.
fn encode_payload<T: Serialize>(body: &T) -> String {
    let json = serde_json::to_vec(body).expect("serializing an in-memory body cannot fail");
    B64.encode(&json)
}

/// The exact bytes a signature covers: `domain ‖ "." ‖ payload`, all ASCII.
///
/// Built from the payload **string**, never from a re-encoded body, so signing
/// and verifying cannot disagree about a canonical form.
pub fn signing_bytes(domain: &[u8], payload: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain);
    bytes.push(b'.');
    bytes.extend_from_slice(payload.as_bytes());
    bytes
}

/// Decode a payload string back into a body.
fn decode_payload<T: for<'de> Deserialize<'de>>(payload: &str) -> Result<T, VerifyError> {
    let json = B64
        .decode(payload.as_bytes())
        .map_err(|_| VerifyError::Payload)?;
    serde_json::from_slice(&json).map_err(|_| VerifyError::Body)
}

impl AnnounceBody {
    /// Sign with the node's key and, when a topic is set, the topic key.
    ///
    /// `topic` must be `Some` exactly when `self.topic` is set; the caller is
    /// expected to construct the body from the same topic.
    pub fn sign(self, node_key: &SecretKey, topic: Option<&Topic>) -> Announce {
        let payload = encode_payload(&self);
        let bytes = signing_bytes(ANNOUNCE_DOMAIN, &payload);
        Announce {
            node_sig: node_key.sign(&bytes),
            topic_sig: topic.map(|t| t.sign(&bytes)),
            payload,
        }
    }
}

impl Announce {
    /// Decode the payload without checking any signature.
    ///
    /// Only for checks that can do nothing but reject, such as freshness.
    /// Anything acted on should come from [`verify`](Self::verify), which
    /// returns the same body once the signatures check out.
    pub fn body(&self) -> Result<AnnounceBody, VerifyError> {
        decode_payload(&self.payload)
    }

    /// Check every signature, then return the body it covers.
    ///
    /// Returning the body is deliberate: it makes "verify, then use" the path
    /// of least resistance.
    pub fn verify(&self) -> Result<AnnounceBody, VerifyError> {
        let bytes = signing_bytes(ANNOUNCE_DOMAIN, &self.payload);
        let body = self.body()?;
        body.addr
            .id
            .verify(&bytes, &self.node_sig)
            .map_err(|_| VerifyError::NodeSignature)?;
        match (&body.topic, &self.topic_sig) {
            (Some(topic), Some(sig)) => topic
                .0
                .verify(&bytes, sig)
                .map_err(|_| VerifyError::TopicSignature)?,
            (Some(_), None) => return Err(VerifyError::MissingTopicSignature),
            (None, Some(_)) => return Err(VerifyError::UnexpectedTopicSignature),
            (None, None) => {}
        }
        Ok(body)
    }
}

impl LookupBody {
    /// Sign with the topic key.
    pub fn sign(self, topic: &Topic) -> Lookup {
        let payload = encode_payload(&self);
        Lookup {
            topic_sig: topic.sign(&signing_bytes(LOOKUP_DOMAIN, &payload)),
            payload,
        }
    }
}

impl Lookup {
    /// Decode the payload without checking the signature. See
    /// [`Announce::body`] for when that is appropriate.
    pub fn body(&self) -> Result<LookupBody, VerifyError> {
        decode_payload(&self.payload)
    }

    /// Check the topic signature, then return the body it covers.
    pub fn verify(&self) -> Result<LookupBody, VerifyError> {
        let bytes = signing_bytes(LOOKUP_DOMAIN, &self.payload);
        let body = self.body()?;
        body.topic
            .0
            .verify(&bytes, &self.topic_sig)
            .map_err(|_| VerifyError::TopicSignature)?;
        Ok(body)
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
        let body = announce_body(Some(&topic), addr);
        let announce = body.clone().sign(&key, Some(&topic));
        assert!(announce.topic_sig.is_some());
        assert_eq!(announce.verify(), Ok(body));
    }

    #[test]
    fn signed_directory_announce_verifies_without_topic_signature() {
        let (key, addr) = node();
        let body = announce_body(None, addr);
        let announce = body.clone().sign(&key, None);
        assert!(announce.topic_sig.is_none());
        assert_eq!(announce.verify(), Ok(body));
    }

    /// Editing the signed bytes must break the signature.
    ///
    /// With the body carried as an opaque payload there is no field to poke,
    /// so this re-encodes a modified body — exactly what an attacker rewriting
    /// a request in flight would have to do.
    #[test]
    fn tampered_body_fails_verification() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let mut announce = announce_body(Some(&topic), addr.clone()).sign(&key, Some(&topic));

        let mut tampered = announce.body().unwrap();
        tampered.ttl_secs += 1;
        announce.payload = encode_payload(&tampered);

        assert_eq!(announce.verify(), Err(VerifyError::NodeSignature));
    }

    /// A payload that is not base64url, or not a valid body, is rejected
    /// before any signature check can be attempted.
    #[test]
    fn malformed_payloads_are_rejected() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let mut announce = announce_body(Some(&topic), addr).sign(&key, Some(&topic));

        announce.payload = "not base64!!".to_string();
        assert_eq!(announce.verify(), Err(VerifyError::Payload));

        announce.payload = B64.encode(b"{\"not\": \"an announce\"}");
        assert_eq!(announce.verify(), Err(VerifyError::Body));
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
        assert_eq!(lookup.verify(), Ok(body.clone()));

        let wrong = body.sign(&Topic::new("chat"));
        assert_eq!(wrong.verify(), Err(VerifyError::TopicSignature));
    }

    #[test]
    fn signing_bytes_are_domain_separated() {
        let payload = "SGVsbG8";
        assert!(signing_bytes(ANNOUNCE_DOMAIN, payload).starts_with(ANNOUNCE_DOMAIN));
        assert!(signing_bytes(LOOKUP_DOMAIN, payload).starts_with(LOOKUP_DOMAIN));
        assert_ne!(
            signing_bytes(ANNOUNCE_DOMAIN, payload),
            signing_bytes(LOOKUP_DOMAIN, payload),
            "the same payload under two domains must sign differently"
        );

        // A topic signature over the bare payload, without the domain prefix,
        // must not verify as a lookup.
        let topic = Topic::new("chat");
        let body = LookupBody {
            topic: topic.id(),
            ts: 1,
        };
        let payload = encode_payload(&body);
        let forged = Lookup {
            topic_sig: topic.sign(payload.as_bytes()),
            payload,
        };
        assert_eq!(forged.verify(), Err(VerifyError::TopicSignature));
    }

    /// A signature made for one message type must not verify as another, even
    /// when the payload bytes happen to be identical.
    #[test]
    fn a_lookup_signature_cannot_be_replayed_as_an_announce() {
        let topic = Topic::with_secret("chat", b"s");
        let (key, addr) = node();
        let announce = announce_body(Some(&topic), addr).sign(&key, Some(&topic));

        // Same payload, but signed under the lookup domain.
        let stolen = topic.sign(&signing_bytes(LOOKUP_DOMAIN, &announce.payload));
        let forged = Announce {
            payload: announce.payload.clone(),
            node_sig: announce.node_sig,
            topic_sig: Some(stolen),
        };
        assert_eq!(forged.verify(), Err(VerifyError::TopicSignature));
    }

    /// The signature survives a JSON round trip of the whole request, because
    /// it covers the payload string rather than a re-encoding of the body.
    #[test]
    fn signature_survives_a_json_round_trip() {
        let topic = Topic::new("chat");
        let (key, addr) = node();
        let req = Request::Announce(announce_body(Some(&topic), addr).sign(&key, Some(&topic)));
        let json = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        let Request::Announce(announce) = back else {
            panic!("wrong variant")
        };
        assert!(announce.verify().is_ok());
    }

    /// An unknown field added by a newer client does not break verification on
    /// an older server: the signature covers bytes, not the parse.
    #[test]
    fn unknown_fields_in_the_payload_still_verify() {
        let topic = Topic::new("chat");
        let (key, addr) = node();

        // Build a payload by hand with an extra field a future version might add.
        let mut value = serde_json::to_value(announce_body(Some(&topic), addr)).unwrap();
        value["future_field"] = serde_json::json!("ignored by this version");
        let payload = B64.encode(serde_json::to_vec(&value).unwrap().as_slice());

        let bytes = signing_bytes(ANNOUNCE_DOMAIN, &payload);
        let announce = Announce {
            node_sig: key.sign(&bytes),
            topic_sig: Some(topic.sign(&bytes)),
            payload,
        };
        assert!(
            announce.verify().is_ok(),
            "an unknown field must not break an otherwise valid signature"
        );
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
