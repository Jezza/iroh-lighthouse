//! Emit wire-format test vectors as JSON, so other implementations can check
//! themselves against this one.
//!
//! Run: `cargo run -p iroh-lighthouse-protocol --example vectors > spec/vectors.json`
//!
//! Each vector gives the body, the `payload` string it encodes to, the exact
//! `signing_bytes` a signature covers, and the resulting signatures. Ed25519 is
//! deterministic, so a correct implementation signing that same payload string
//! reproduces those signatures bit for bit. Its own encoding of the body may
//! differ (key order, whitespace) and still be valid: only the payload as sent
//! is signed.
//!
//! The keys here are fixed rather than generated, precisely so the output is
//! stable enough to diff between runs and between implementations.
//!
//! `tests/vectors.rs` includes this file and checks [`generate`] against the
//! committed `spec/vectors.json`, so the case list lives only here.

use std::net::SocketAddr;

use iroh::{EndpointAddr, SecretKey};
use iroh_lighthouse_protocol::Topic;
use iroh_lighthouse_protocol::{
    ANNOUNCE_DOMAIN, AnnounceBody, LOOKUP_DOMAIN, LookupBody, signing_bytes,
};
use serde_json::{Map, Value, json};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The payload string for a body: base64url of its JSON, no padding.
fn payload<T: serde::Serialize>(body: &T) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&serde_json::to_vec(body).unwrap())
}

fn announce_vector(
    name: &str,
    body: AnnounceBody,
    key: &SecretKey,
    topic: Option<&Topic>,
) -> (String, Value) {
    let payload = payload(&body);
    let bytes = signing_bytes(ANNOUNCE_DOMAIN, &payload);
    let signed = body.clone().sign(key, topic);
    (
        name.to_string(),
        json!({
            "body": serde_json::to_value(&body).unwrap(),
            "payload": payload,
            "signing_bytes_hex": hex(&bytes),
            "signing_bytes_utf8": String::from_utf8_lossy(&bytes),
            "node_sig": hex(&signed.node_sig.to_bytes()),
            "topic_sig": signed.topic_sig.map(|s| hex(&s.to_bytes())),
        }),
    )
}

fn lookup_vector(name: &str, body: LookupBody, topic: &Topic) -> (String, Value) {
    let payload = payload(&body);
    let bytes = signing_bytes(LOOKUP_DOMAIN, &payload);
    let signed = body.clone().sign(topic);
    (
        name.to_string(),
        json!({
            "body": serde_json::to_value(&body).unwrap(),
            "payload": payload,
            "signing_bytes_hex": hex(&bytes),
            "signing_bytes_utf8": String::from_utf8_lossy(&bytes),
            "topic_sig": hex(&signed.topic_sig.to_bytes()),
        }),
    )
}

/// Build the whole vectors document.
pub fn generate() -> Value {
    let node_key = SecretKey::from_bytes(&[7u8; 32]);
    let private = Topic::with_secret("chat", b"hunter2");
    let public = Topic::new("chat");

    let v4 = EndpointAddr::new(node_key.public())
        .with_ip_addr("127.0.0.1:4433".parse::<SocketAddr>().unwrap());
    let v6 = EndpointAddr::new(node_key.public())
        .with_ip_addr("[::1]:4433".parse::<SocketAddr>().unwrap());
    // Two addresses, to exercise a body whose `addrs` set has more than one
    // entry.
    let multi = EndpointAddr::new(node_key.public())
        .with_ip_addr("10.0.0.5:1234".parse::<SocketAddr>().unwrap())
        .with_ip_addr("127.0.0.1:4433".parse::<SocketAddr>().unwrap());

    let cases = vec![
        announce_vector(
            "announce_topic_v4",
            AnnounceBody {
                topic: Some(private.id()),
                addr: v4.clone(),
                ttl_secs: 3600,
                ts: 1_757_850_000,
            },
            &node_key,
            Some(&private),
        ),
        announce_vector(
            "announce_directory",
            AnnounceBody {
                topic: None,
                addr: v4.clone(),
                ttl_secs: 60,
                ts: 1,
            },
            &node_key,
            None,
        ),
        announce_vector(
            "announce_ipv6",
            AnnounceBody {
                topic: Some(private.id()),
                addr: v6,
                ttl_secs: 30,
                ts: 99,
            },
            &node_key,
            Some(&private),
        ),
        announce_vector(
            "announce_multi_addr",
            AnnounceBody {
                topic: Some(private.id()),
                addr: multi,
                ttl_secs: 7200,
                ts: 1_700_000_000,
            },
            &node_key,
            Some(&private),
        ),
        announce_vector(
            "announce_ttl_zero_unregister",
            AnnounceBody {
                topic: Some(private.id()),
                addr: v4,
                ttl_secs: 0,
                ts: 1_757_850_000,
            },
            &node_key,
            Some(&private),
        ),
        lookup_vector(
            "lookup_private_topic",
            LookupBody {
                topic: private.id(),
                ts: 1_757_850_010,
            },
            &private,
        ),
        lookup_vector(
            "lookup_public_topic_large_ts",
            LookupBody {
                topic: public.id(),
                ts: 4_000_000_000,
            },
            &public,
        ),
    ];

    let mut out = Map::new();
    out.insert(
        "scheme".into(),
        json!("domain || '.' || base64url_nopad(json(body))"),
    );
    out.insert(
        "announce_domain".into(),
        json!(String::from_utf8_lossy(ANNOUNCE_DOMAIN)),
    );
    out.insert(
        "lookup_domain".into(),
        json!(String::from_utf8_lossy(LOOKUP_DOMAIN)),
    );
    out.insert("node_secret_key_bytes".into(), json!(hex(&[7u8; 32])));
    out.insert("node_id".into(), json!(node_key.public().to_string()));
    out.insert(
        "topic_private".into(),
        json!({ "name": "chat", "secret": "hunter2", "id": private.id().to_string() }),
    );
    out.insert(
        "topic_public".into(),
        json!({ "name": "chat", "secret": "", "id": public.id().to_string() }),
    );
    out.insert("vectors".into(), Value::Object(cases.into_iter().collect()));

    Value::Object(out)
}

fn main() {
    println!("{}", serde_json::to_string_pretty(&generate()).unwrap());
}
