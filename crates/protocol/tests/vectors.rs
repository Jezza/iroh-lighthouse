//! The committed wire vectors must stay in agreement with the code.
//!
//! `spec/vectors.json` is what other implementations check themselves against,
//! so it is only useful if it cannot drift. This test regenerates the whole
//! document from the example that produced it and asserts the committed file
//! still matches, then verifies every committed signature on its own terms.
//!
//! If this fails after a deliberate protocol change, regenerate the file:
//!
//! ```sh
//! cargo run -p iroh-lighthouse-protocol --example vectors > spec/vectors.json
//! ```
//!
//! and treat the diff as the thing to review, because it is the wire format.

#[allow(dead_code)]
#[path = "../examples/vectors.rs"]
mod generator;

use iroh::Signature;
use iroh_lighthouse_protocol::{Announce, AnnounceBody, Lookup, LookupBody};
use serde_json::Value;

fn committed() -> Value {
    let raw = include_str!("../../../spec/vectors.json");
    serde_json::from_str(raw).expect("spec/vectors.json is not valid JSON")
}

fn signature(hex: &str) -> Signature {
    let bytes = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .expect("signature is not lowercase hex");
    Signature::try_from(bytes.as_slice()).expect("signature is not 64 bytes")
}

/// The committed file is exactly what the generator produces today, so no
/// vector — payload, signing bytes, signatures or identities — has drifted.
#[test]
fn committed_vectors_match_the_generator() {
    assert!(
        generator::generate() == committed(),
        "spec/vectors.json is stale; regenerate it with \
         `cargo run -p iroh-lighthouse-protocol --example vectors > spec/vectors.json`"
    );
}

/// Every committed signature verifies against its payload and yields the
/// committed body. This is the check another implementation relies on, so it
/// runs on the file alone rather than on anything re-derived from code.
#[test]
fn every_committed_vector_verifies() {
    let doc = committed();
    let vectors = doc["vectors"].as_object().unwrap();
    assert!(!vectors.is_empty());

    for (name, vector) in vectors {
        let payload = vector["payload"].as_str().unwrap().to_string();
        let topic_sig = vector["topic_sig"].as_str().map(signature);

        if name.starts_with("announce") {
            let announce = Announce {
                payload,
                node_sig: signature(vector["node_sig"].as_str().unwrap()),
                topic_sig,
            };
            let body = announce
                .verify()
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            let want: AnnounceBody = serde_json::from_value(vector["body"].clone()).unwrap();
            assert_eq!(body, want, "{name}: payload is not the stated body");
        } else {
            let lookup = Lookup {
                payload,
                topic_sig: topic_sig.unwrap_or_else(|| panic!("{name}: lookup needs a topic_sig")),
            };
            let body = lookup
                .verify()
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            let want: LookupBody = serde_json::from_value(vector["body"].clone()).unwrap();
            assert_eq!(body, want, "{name}: payload is not the stated body");
        }
    }
}

/// The signed string really is `domain . payload`, checked against the file
/// rather than against the function that produced it.
#[test]
fn committed_signing_bytes_have_the_documented_shape() {
    let doc = committed();
    let announce_domain = doc["announce_domain"].as_str().unwrap();
    let lookup_domain = doc["lookup_domain"].as_str().unwrap();

    for (name, vector) in doc["vectors"].as_object().unwrap() {
        let domain = if name.starts_with("announce") {
            announce_domain
        } else {
            lookup_domain
        };
        let payload = vector["payload"].as_str().unwrap();
        let utf8 = vector["signing_bytes_utf8"].as_str().unwrap();
        assert_eq!(
            utf8,
            format!("{domain}.{payload}"),
            "{name}: signed string is not domain + '.' + payload"
        );
        assert_eq!(
            vector["signing_bytes_hex"].as_str().unwrap(),
            data_encoding::HEXLOWER.encode(utf8.as_bytes()),
            "{name}: hex and utf8 signing bytes disagree"
        );
        // The payload is base64url of the body's JSON, nothing more.
        let decoded = data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .unwrap_or_else(|_| panic!("{name}: payload is not base64url"));
        let decoded: Value = serde_json::from_slice(&decoded)
            .unwrap_or_else(|_| panic!("{name}: payload is not JSON"));
        assert_eq!(decoded, vector["body"], "{name}: payload is not the body");
    }
}
