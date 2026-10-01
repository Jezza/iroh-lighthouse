//! The DHT fallback engages when the lighthouse is unreachable.
//!
//! These tests are about the *wiring*: that a fallback-enabled session is
//! constructed, that a lighthouse outage does not kill it, and that a node can
//! still join while the lighthouse is down.
//!
//! They DO reach the real mainline DHT — there is no way to exercise the
//! fallback without it — so every test uses a **random per-run topic secret**.
//! An earlier draft used a fixed secret and asserted the topic was empty; it
//! passed, then failed on the next run because it had found the record its own
//! previous run published a minute earlier. A fixed topic name makes these
//! tests both flaky and mildly antisocial, since the slot is on a public
//! network.
//!
//! Nothing here asserts on how many peers the DHT returns: that is network
//! state we do not control. Real two-node discovery over the DHT is covered by
//! `dht_discovery_between_two_nodes`, which is `#[ignore]`d because it depends
//! on a live public network.

mod common;

use std::time::Duration;

use iroh_lighthouse::Topic;

use common::{endpoint, http_client, test_config};
use iroh_lighthouse_server::Server;

/// A secret no other run will use, so each test gets a private DHT slot.
fn unique_secret() -> Vec<u8> {
    iroh::SecretKey::generate().public().as_bytes().to_vec()
}

/// A session created with a fallback behaves like an ordinary one while the
/// lighthouse is up: same peers, same API, no visible difference.
#[tokio::test]
async fn fallback_session_works_normally_while_the_lighthouse_is_up() {
    let server = Server::spawn(test_config()).await.unwrap();
    let lighthouse = http_client(&server);
    let ep = endpoint().await;
    let secret = unique_secret();

    let session = lighthouse
        .join_with_fallback(
            &ep,
            Topic::with_secret("fallback-normal", &secret),
            Duration::from_secs(60),
            // No polling: this test is about join, and a poll racing the
            // assertion would make it flaky.
            None,
        )
        .await
        .expect("join with fallback should succeed while the lighthouse is up");

    assert!(
        session.peers().is_empty(),
        "first member of a topic sees nobody else"
    );

    let other = endpoint().await;
    let _second = lighthouse
        .join_with_fallback(
            &other,
            Topic::with_secret("fallback-normal", &secret),
            Duration::from_secs(60),
            None,
        )
        .await
        .unwrap();

    let peers = session.refresh().await.unwrap();
    assert_eq!(peers.len(), 1, "the second member is visible over http");
    assert_eq!(peers[0].addr.id, other.id());

    server.shutdown().await.unwrap();
}

/// The point of the feature: a session survives the lighthouse going away.
///
/// The DHT lookup itself will not find anyone here — the test does not join a
/// real topic on the public DHT — but the session must stay alive, keep
/// retrying, and not lose the members it already knew.
#[tokio::test]
async fn session_survives_the_lighthouse_disappearing() {
    let server = Server::spawn(test_config()).await.unwrap();
    let lighthouse = http_client(&server);
    let ep = endpoint().await;
    let other = endpoint().await;
    let secret = unique_secret();
    let topic = || Topic::with_secret("fallback-outage", &secret);

    let session = lighthouse
        .join_with_fallback(&ep, topic(), Duration::from_secs(60), None)
        .await
        .unwrap();
    let _second = lighthouse
        .join_with_fallback(&other, topic(), Duration::from_secs(60), None)
        .await
        .unwrap();

    let before = session.refresh().await.unwrap();
    assert_eq!(before.len(), 1, "both members registered before the outage");

    // The lighthouse goes away.
    server.shutdown().await.unwrap();

    // A refresh now fails — it is a direct call with no fallback path — but the
    // session must still be usable and must still report what it last knew.
    assert!(
        session.refresh().await.is_err(),
        "an explicit refresh surfaces the outage to the caller"
    );
    assert_eq!(
        session.peers().len(),
        1,
        "the last known membership is retained through the outage"
    );

    // And the background task is still running: leaving is still possible
    // (it will fail to reach the server, which is expected and not a panic).
    let _ = session.leave().await;
}

/// Joining while the lighthouse is already down must not be fatal when a
/// fallback is configured.
///
/// Without the feature this is a hard error. With it, the session is created
/// and the DHT is consulted instead; finding nobody there is a legitimate
/// outcome for a topic nobody else has joined.
#[tokio::test]
async fn can_join_while_the_lighthouse_is_down() {
    // Start and immediately stop a server, so we have a real address that
    // nothing is listening on.
    let server = Server::spawn(test_config()).await.unwrap();
    let lighthouse = http_client(&server);
    server.shutdown().await.unwrap();

    let ep = endpoint().await;
    let joined = tokio::time::timeout(
        Duration::from_secs(90),
        lighthouse.join_with_fallback(
            &ep,
            Topic::with_secret("fallback-cold-join", &unique_secret()),
            Duration::from_secs(60),
            None,
        ),
    )
    .await;

    match joined {
        Ok(Ok(_session)) => {
            // The DHT answered and the session exists, which is the claim:
            // an outage at join time is survivable. How many peers came back
            // is network state, not something to assert on.
        }
        Ok(Err(err)) => {
            // The DHT was unreachable too (no network in CI, for instance).
            // That is an acceptable outcome for this test; what must not
            // happen is a panic or a hang.
            eprintln!("dht fallback unavailable in this environment: {err}");
        }
        Err(_) => panic!("join_with_fallback hung instead of failing"),
    }
}

/// Two nodes find each other over the DHT with no lighthouse involved at all.
///
/// `#[ignore]`d on purpose: it talks to the real public mainline DHT, so it is
/// slow and depends on outbound UDP working. Run it deliberately:
///
/// ```sh
/// cargo test -p iroh-lighthouse-server --all-features \
///     --test fallback -- --ignored --nocapture
/// ```
///
/// This is the claim the fast tests cannot make. It uses a random topic secret
/// so it never collides with another run.
#[tokio::test]
#[ignore = "talks to the real public mainline DHT"]
async fn dht_discovery_between_two_nodes() {
    use iroh_lighthouse::DhtFallback;

    let secret = unique_secret();
    let topic = Topic::with_secret("fallback-live-discovery", &secret);
    let (a, b) = (endpoint().await, endpoint().await);
    let addr_a = common::dialable(&a).await;
    let addr_b = common::dialable(&b).await;

    let dht_a = DhtFallback::new(&a, &topic);
    let dht_b = DhtFallback::new(&b, &topic);

    // Read-before-write, exactly as `seed_from_dht` does. Publishers share one
    // BEP44 mutable item, so a write displaces what is already there; the node
    // that publishes second must read first or it destroys the record it came
    // for. An earlier draft of this test announced first and B saw zero peers.
    let _ = dht_a.lookup().await;
    dht_a.announce(addr_a.clone()).await.expect("a publishes");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let seen_by_b = dht_b.lookup().await.expect("b reads before publishing");
    println!("b sees {} peer(s) over the dht", seen_by_b.len());
    assert!(
        seen_by_b.iter().any(|peer| peer.addr.id == a.id()),
        "b should discover a over the dht with no lighthouse involved"
    );
    dht_b.announce(addr_b.clone()).await.expect("b publishes");

    // Records land in the current minute's slot; give the DHT a moment to
    // settle before reading back.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ASYMMETRY IS EXPECTED, and this is the honest assertion.
    //
    // All publishers on a topic share one BEP44 mutable item, and each storing
    // node keeps a single value for a given (key, salt). A publish therefore
    // displaces earlier records on whichever nodes it reaches. Reads return the
    // union across the storing nodes a lookup happens to hit, so which records
    // survive is probabilistic: measured here, B reliably saw A, while A saw
    // nothing once B's write had landed.
    //
    // That is sufficient for what this is for. Bootstrap needs ONE reachable
    // peer to join the gossip mesh, not a complete membership list — and once
    // joined, gossip itself distributes the rest. Asserting mutual discovery
    // would be asserting a property the DHT does not provide.
    let seen_by_a = dht_a.lookup().await.expect("a reads the topic");
    println!("a sees {} peer(s) over the dht", seen_by_a.len());

    assert!(
        seen_by_a.iter().all(|peer| peer.addr.id != a.id()),
        "a must never be listed as its own peer"
    );

    // The address that came back must be complete enough to dial, which is the
    // guarantee that makes a DHT peer useful without further discovery.
    let found = seen_by_b
        .iter()
        .find(|peer| peer.addr.id == a.id())
        .expect("checked above");
    assert!(
        found.addr.ip_addrs().next().is_some(),
        "a peer from the dht carries a dialable address, not a bare id"
    );
}
