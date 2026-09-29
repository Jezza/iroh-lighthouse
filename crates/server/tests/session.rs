//! Sessions, expiry, and persistence across a restart.

mod common;

use std::time::Duration;

use common::{dialable, endpoint, http_client, iroh_client, test_config};
use iroh_lighthouse::Topic;
use iroh_lighthouse_server::{Server, SnapshotConfig};

#[tokio::test]
async fn join_returns_initial_peers_and_watch_sees_later_joiners() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    dialable(&b).await;
    let topic = Topic::with_secret("session", b"s");

    let sa = http_client(&server)
        .join(&a, topic.clone(), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(sa.peers().is_empty());
    let mut watch = sa.watch_peers();

    let sb = iroh_client(&server, &b)
        .await
        .join(&b, topic.clone(), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        sb.peers().iter().map(|p| p.addr.id).collect::<Vec<_>>(),
        vec![a.id()]
    );

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            watch.changed().await.unwrap();
            if watch.borrow().iter().any(|p| p.addr.id == b.id()) {
                break;
            }
        }
    })
    .await
    .expect("a's session never saw b");

    drop(sb);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_keeps_registration_alive_past_the_ttl() {
    let server = Server::spawn(test_config()).await.unwrap();
    let a = endpoint().await;
    dialable(&a).await;
    let topic = Topic::new("alive");
    let client = http_client(&server);
    let _session = client
        .join(&a, topic.clone(), Duration::from_secs(2))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        client.lookup(&topic).await.unwrap().len(),
        1,
        "refreshed by the session"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropped_session_ages_out_but_leave_removes_immediately() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    dialable(&b).await;
    let topic = Topic::new("bye");
    let client = http_client(&server);

    let sa = client
        .join(&a, topic.clone(), Duration::from_secs(2))
        .await
        .unwrap();
    let sb = client
        .join(&b, topic.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(client.lookup(&topic).await.unwrap().len(), 2);

    sb.leave().await.unwrap();
    let after_leave = client.lookup(&topic).await.unwrap();
    assert_eq!(
        after_leave.iter().map(|p| p.addr.id).collect::<Vec<_>>(),
        vec![a.id()]
    );

    drop(sa);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        client.lookup(&topic).await.unwrap().is_empty(),
        "no refresh after drop"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn refresh_returns_current_peers() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    dialable(&b).await;
    let topic = Topic::new("refresh");
    let client = http_client(&server);
    let sa = client
        .join(&a, topic.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    client
        .announce(
            b.secret_key(),
            Some(&topic),
            dialable(&b).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(sa.peers().is_empty(), "not refreshed yet");
    let peers = sa.refresh().await.unwrap();
    assert_eq!(
        peers.iter().map(|p| p.addr.id).collect::<Vec<_>>(),
        vec![b.id()]
    );
    assert_eq!(sa.peers(), peers);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unrefreshed_announce_expires() {
    let server = Server::spawn(test_config()).await.unwrap();
    let a = endpoint().await;
    let topic = Topic::new("expire");
    let client = http_client(&server);
    client
        .announce(
            a.secret_key(),
            Some(&topic),
            dialable(&a).await,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(client.lookup(&topic).await.unwrap().is_empty());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn registrations_survive_a_restart_via_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = SnapshotConfig {
        path: dir.path().join("lighthouse.json"),
        interval: Duration::from_secs(3600),
    };
    let mut config = test_config();
    config.snapshot = Some(snapshot.clone());

    let a = endpoint().await;
    let topic = Topic::new("persist");
    let first = Server::spawn(config.clone()).await.unwrap();
    http_client(&first)
        .announce(
            a.secret_key(),
            Some(&topic),
            dialable(&a).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    http_client(&first)
        .announce(
            a.secret_key(),
            None,
            dialable(&a).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    first.shutdown().await.unwrap();

    let second = Server::spawn(config).await.unwrap();
    let client = http_client(&second);
    let peers = client.lookup(&topic).await.unwrap();
    assert_eq!(
        peers.iter().map(|p| p.addr.id).collect::<Vec<_>>(),
        vec![a.id()]
    );
    assert!(peers[0].expires_in_secs <= 60);
    assert!(client.resolve(a.id()).await.unwrap().is_some());
    second.shutdown().await.unwrap();
}

/// Wait until the watched peer list satisfies `pred`, or fail after 10s.
async fn wait_for(
    watch: &mut tokio::sync::watch::Receiver<Vec<iroh_lighthouse::protocol::Peer>>,
    what: &str,
    pred: impl Fn(&[iroh_lighthouse::protocol::Peer]) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if pred(&watch.borrow_and_update()) {
                return;
            }
            watch.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("watch never saw {what}"));
}

#[tokio::test]
async fn watch_sees_joins_leaves_and_moves_between_keepalives() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    let topic = Topic::new("poll");
    let client = http_client(&server);

    // A 60s TTL means the keep-alive re-announce is 30s away: anything the
    // watch sees inside this test comes from polling.
    let sa = client
        .join_with(
            &a,
            topic.clone(),
            Duration::from_secs(60),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    let mut watch = sa.watch_peers();

    let b_addr = dialable(&b).await;
    client
        .announce(
            b.secret_key(),
            Some(&topic),
            b_addr.clone(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    wait_for(&mut watch, "b join", |peers| {
        peers.iter().any(|p| p.addr == b_addr)
    })
    .await;

    let moved = iroh::EndpointAddr::new(b.id())
        .with_ip_addr("10.9.9.9:9".parse::<std::net::SocketAddr>().unwrap());
    client
        .announce(
            b.secret_key(),
            Some(&topic),
            moved.clone(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    wait_for(&mut watch, "b address change", |peers| {
        peers.iter().any(|p| p.addr == moved)
    })
    .await;

    client
        .announce(b.secret_key(), Some(&topic), moved, Duration::ZERO)
        .await
        .unwrap();
    wait_for(&mut watch, "b leave", |peers| peers.is_empty()).await;

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn watch_is_quiet_while_membership_is_unchanged() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    let topic = Topic::new("quiet");
    let client = http_client(&server);
    client
        .announce(
            b.secret_key(),
            Some(&topic),
            dialable(&b).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    // Keep-alive every second and a poll every second, both returning the
    // same single peer with a shrinking `expires_in_secs`.
    let sa = client
        .join_with(
            &a,
            topic.clone(),
            Duration::from_secs(2),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    let watch = sa.watch_peers();
    assert_eq!(sa.peers().len(), 1);

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !watch.has_changed().unwrap(),
        "unchanged membership must not wake watchers"
    );
    assert_eq!(sa.peers().len(), 1);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn polling_can_be_disabled() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    dialable(&a).await;
    let topic = Topic::new("nopoll");
    let client = http_client(&server);
    let sa = client
        .join_with(&a, topic.clone(), Duration::from_secs(60), None)
        .await
        .unwrap();
    let watch = sa.watch_peers();

    client
        .announce(
            b.secret_key(),
            Some(&topic),
            dialable(&b).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !watch.has_changed().unwrap(),
        "without polling only the keep-alive updates peers"
    );
    assert!(sa.peers().is_empty());

    server.shutdown().await.unwrap();
}
