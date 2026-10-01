//! Both carriers end to end: an in-process server, real iroh endpoints, real HTTP.

mod common;

use std::time::Duration;

use common::{dialable, endpoint, http_client, iroh_client, test_config};
use iroh::Endpoint;
use iroh_lighthouse::Server;
use iroh_lighthouse_client::protocol::ErrorCode;
use iroh_lighthouse_client::{Lighthouse, Topic};

const TTL: Duration = Duration::from_secs(60);

async fn announce_and_lookup(
    a_client: Lighthouse,
    b_client: Lighthouse,
    a: &Endpoint,
    b: &Endpoint,
) {
    let topic = Topic::with_secret("carriers", b"s3cret");

    let first = a_client
        .announce(a.secret_key(), Some(&topic), dialable(a).await, TTL)
        .await
        .unwrap();
    assert_eq!(first.ttl, TTL);
    assert!(first.peers.is_empty());

    let second = b_client
        .announce(b.secret_key(), Some(&topic), dialable(b).await, TTL)
        .await
        .unwrap();
    assert_eq!(second.peers.len(), 1);
    assert_eq!(second.peers[0].addr.id, a.id());
    assert!(second.peers[0].expires_in_secs <= 60);

    let all = a_client.lookup(&topic).await.unwrap();
    let mut ids: Vec<_> = all.iter().map(|p| p.addr.id).collect();
    ids.sort();
    let mut expected = vec![a.id(), b.id()];
    expected.sort();
    assert_eq!(ids, expected);

    let wrong_secret = Topic::with_secret("carriers", b"wrong");
    assert!(b_client.lookup(&wrong_secret).await.unwrap().is_empty());
}

#[tokio::test]
async fn announce_and_lookup_over_http() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    announce_and_lookup(http_client(&server), http_client(&server), &a, &b).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn announce_and_lookup_over_iroh() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    let (ca, cb) = (
        iroh_client(&server, &a).await,
        iroh_client(&server, &b).await,
    );
    announce_and_lookup(ca, cb, &a, &b).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn carriers_share_one_registry() {
    let server = Server::spawn(test_config()).await.unwrap();
    let (a, b) = (endpoint().await, endpoint().await);
    let topic = Topic::new("shared");
    http_client(&server)
        .announce(a.secret_key(), Some(&topic), dialable(&a).await, TTL)
        .await
        .unwrap();
    let seen = iroh_client(&server, &b).await.lookup(&topic).await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].addr.id, a.id());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn directory_publish_resolve_and_not_found() {
    let server = Server::spawn(test_config()).await.unwrap();
    let client = http_client(&server);
    let (published, member) = (endpoint().await, endpoint().await);
    let topic = Topic::new("t");

    let addr = dialable(&published).await;
    let announced = client
        .announce(published.secret_key(), None, addr.clone(), TTL)
        .await
        .unwrap();
    assert!(announced.peers.is_empty());
    client
        .announce(
            member.secret_key(),
            Some(&topic),
            dialable(&member).await,
            TTL,
        )
        .await
        .unwrap();

    let resolved = client.resolve(published.id()).await.unwrap().unwrap();
    assert_eq!(resolved.addr, addr);
    assert_eq!(client.resolve(member.id()).await.unwrap(), None);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn zero_ttl_unregisters_over_iroh() {
    let server = Server::spawn(test_config()).await.unwrap();
    let a = endpoint().await;
    let client = iroh_client(&server, &a).await;
    let topic = Topic::new("leave");
    let addr = dialable(&a).await;
    client
        .announce(a.secret_key(), Some(&topic), addr.clone(), TTL)
        .await
        .unwrap();
    assert_eq!(client.lookup(&topic).await.unwrap().len(), 1);
    client
        .announce(a.secret_key(), Some(&topic), addr, Duration::ZERO)
        .await
        .unwrap();
    assert!(client.lookup(&topic).await.unwrap().is_empty());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn server_errors_surface_with_their_code() {
    let server = Server::spawn(test_config()).await.unwrap();
    let client = http_client(&server);
    let topic = Topic::new("full");
    for _ in 0..2 {
        let ep = endpoint().await;
        client
            .announce(ep.secret_key(), Some(&topic), dialable(&ep).await, TTL)
            .await
            .unwrap();
    }
    let third = endpoint().await;
    let err = client
        .announce(
            third.secret_key(),
            Some(&topic),
            dialable(&third).await,
            TTL,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::TopicFull));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn info_reports_lighthouse_address_and_limits() {
    let server = Server::spawn(test_config()).await.unwrap();
    let info = http_client(&server).info().await.unwrap();
    assert_eq!(
        info.lighthouse.map(|a| a.id),
        Some(server.endpoint().unwrap().id())
    );
    assert_eq!(info.min_ttl_secs, 1);
    assert_eq!(info.max_ttl_secs, 3600);
    assert_eq!(info.max_peers_per_topic, 2);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn configured_external_addr_is_advertised() {
    let external: std::net::SocketAddr = "203.0.113.5:4433".parse().unwrap();
    let mut config = test_config();
    config.iroh.as_mut().unwrap().external_addrs = vec![external];
    let server = Server::spawn(config).await.unwrap();

    let client = http_client(&server);
    let advertised = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let info = client.info().await.unwrap();
            let addr = info.lighthouse.expect("iroh carrier enabled");
            if addr.ip_addrs().any(|a| *a == external) {
                return addr;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("external address never showed up in info");
    assert_eq!(advertised.id, server.endpoint().unwrap().id());
    assert!(
        server
            .endpoint_addr()
            .unwrap()
            .ip_addrs()
            .any(|a| *a == external),
        "endpoint itself advertises the configured address"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ttl_is_clamped_to_server_limits() {
    let server = Server::spawn(test_config()).await.unwrap();
    let a = endpoint().await;
    let announced = http_client(&server)
        .announce(
            a.secret_key(),
            Some(&Topic::new("clamp")),
            dialable(&a).await,
            Duration::from_secs(10_000),
        )
        .await
        .unwrap();
    assert_eq!(announced.ttl, Duration::from_secs(3600));
    server.shutdown().await.unwrap();
}
