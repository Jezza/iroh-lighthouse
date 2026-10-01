//! The lighthouse as an iroh address lookup service.

mod common;

use std::time::Duration;

use common::{dialable, endpoint, http_client, test_config};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr};
use iroh_lighthouse::Server;
use iroh_lighthouse_client::LighthouseLookup;

const TEST_ALPN: &[u8] = b"lighthouse-test/echo";

fn http_url(server: &Server) -> url::Url {
    format!("http://{}", server.http_addr().unwrap())
        .parse()
        .unwrap()
}

#[tokio::test]
async fn endpoint_with_lighthouse_lookup_publishes_itself_to_the_directory() {
    let server = Server::spawn(test_config()).await.unwrap();
    let e = Endpoint::builder(presets::Minimal)
        .address_lookup(LighthouseLookup::http(http_url(&server)).ttl(Duration::from_secs(60)))
        .bind()
        .await
        .unwrap();
    dialable(&e).await;

    let client = http_client(&server);
    let peer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(peer) = client.resolve(e.id()).await.unwrap() {
                return peer;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("endpoint never published itself");
    assert_eq!(peer.addr.id, e.id());
    assert!(
        peer.addr.ip_addrs().next().is_some(),
        "published with direct addresses"
    );
    assert!(peer.expires_in_secs <= 60);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn connect_by_id_alone_through_the_lighthouse() {
    let server = Server::spawn(test_config()).await.unwrap();
    let lighthouse_addr = dialable(server.endpoint().unwrap()).await;

    // D accepts our test ALPN and is published in the directory.
    let d = Endpoint::builder(presets::Minimal)
        .alpns(vec![TEST_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let d_id = d.id();
    http_client(&server)
        .announce(
            d.secret_key(),
            None,
            dialable(&d).await,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let accept = tokio::spawn(async move {
        let incoming = d.accept().await.expect("endpoint closed");
        let conn = incoming.await.expect("handshake failed");
        conn.remote_id()
    });

    // C knows only the lighthouse (over iroh) and D's id.
    let c = Endpoint::builder(presets::Minimal)
        .address_lookup(LighthouseLookup::iroh(lighthouse_addr))
        .bind()
        .await
        .unwrap();
    let conn = c.connect(EndpointAddr::new(d_id), TEST_ALPN).await.unwrap();
    assert_eq!(conn.remote_id(), d_id);
    assert_eq!(accept.await.unwrap(), c.id());
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_id_fails_to_connect() {
    let server = Server::spawn(test_config()).await.unwrap();
    let c = Endpoint::builder(presets::Minimal)
        .address_lookup(LighthouseLookup::http(http_url(&server)))
        .bind()
        .await
        .unwrap();
    let ghost = endpoint().await.id();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        c.connect(EndpointAddr::new(ghost), TEST_ALPN),
    )
    .await
    .expect("connect should fail fast, not hang");
    assert!(result.is_err());
    server.shutdown().await.unwrap();
}
