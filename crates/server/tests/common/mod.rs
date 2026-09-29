//! Shared helpers for the integration tests.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, Watcher};
use iroh_lighthouse::Lighthouse;
use iroh_lighthouse_server::handler::Limits;
use iroh_lighthouse_server::registry::SizeLimits;
use iroh_lighthouse_server::{Config, IrohConfig, Server};

pub fn test_config() -> Config {
    Config {
        http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        iroh: Some(IrohConfig {
            secret_key: iroh::SecretKey::generate(),
            bind_port: 0,
            relays: false,
            external_addrs: Vec::new(),
        }),
        snapshot: None,
        sweep_interval: Duration::from_secs(30),
        limits: Limits {
            min_ttl_secs: 1,
            max_ttl_secs: 3600,
            max_skew_secs: 300,
            size: SizeLimits {
                max_peers_per_topic: 2,
                max_topics: 100,
            },
        },
    }
}

pub async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal).bind().await.unwrap()
}

/// The endpoint's address once it has at least one direct address to dial.
pub async fn dialable(ep: &Endpoint) -> EndpointAddr {
    let mut watcher = ep.watch_addr();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let addr = watcher.get();
            if addr.ip_addrs().next().is_some() {
                return addr;
            }
            watcher.updated().await.unwrap();
        }
    })
    .await
    .expect("endpoint never got a direct address")
}

pub fn http_client(server: &Server) -> Lighthouse {
    let addr = server.http_addr().unwrap();
    Lighthouse::http(format!("http://{addr}").parse().unwrap())
}

pub async fn iroh_client(server: &Server, ep: &Endpoint) -> Lighthouse {
    let lighthouse = dialable(server.endpoint().unwrap()).await;
    Lighthouse::iroh(ep.clone(), lighthouse)
}
