//! Join a topic and print peers as they come and go.
//!
//! ```sh
//! cargo run --example join -- https://ichor.io my-topic [secret]
//! ```

use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh_lighthouse::{Lighthouse, Topic};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("usage: join <lighthouse-url> <topic> [secret]")?;
    let name = args
        .next()
        .ok_or("usage: join <lighthouse-url> <topic> [secret]")?;
    let topic = match args.next() {
        Some(secret) => Topic::with_secret(name, secret.as_bytes()),
        None => Topic::new(name),
    };

    let endpoint = Endpoint::builder(presets::N0).bind().await?;
    let lighthouse = Lighthouse::http(url.parse()?);
    let session = lighthouse
        .join(&endpoint, topic, Duration::from_secs(3600))
        .await?;
    println!(
        "joined as {} with {} peer(s)",
        endpoint.id(),
        session.peers().len()
    );

    let mut peers = session.watch_peers();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            changed = peers.changed() => {
                changed?;
                for peer in peers.borrow().iter() {
                    println!("peer {} (expires in {}s)", peer.addr.id, peer.expires_in_secs);
                }
            }
        }
    }
    session.leave().await?;
    endpoint.close().await;
    Ok(())
}
