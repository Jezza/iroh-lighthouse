//! `lighthouse`: poke a deployed lighthouse from the command line.

use std::time::Duration;

use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId};
use iroh_lighthouse_client::protocol::Peer;
use iroh_lighthouse_client::{Lighthouse, Topic, parse_url};
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "lighthouse",
    version,
    about = "Talk to an iroh-lighthouse server"
)]
struct Cli {
    /// Lighthouse URL or host, for example iroh.ichor.io (https is assumed;
    /// http for localhost and IP addresses)
    #[arg(long, env = "LIGHTHOUSE_URL", value_parser = parse_url)]
    url: Url,
    /// Fetch the lighthouse's iroh address over HTTP, then use the iroh carrier.
    #[arg(long)]
    via_iroh: bool,
    /// Bind local endpoints without the n0 relay infrastructure.
    #[arg(long)]
    no_relays: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the lighthouse's version, iroh address, and limits.
    Info,
    /// List the members of a topic without joining it.
    Lookup {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        secret: Option<String>,
    },
    /// Look up a published endpoint by id.
    Resolve { id: EndpointId },
    /// Join a topic with a fresh endpoint and print peers as they come, go, or move, until Ctrl-C.
    Join {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        secret: Option<String>,
        /// Registration lifetime; the session re-announces at half of it.
        #[arg(long, default_value = "1h", value_parser = humantime::parse_duration)]
        ttl: Duration,
        /// How often to poll the topic for membership changes.
        #[arg(long, default_value = "10s", value_parser = humantime::parse_duration)]
        poll: Duration,
    },
}

fn topic(name: &str, secret: Option<&str>) -> Topic {
    match secret {
        Some(secret) => Topic::with_secret(name, secret.as_bytes()),
        None => Topic::new(name),
    }
}

fn print_peers(peers: &[Peer]) {
    if peers.is_empty() {
        println!("  (no other peers)");
    }
    for peer in peers {
        let relays: Vec<String> = peer.addr.relay_urls().map(ToString::to_string).collect();
        let ips: Vec<String> = peer.addr.ip_addrs().map(ToString::to_string).collect();
        println!(
            "  {}  expires in {}s  relays={relays:?}  ips={ips:?}",
            peer.addr.id, peer.expires_in_secs
        );
    }
}

async fn bind(no_relays: bool) -> anyhow::Result<Endpoint> {
    let endpoint = if no_relays {
        Endpoint::builder(presets::Minimal).bind().await?
    } else {
        Endpoint::builder(presets::N0).bind().await?
    };
    Ok(endpoint)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();

    let endpoint = match &cli.command {
        Command::Join { .. } => Some(bind(cli.no_relays).await?),
        _ if cli.via_iroh => Some(bind(cli.no_relays).await?),
        _ => None,
    };

    let http = Lighthouse::http(cli.url.clone());
    let lighthouse = if cli.via_iroh {
        let info = http.info().await?;
        let addr = info
            .lighthouse
            .ok_or_else(|| anyhow::anyhow!("lighthouse has the iroh carrier disabled"))?;
        Lighthouse::iroh(
            endpoint.clone().expect("endpoint bound for iroh carrier"),
            addr,
        )
    } else {
        http
    };

    match cli.command {
        Command::Info => {
            let info = lighthouse.info().await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Command::Lookup {
            topic: name,
            secret,
        } => {
            let topic = topic(&name, secret.as_deref());
            let peers = lighthouse.lookup(&topic).await?;
            println!("topic {} ({}): {} peer(s)", name, topic.id(), peers.len());
            print_peers(&peers);
        }
        Command::Resolve { id } => match lighthouse.resolve(id).await? {
            Some(peer) => println!("{}", serde_json::to_string_pretty(&peer)?),
            None => {
                println!("not found");
                std::process::exit(1);
            }
        },
        Command::Join {
            topic: name,
            secret,
            ttl,
            poll,
        } => {
            let endpoint = endpoint.as_ref().expect("endpoint bound for join");
            let topic = topic(&name, secret.as_deref());
            let session = lighthouse
                .join_with(endpoint, topic.clone(), ttl, Some(poll))
                .await?;
            println!(
                "joined topic {} ({}) as {} for {}, polling every {}",
                name,
                topic.id(),
                endpoint.id(),
                humantime::format_duration(ttl),
                humantime::format_duration(poll)
            );
            print_peers(&session.peers());
            let mut watch = session.watch_peers();
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    changed = watch.changed() => {
                        if changed.is_err() { break; }
                        println!("peers updated:");
                        print_peers(&watch.borrow());
                    }
                }
            }
            println!("leaving");
            session.leave().await?;
        }
    }
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroh_lighthouse_client::DEFAULT_POLL_INTERVAL;

    use super::*;

    #[test]
    fn every_subcommand_parses() {
        let base = ["lighthouse", "--url", "https://iroh.ichor.io"];
        let info = Cli::try_parse_from(base.iter().chain(["info"].iter())).unwrap();
        assert!(matches!(info.command, Command::Info));
        assert!(!info.via_iroh);

        let lookup = Cli::try_parse_from(
            base.iter()
                .chain(["--via-iroh", "lookup", "--topic", "chat", "--secret", "s"].iter()),
        )
        .unwrap();
        assert!(lookup.via_iroh);
        assert!(
            matches!(lookup.command, Command::Lookup { ref topic, secret: Some(ref s) } if topic == "chat" && s == "s")
        );

        let join = Cli::try_parse_from(
            base.iter()
                .chain(["join", "--topic", "chat", "--ttl", "2h", "--poll", "3s"].iter()),
        )
        .unwrap();
        assert!(matches!(
            join.command,
            Command::Join { ttl, poll, .. }
                if ttl == Duration::from_secs(7200) && poll == Duration::from_secs(3)
        ));

        let id = iroh::SecretKey::generate().public().to_string();
        let resolve =
            Cli::try_parse_from(base.iter().chain(["resolve", id.as_str()].iter())).unwrap();
        assert!(matches!(resolve.command, Command::Resolve { .. }));
    }

    #[test]
    fn join_polls_at_the_library_default() {
        let cli = Cli::try_parse_from([
            "lighthouse",
            "--url",
            "https://iroh.ichor.io",
            "join",
            "--topic",
            "t",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Join { poll, .. } if poll == DEFAULT_POLL_INTERVAL));
    }

    #[test]
    fn bare_host_url_parses() {
        let cli = Cli::try_parse_from(["lighthouse", "--url", "iroh.ichor.io", "info"]).unwrap();
        assert_eq!(cli.url.as_str(), "https://iroh.ichor.io/");
    }

    #[test]
    fn secret_selects_private_topic() {
        assert_eq!(topic("chat", None).id(), Topic::new("chat").id());
        assert_ne!(topic("chat", Some("s")).id(), Topic::new("chat").id());
    }
}
