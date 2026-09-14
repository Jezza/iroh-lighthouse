use clap::Parser;
use iroh_lighthouse_server::Server;
use iroh_lighthouse_server::cli::Cli;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = match Cli::parse().into_config() {
        Ok(config) => config,
        Err(err) => {
            error!(%err, "invalid configuration");
            std::process::exit(2);
        }
    };

    let server = match Server::spawn(config).await {
        Ok(server) => server,
        Err(err) => {
            error!(%err, "failed to start");
            std::process::exit(1);
        }
    };

    if let Some(addr) = server.http_addr() {
        info!(%addr, "http carrier ready");
    }
    if let Some(endpoint) = server.endpoint() {
        info!(id = %endpoint.id(), "iroh carrier ready");
        println!("lighthouse endpoint id: {}", endpoint.id());
    }

    wait_for_shutdown_signal().await;
    info!("shutting down");
    if let Err(err) = server.shutdown().await {
        error!(%err, "shutdown incomplete");
        std::process::exit(1);
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
