//! Wiring: configuration, startup, background tasks, and shutdown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, SecretKey, Watcher};
use iroh_lighthouse::protocol::ALPN;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::handler::{Ctx, Limits, now_unix};
use crate::http;
use crate::iroh_carrier::LighthouseProtocol;
use crate::registry::{Registry, SizeLimits};
use crate::snapshot;

/// How the iroh carrier binds.
#[derive(Debug, Clone)]
pub struct IrohConfig {
    /// Key that gives the lighthouse a stable endpoint id.
    pub secret_key: SecretKey,
    /// UDP port to bind on IPv4; `0` lets iroh pick ports on both address families.
    pub bind_port: u16,
    /// Use the n0 relay and DNS infrastructure so the lighthouse is reachable
    /// through relays. Disable for isolated or test deployments.
    pub relays: bool,
    /// Public addresses to advertise on top of whatever iroh discovers, for
    /// hosts behind NAT or a Docker port mapping where discovery cannot see
    /// the address peers must dial.
    pub external_addrs: Vec<SocketAddr>,
}

/// Where and how often to persist the registry.
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    pub path: PathBuf,
    pub interval: Duration,
}

/// Everything needed to start a server.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP bind address; `None` disables the HTTP carrier.
    pub http_listen: Option<SocketAddr>,
    /// iroh carrier settings; `None` disables it.
    pub iroh: Option<IrohConfig>,
    /// Snapshot persistence; `None` keeps everything in memory only.
    pub snapshot: Option<SnapshotConfig>,
    pub sweep_interval: Duration,
    pub limits: Limits,
}

impl Default for Config {
    /// Production defaults with a fresh iroh key.
    fn default() -> Self {
        Self {
            http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
            iroh: Some(IrohConfig {
                secret_key: SecretKey::generate(),
                bind_port: 0,
                relays: true,
                external_addrs: Vec::new(),
            }),
            snapshot: None,
            sweep_interval: Duration::from_secs(30),
            limits: Limits {
                min_ttl_secs: 10,
                max_ttl_secs: 7 * 24 * 3600,
                max_skew_secs: 300,
                size: SizeLimits {
                    max_peers_per_topic: 256,
                    max_topics: 10_000,
                },
            },
        }
    }
}

/// Errors from starting or stopping a server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("no carrier enabled: both http and iroh are disabled")]
    NoCarrier,
    #[error("http bind failed: {0}")]
    HttpBind(#[source] std::io::Error),
    #[error("iroh bind failed: {0}")]
    IrohBind(String),
    #[error("snapshot write failed: {0}")]
    Snapshot(#[source] std::io::Error),
}

/// A running lighthouse.
#[derive(Debug)]
pub struct Server {
    ctx: Arc<Ctx>,
    http_addr: Option<SocketAddr>,
    http_task: Option<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
    router: Option<Router>,
    tasks: JoinSet<()>,
    shutdown: watch::Sender<bool>,
    snapshot_path: Option<PathBuf>,
}

impl Server {
    /// Start every enabled carrier and background task.
    pub async fn spawn(config: Config) -> Result<Self, ServerError> {
        if config.http_listen.is_none() && config.iroh.is_none() {
            return Err(ServerError::NoCarrier);
        }

        let registry = match &config.snapshot {
            Some(snap) => snapshot::load(&snap.path, now_unix()),
            None => Registry::default(),
        };
        let ctx = Arc::new(Ctx::new(registry, config.limits));
        let mut tasks = JoinSet::new();
        let (shutdown, shutdown_rx) = watch::channel(false);

        let (endpoint, router) = match config.iroh {
            Some(iroh) => {
                let (endpoint, router) = bind_iroh(iroh, &ctx, &mut tasks).await?;
                (Some(endpoint), Some(router))
            }
            None => (None, None),
        };

        let (http_addr, http_task) = match config.http_listen {
            Some(listen) => {
                let listener = TcpListener::bind(listen)
                    .await
                    .map_err(ServerError::HttpBind)?;
                let local = listener.local_addr().map_err(ServerError::HttpBind)?;
                let app = http::router(ctx.clone());
                let mut rx = shutdown_rx.clone();
                let task = tokio::spawn(async move {
                    let result = axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = rx.wait_for(|stop| *stop).await;
                        })
                        .await;
                    if let Err(err) = result {
                        warn!(%err, "http server exited with error");
                    }
                });
                info!(%local, "http carrier listening");
                (Some(local), Some(task))
            }
            None => (None, None),
        };

        spawn_sweeper(ctx.clone(), config.sweep_interval, &mut tasks);
        if let Some(snap) = &config.snapshot {
            spawn_snapshotter(ctx.clone(), snap.clone(), &mut tasks);
        }

        Ok(Self {
            ctx,
            http_addr,
            http_task,
            endpoint,
            router,
            tasks,
            shutdown,
            snapshot_path: config.snapshot.map(|snap| snap.path),
        })
    }

    /// Shared handler state, mostly for tests and embedding.
    pub fn ctx(&self) -> &Arc<Ctx> {
        &self.ctx
    }

    /// Where HTTP is listening, if enabled.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The lighthouse's iroh endpoint, if enabled.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    /// The lighthouse's current iroh address, if enabled.
    pub fn endpoint_addr(&self) -> Option<EndpointAddr> {
        self.endpoint.as_ref().map(Endpoint::addr)
    }

    /// Stop accepting, write a final snapshot, and release everything.
    pub async fn shutdown(mut self) -> Result<(), ServerError> {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.http_task.take()
            && tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .is_err()
        {
            warn!("http server did not drain in time");
        }
        if let Some(router) = self.router.take()
            && let Err(err) = router.shutdown().await
        {
            warn!(%err, "iroh router shutdown failed");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close().await;
        }
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}

        if let Some(path) = self.snapshot_path.take() {
            let registry = self.ctx.registry().clone();
            tokio::task::spawn_blocking(move || snapshot::save(&path, &registry))
                .await
                .map_err(|err| ServerError::Snapshot(std::io::Error::other(err)))?
                .map_err(ServerError::Snapshot)?;
        }
        Ok(())
    }
}

async fn bind_iroh(
    config: IrohConfig,
    ctx: &Arc<Ctx>,
    tasks: &mut JoinSet<()>,
) -> Result<(Endpoint, Router), ServerError> {
    let mut builder = if config.relays {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::Minimal)
    };
    builder = builder
        .secret_key(config.secret_key)
        .alpns(vec![ALPN.to_vec()]);
    if config.bind_port != 0 {
        builder = builder
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], config.bind_port)))
            .map_err(|err| ServerError::IrohBind(err.to_string()))?;
    }
    for addr in &config.external_addrs {
        builder = builder.external_addr(*addr);
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|err| ServerError::IrohBind(err.to_string()))?;
    info!(
        id = %endpoint.id(),
        external = ?config.external_addrs,
        "iroh carrier bound"
    );

    ctx.set_lighthouse(Some(endpoint.addr()));
    let mut watcher = endpoint.watch_addr();
    let ctx_for_watch = ctx.clone();
    tasks.spawn(async move {
        loop {
            ctx_for_watch.set_lighthouse(Some(watcher.get()));
            if watcher.updated().await.is_err() {
                break;
            }
        }
    });

    let router = Router::builder(endpoint.clone())
        .accept(ALPN, LighthouseProtocol::new(ctx.clone()))
        .spawn();
    Ok((endpoint, router))
}

fn spawn_sweeper(ctx: Arc<Ctx>, every: Duration, tasks: &mut JoinSet<()>) {
    tasks.spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let removed = ctx.registry().sweep(now_unix());
            if removed > 0 {
                debug!(removed, "swept expired entries");
            }
        }
    });
}

fn spawn_snapshotter(ctx: Arc<Ctx>, config: SnapshotConfig, tasks: &mut JoinSet<()>) {
    tasks.spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let registry = {
                let mut guard = ctx.registry();
                if !guard.take_dirty() {
                    continue;
                }
                guard.clone()
            };
            let path = config.path.clone();
            match tokio::task::spawn_blocking(move || snapshot::save(&path, &registry)).await {
                Ok(Ok(())) => debug!(path = %config.path.display(), "snapshot written"),
                Ok(Err(err)) => warn!(path = %config.path.display(), %err, "snapshot failed"),
                Err(err) => warn!(%err, "snapshot task panicked"),
            }
        }
    });
}
