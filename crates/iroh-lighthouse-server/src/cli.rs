//! Command-line and environment configuration for the server binary.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use iroh::SecretKey;

use crate::handler::Limits;
use crate::registry::SizeLimits;
use crate::server::{Config, IrohConfig, SnapshotConfig};

/// Every flag has an environment fallback prefixed `LIGHTHOUSE_`.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "iroh-lighthouse-server",
    version,
    about = "Topic rendezvous and address lookup for iroh nodes"
)]
pub struct Cli {
    /// HTTP bind address. Put a TLS-terminating reverse proxy in front of it.
    #[arg(long, env = "LIGHTHOUSE_HTTP_LISTEN", default_value = "127.0.0.1:8080")]
    pub http_listen: SocketAddr,
    /// Disable the HTTP carrier.
    #[arg(long, env = "LIGHTHOUSE_NO_HTTP")]
    pub no_http: bool,
    /// UDP port for the iroh carrier on IPv4; 0 lets iroh pick.
    #[arg(long, env = "LIGHTHOUSE_IROH_PORT", default_value_t = 0)]
    pub iroh_port: u16,
    /// Disable the iroh carrier.
    #[arg(long, env = "LIGHTHOUSE_NO_IROH")]
    pub no_iroh: bool,
    /// Run the iroh carrier without the n0 relay and DNS infrastructure.
    #[arg(long, env = "LIGHTHOUSE_NO_RELAYS")]
    pub no_relays: bool,
    /// File holding the lighthouse's iroh secret key; created if missing.
    #[arg(
        long,
        env = "LIGHTHOUSE_SECRET_KEY_FILE",
        default_value = "lighthouse.key"
    )]
    pub secret_key_file: PathBuf,
    /// Registry snapshot file.
    #[arg(
        long,
        env = "LIGHTHOUSE_SNAPSHOT",
        default_value = "lighthouse.snapshot.json"
    )]
    pub snapshot: PathBuf,
    /// Keep the registry in memory only.
    #[arg(long, env = "LIGHTHOUSE_NO_SNAPSHOT")]
    pub no_snapshot: bool,
    /// How often to write the snapshot when it changed.
    #[arg(long, env = "LIGHTHOUSE_SNAPSHOT_INTERVAL", default_value = "5s", value_parser = humantime::parse_duration)]
    pub snapshot_interval: Duration,
    /// How often to drop expired entries.
    #[arg(long, env = "LIGHTHOUSE_SWEEP_INTERVAL", default_value = "30s", value_parser = humantime::parse_duration)]
    pub sweep_interval: Duration,
    /// Shortest TTL a node may request.
    #[arg(long, env = "LIGHTHOUSE_MIN_TTL", default_value = "10s", value_parser = humantime::parse_duration)]
    pub min_ttl: Duration,
    /// Longest TTL a node may request.
    #[arg(long, env = "LIGHTHOUSE_MAX_TTL", default_value = "7d", value_parser = humantime::parse_duration)]
    pub max_ttl: Duration,
    /// Tolerated distance between a request timestamp and the server clock.
    #[arg(long, env = "LIGHTHOUSE_MAX_SKEW", default_value = "5m", value_parser = humantime::parse_duration)]
    pub max_skew: Duration,
    #[arg(long, env = "LIGHTHOUSE_MAX_PEERS_PER_TOPIC", default_value_t = 256)]
    pub max_peers_per_topic: usize,
    #[arg(long, env = "LIGHTHOUSE_MAX_TOPICS", default_value_t = 10_000)]
    pub max_topics: usize,
}

/// Configuration problems detected before anything is bound.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("both carriers are disabled; drop --no-http or --no-iroh")]
    NoCarrier,
    #[error("--min-ttl must be at least 1s and no greater than --max-ttl")]
    TtlRange,
    #[error("TTLs must fit in 32 bits of seconds")]
    TtlTooLarge,
    #[error("--max-peers-per-topic and --max-topics must be at least 1")]
    ZeroLimit,
    #[error("secret key file {path}: {source}")]
    Key {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Cli {
    /// Validate and turn the flags into a server [`Config`], loading or
    /// creating the secret key file when the iroh carrier is enabled.
    pub fn into_config(self) -> Result<Config, CliError> {
        if self.no_http && self.no_iroh {
            return Err(CliError::NoCarrier);
        }
        let min_ttl_secs = ttl_secs(self.min_ttl)?;
        let max_ttl_secs = ttl_secs(self.max_ttl)?;
        if min_ttl_secs == 0 || min_ttl_secs > max_ttl_secs {
            return Err(CliError::TtlRange);
        }
        if self.max_peers_per_topic == 0 || self.max_topics == 0 {
            return Err(CliError::ZeroLimit);
        }

        let iroh = if self.no_iroh {
            None
        } else {
            let secret_key =
                load_or_create_key(&self.secret_key_file).map_err(|source| CliError::Key {
                    path: self.secret_key_file.clone(),
                    source,
                })?;
            Some(IrohConfig {
                secret_key,
                bind_port: self.iroh_port,
                relays: !self.no_relays,
            })
        };

        Ok(Config {
            http_listen: (!self.no_http).then_some(self.http_listen),
            iroh,
            snapshot: (!self.no_snapshot).then_some(SnapshotConfig {
                path: self.snapshot,
                interval: self.snapshot_interval,
            }),
            sweep_interval: self.sweep_interval,
            limits: Limits {
                min_ttl_secs,
                max_ttl_secs,
                max_skew_secs: self.max_skew.as_secs(),
                size: SizeLimits {
                    max_peers_per_topic: self.max_peers_per_topic,
                    max_topics: self.max_topics,
                },
            },
        })
    }
}

/// Read the secret key from `path`, or generate one and write it with mode 0600.
pub fn load_or_create_key(path: &Path) -> std::io::Result<SecretKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse::<SecretKey>()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            write_private(path, &encode_hex(&key.to_bytes()))?;
            Ok(key)
        }
        Err(err) => Err(err),
    }
}

fn ttl_secs(ttl: Duration) -> Result<u32, CliError> {
    u32::try_from(ttl.as_secs()).map_err(|_| CliError::TtlTooLarge)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 1);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push('\n');
    out
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], key_dir: &Path) -> Cli {
        let key = key_dir.join("test.key");
        let mut full = vec![
            "iroh-lighthouse-server",
            "--secret-key-file",
            key.to_str().unwrap(),
        ];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap()
    }

    #[test]
    fn defaults_are_production_values() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(&[], dir.path()).into_config().unwrap();
        assert_eq!(config.http_listen, Some("127.0.0.1:8080".parse().unwrap()));
        let iroh = config.iroh.unwrap();
        assert_eq!(iroh.bind_port, 0);
        assert!(iroh.relays);
        let snapshot = config.snapshot.unwrap();
        assert_eq!(snapshot.path, PathBuf::from("lighthouse.snapshot.json"));
        assert_eq!(snapshot.interval, Duration::from_secs(5));
        assert_eq!(config.sweep_interval, Duration::from_secs(30));
        assert_eq!(config.limits.min_ttl_secs, 10);
        assert_eq!(config.limits.max_ttl_secs, 7 * 24 * 3600);
        assert_eq!(config.limits.max_skew_secs, 300);
        assert_eq!(config.limits.size.max_peers_per_topic, 256);
        assert_eq!(config.limits.size.max_topics, 10_000);
    }

    #[test]
    fn carriers_and_snapshot_can_be_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let config = parse(&["--no-iroh", "--no-snapshot"], dir.path())
            .into_config()
            .unwrap();
        assert!(config.iroh.is_none());
        assert!(config.snapshot.is_none());
        assert!(
            !dir.path().join("test.key").exists(),
            "no key needed without iroh"
        );

        let config = parse(
            &["--no-http", "--no-relays", "--iroh-port", "4433"],
            dir.path(),
        )
        .into_config()
        .unwrap();
        assert!(config.http_listen.is_none());
        let iroh = config.iroh.unwrap();
        assert_eq!(iroh.bind_port, 4433);
        assert!(!iroh.relays);
    }

    #[test]
    fn disabling_both_carriers_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = parse(&["--no-http", "--no-iroh"], dir.path())
            .into_config()
            .unwrap_err();
        assert!(matches!(err, CliError::NoCarrier));
    }

    #[test]
    fn ttl_range_is_validated() {
        let dir = tempfile::tempdir().unwrap();
        let err = parse(&["--min-ttl", "1h", "--max-ttl", "10s"], dir.path())
            .into_config()
            .unwrap_err();
        assert!(matches!(err, CliError::TtlRange));
        let err = parse(&["--min-ttl", "0s"], dir.path())
            .into_config()
            .unwrap_err();
        assert!(matches!(err, CliError::TtlRange));
        let err = parse(&["--max-ttl", "200years"], dir.path())
            .into_config()
            .unwrap_err();
        assert!(matches!(err, CliError::TtlTooLarge));
        let config = parse(&["--min-ttl", "1s", "--max-ttl", "2d"], dir.path())
            .into_config()
            .unwrap();
        assert_eq!(config.limits.min_ttl_secs, 1);
        assert_eq!(config.limits.max_ttl_secs, 172_800);
    }

    #[test]
    fn zero_limits_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = parse(&["--max-peers-per-topic", "0"], dir.path())
            .into_config()
            .unwrap_err();
        assert!(matches!(err, CliError::ZeroLimit));
    }

    #[test]
    fn key_file_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lighthouse.key");
        let first = load_or_create_key(&path).unwrap();
        let second = load_or_create_key(&path).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let config = parse(&[], dir.path()).into_config().unwrap();
        let from_cli = load_or_create_key(&dir.path().join("test.key")).unwrap();
        assert_eq!(
            config.iroh.unwrap().secret_key.to_bytes(),
            from_cli.to_bytes()
        );
    }

    #[test]
    fn garbage_key_file_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lighthouse.key");
        std::fs::write(&path, "not a key").unwrap();
        assert!(load_or_create_key(&path).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "not a key",
            "left untouched"
        );
    }
}
