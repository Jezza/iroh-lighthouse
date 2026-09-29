//! Atomic JSON snapshots of the registry.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use tracing::{info, warn};

use crate::registry::Registry;

/// Load a snapshot and drop everything that expired before `now`.
///
/// A missing file yields an empty registry. A corrupt file is logged and
/// treated as missing rather than aborting startup.
pub fn load(path: &Path, now: u64) -> Registry {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            info!(path = %path.display(), "no snapshot found, starting empty");
            return Registry::default();
        }
        Err(err) => {
            warn!(path = %path.display(), %err, "cannot read snapshot, starting empty");
            return Registry::default();
        }
    };
    match serde_json::from_slice::<Registry>(&bytes) {
        Ok(mut registry) => {
            let expired = registry.sweep(now);
            info!(
                path = %path.display(),
                topics = registry.topic_count(),
                directory = registry.directory_len(),
                expired,
                "restored snapshot"
            );
            registry
        }
        Err(err) => {
            warn!(path = %path.display(), %err, "corrupt snapshot ignored, starting empty");
            Registry::default()
        }
    }
}

/// Write the registry to `path` atomically: temp file, fsync, rename.
pub fn save(path: &Path, registry: &Registry) -> io::Result<()> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot path has no file name",
        )
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);

    let bytes = serde_json::to_vec(registry).map_err(io::Error::other)?;
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::{EndpointAddr, SecretKey};
    use iroh_lighthouse::Topic;

    use super::*;
    use crate::registry::SizeLimits;

    const LIMITS: SizeLimits = SizeLimits {
        max_peers_per_topic: 10,
        max_topics: 10,
    };

    fn addr(port: u16) -> EndpointAddr {
        EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    #[test]
    fn save_then_load_round_trips_live_entries_and_drops_expired_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");
        let topic = Topic::new("t").id();
        let (live, dead) = (addr(1), addr(2));

        let mut reg = Registry::default();
        reg.announce(Some(topic), live.clone(), 100, 1000, LIMITS)
            .unwrap();
        reg.announce(Some(topic), dead.clone(), 100, 150, LIMITS)
            .unwrap();
        reg.announce(None, live.clone(), 100, 1000, LIMITS).unwrap();
        save(&path, &reg).unwrap();

        let loaded = load(&path, 200);
        let peers = loaded.lookup(&topic, 200);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, live);
        assert_eq!(peers[0].expires_in_secs, 800);
        assert!(loaded.resolve(&live.id, 200).is_some());
        assert!(
            !std::fs::read_dir(dir.path())
                .unwrap()
                .any(|e| { e.unwrap().file_name().to_string_lossy().contains("tmp") }),
            "no temp file left behind"
        );
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load(&dir.path().join("nope.json"), 0);
        assert_eq!(loaded, Registry::default());
    }

    #[test]
    fn corrupt_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert_eq!(load(&path, 0), Registry::default());
    }

    #[test]
    fn save_overwrites_previous_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");
        let topic = Topic::new("t").id();
        let mut reg = Registry::default();
        reg.announce(Some(topic), addr(1), 100, 1000, LIMITS)
            .unwrap();
        save(&path, &reg).unwrap();
        reg.announce(Some(topic), addr(2), 100, 1000, LIMITS)
            .unwrap();
        save(&path, &reg).unwrap();
        assert_eq!(load(&path, 100).lookup(&topic, 100).len(), 2);
    }
}
