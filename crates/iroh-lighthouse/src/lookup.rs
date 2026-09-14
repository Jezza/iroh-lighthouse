//! Plug a lighthouse into iroh's address lookup.
//!
//! [`LighthouseLookup`] publishes this endpoint's address to the lighthouse
//! directory whenever iroh reports a change, and resolves other endpoints by id
//! through the same lighthouse. A node configured with it can dial any
//! published peer knowing only the lighthouse and the peer's id.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, Error, Item,
};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use n0_future::StreamExt;
use n0_future::boxed::BoxStream;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use url::Url;

use crate::client::Lighthouse;

/// Default lifetime of a directory entry, refreshed at half this interval.
pub const DEFAULT_DIRECTORY_TTL: Duration = Duration::from_secs(3600);

/// Provenance string attached to every resolved item.
pub const PROVENANCE: &str = "iroh-lighthouse";

const MIN_REPUBLISH: Duration = Duration::from_secs(1);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
enum Target {
    Http(Url),
    Iroh(EndpointAddr),
}

/// Builder for the lighthouse address lookup service.
///
/// Pass it to `Endpoint::builder(..).address_lookup(..)`.
#[derive(Debug, Clone)]
pub struct LighthouseLookup {
    target: Target,
    ttl: Duration,
}

impl LighthouseLookup {
    /// Use the lighthouse at `url` over HTTP(S).
    pub fn http(url: Url) -> Self {
        Self {
            target: Target::Http(url),
            ttl: DEFAULT_DIRECTORY_TTL,
        }
    }

    /// Use the lighthouse over iroh at `lighthouse`, dialled from the endpoint being built.
    pub fn iroh(lighthouse: EndpointAddr) -> Self {
        Self {
            target: Target::Iroh(lighthouse),
            ttl: DEFAULT_DIRECTORY_TTL,
        }
    }

    /// Lifetime requested for directory entries. Default one hour.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

impl AddressLookupBuilder for LighthouseLookup {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        let lighthouse = match self.target {
            Target::Http(url) => Lighthouse::http(url),
            Target::Iroh(addr) => Lighthouse::iroh(endpoint.clone(), addr),
        };
        Ok(Service {
            lighthouse,
            key: endpoint.secret_key().clone(),
            id: endpoint.id(),
            ttl: self.ttl,
            publisher: Mutex::new(None),
        })
    }
}

/// The running service: one lighthouse handle plus the current republish task.
#[derive(Debug)]
struct Service {
    lighthouse: Lighthouse,
    key: SecretKey,
    id: EndpointId,
    ttl: Duration,
    publisher: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(task) = self
            .publisher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

impl AddressLookup for Service {
    fn publish(&self, data: &EndpointData) {
        let mut slot = self.publisher.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = slot.take() {
            old.abort();
        }
        if data.addrs().next().is_none() {
            debug!("no addresses to publish to the lighthouse yet");
            return;
        }
        let addr = EndpointAddr::from_parts(self.id, data.addrs().cloned());
        *slot = Some(tokio::spawn(republish(
            self.lighthouse.clone(),
            self.key.clone(),
            addr,
            self.ttl,
        )));
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let lighthouse = self.lighthouse.clone();
        let lookup = async move {
            match lighthouse.resolve(endpoint_id).await {
                Ok(Some(peer)) => Some(Ok(Item::new(
                    EndpointInfo::from(peer.addr),
                    PROVENANCE,
                    Some(now_millis()),
                ))),
                Ok(None) => None,
                Err(err) => Some(Err(Error::from_err(PROVENANCE, err))),
            }
        };
        Some(Box::pin(
            n0_future::stream::once_future(lookup).flat_map(n0_future::stream::iter),
        ))
    }
}

async fn republish(lighthouse: Lighthouse, key: SecretKey, addr: EndpointAddr, ttl: Duration) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match lighthouse.announce(&key, None, addr.clone(), ttl).await {
            Ok(announced) => {
                backoff = INITIAL_BACKOFF;
                tokio::time::sleep((announced.ttl / 2).max(MIN_REPUBLISH)).await;
            }
            Err(err) => {
                warn!(%err, retry_in = ?backoff, "directory publish failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
