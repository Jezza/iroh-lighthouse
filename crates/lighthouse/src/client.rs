//! The client handle: one API over two carriers.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use tokio::sync::Mutex;
use url::Url;

use crate::protocol::{
    ALPN, AnnounceBody, ErrorBody, ErrorCode, HTTP_ANNOUNCE, HTTP_INFO, HTTP_LOOKUP, HTTP_RESOLVE,
    Info, LookupBody, MAX_MESSAGE_SIZE, Peer, Request, Response,
};
use crate::session::{DEFAULT_POLL_INTERVAL, Session};
use crate::topic::Topic;

/// Result of a successful announce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {
    /// The lifetime the lighthouse actually granted.
    pub ttl: Duration,
    /// Other members of the topic. Empty for directory publishes.
    pub peers: Vec<Peer>,
}

/// Everything that can go wrong talking to a lighthouse.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http transport: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http status {status} with non-protocol body: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("iroh transport: {0}")]
    Iroh(String),
    #[error("lighthouse refused the request ({:?}): {}", .0.code, .0.message)]
    Server(ErrorBody),
    #[error("could not decode response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unexpected response: {0:?}")]
    Unexpected(Response),
    #[error("message exceeds the protocol size limit")]
    TooLarge,
}

impl Error {
    /// The protocol error code, when the lighthouse answered with an error.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Error::Server(body) => Some(body.code),
            _ => None,
        }
    }

    fn iroh(err: impl fmt::Display) -> Self {
        Error::Iroh(err.to_string())
    }
}

enum Carrier {
    Http {
        client: reqwest::Client,
        base: Url,
    },
    Iroh {
        endpoint: Endpoint,
        lighthouse: EndpointAddr,
        conn: Mutex<Option<Connection>>,
    },
}

impl fmt::Debug for Carrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Carrier::Http { base, .. } => f.debug_struct("Http").field("base", base).finish(),
            Carrier::Iroh { lighthouse, .. } => f
                .debug_struct("Iroh")
                .field("lighthouse", &lighthouse.id)
                .finish(),
        }
    }
}

/// A handle to one lighthouse over one carrier. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Lighthouse {
    carrier: Arc<Carrier>,
}

impl Lighthouse {
    /// Talk to a lighthouse at `url` over HTTP(S), for example `https://iroh.ichor.io`.
    pub fn http(url: Url) -> Self {
        Self {
            carrier: Arc::new(Carrier::Http {
                client: reqwest::Client::new(),
                base: url,
            }),
        }
    }

    /// Talk to a lighthouse over iroh, dialling `lighthouse` from `endpoint`.
    pub fn iroh(endpoint: Endpoint, lighthouse: EndpointAddr) -> Self {
        Self {
            carrier: Arc::new(Carrier::Iroh {
                endpoint,
                lighthouse,
                conn: Mutex::new(None),
            }),
        }
    }

    /// Register `addr` on `topic` (or in the directory when `None`) for `ttl`.
    ///
    /// `key` must be the secret key of `addr.id`. A zero `ttl` unregisters.
    pub async fn announce(
        &self,
        key: &SecretKey,
        topic: Option<&Topic>,
        addr: EndpointAddr,
        ttl: Duration,
    ) -> Result<Announced, Error> {
        let body = AnnounceBody {
            topic: topic.map(Topic::id),
            addr,
            ttl_secs: u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX),
            ts: now_unix(),
        };
        match self
            .request(Request::Announce(body.sign(key, topic)))
            .await?
        {
            Response::Announced { ttl_secs, peers } => Ok(Announced {
                ttl: Duration::from_secs(u64::from(ttl_secs)),
                peers,
            }),
            other => Err(Error::Unexpected(other)),
        }
    }

    /// Read the members of a topic without registering.
    pub async fn lookup(&self, topic: &Topic) -> Result<Vec<Peer>, Error> {
        let body = LookupBody {
            topic: topic.id(),
            ts: now_unix(),
        };
        match self.request(Request::Lookup(body.sign(topic))).await? {
            Response::Peers { peers } => Ok(peers),
            other => Err(Error::Unexpected(other)),
        }
    }

    /// Look up a published node by id.
    pub async fn resolve(&self, id: EndpointId) -> Result<Option<Peer>, Error> {
        match self.request(Request::Resolve { id }).await {
            Ok(Response::Resolved { peer }) => Ok(Some(peer)),
            Ok(other) => Err(Error::Unexpected(other)),
            Err(err) if err.code() == Some(ErrorCode::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Join a topic: announce `endpoint` on it and keep the registration alive.
    ///
    /// Returns once the first announce succeeded. `ttl` is the requested
    /// lifetime; the session re-announces at half of whatever the lighthouse
    /// grants and polls the topic every [`DEFAULT_POLL_INTERVAL`] so
    /// [`Session::watch_peers`] tracks the other members.
    pub async fn join(
        &self,
        endpoint: &Endpoint,
        topic: Topic,
        ttl: Duration,
    ) -> Result<Session, Error> {
        self.join_with(endpoint, topic, ttl, Some(DEFAULT_POLL_INTERVAL))
            .await
    }

    /// [`join`](Self::join) with an explicit poll interval.
    ///
    /// Intervals under one second are raised to one second. `None` disables
    /// polling: the peer list then only updates on the keep-alive re-announce
    /// at half the granted TTL, on address changes, and on [`Session::refresh`].
    pub async fn join_with(
        &self,
        endpoint: &Endpoint,
        topic: Topic,
        ttl: Duration,
        poll_interval: Option<Duration>,
    ) -> Result<Session, Error> {
        Session::start(
            self.clone(),
            endpoint.clone(),
            topic,
            ttl,
            poll_interval,
            #[cfg(feature = "dht-fallback")]
            None,
        )
        .await
    }

    /// [`join`](Self::join) with a DHT fallback for when this lighthouse is
    /// unreachable.
    ///
    /// Behaves exactly like [`join`](Self::join) while the lighthouse answers.
    /// When it does not, the session publishes its address to, and reads the
    /// topic's members from, the BitTorrent mainline DHT — so a topic keeps
    /// working through an outage, and a node can even join during one.
    ///
    /// The lighthouse is retried on the usual backoff throughout; the DHT is a
    /// stand-in, never a replacement. Peers found either way are ordinary
    /// [`Peer`](crate::protocol::Peer) values carrying a full address, so
    /// callers cannot tell — and do not need to — which path produced them.
    ///
    /// The topic's secret gates the DHT slot as well as the lighthouse topic
    /// id, so a private topic stays private on the fallback path. See
    /// [`fallback`](crate::fallback) for how that derivation works.
    #[cfg(feature = "dht-fallback")]
    pub async fn join_with_fallback(
        &self,
        endpoint: &Endpoint,
        topic: Topic,
        ttl: Duration,
        poll_interval: Option<Duration>,
    ) -> Result<Session, Error> {
        let fallback = std::sync::Arc::new(crate::fallback::DhtFallback::new(endpoint, &topic));
        Session::start(
            self.clone(),
            endpoint.clone(),
            topic,
            ttl,
            poll_interval,
            Some(fallback),
        )
        .await
    }

    /// Describe the lighthouse.
    pub async fn info(&self) -> Result<Info, Error> {
        match self.request(Request::Info).await? {
            Response::Info(info) => Ok(info),
            other => Err(Error::Unexpected(other)),
        }
    }

    /// Send one request over whichever carrier this handle uses and surface
    /// protocol errors as [`Error::Server`].
    async fn request(&self, req: Request) -> Result<Response, Error> {
        let response = match &*self.carrier {
            Carrier::Http { client, base } => http_request(client, base, &req).await?,
            Carrier::Iroh {
                endpoint,
                lighthouse,
                conn,
            } => iroh_request(endpoint, lighthouse, conn, &req).await?,
        };
        match response {
            Response::Error(body) => Err(Error::Server(body)),
            other => Ok(other),
        }
    }
}

/// Parse a lighthouse address, filling in the scheme when it is left out.
///
/// `iroh.ichor.io` becomes `https://iroh.ichor.io`. `localhost` and IP
/// addresses get `http://` instead, since those are local or have no
/// certificate. Input that already has a scheme is used as is.
pub fn parse_url(input: &str) -> Result<Url, url::ParseError> {
    if input.contains("://") {
        return Url::parse(input);
    }
    let https = Url::parse(&format!("https://{input}"))?;
    let local = match https.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost" || domain.ends_with(".localhost"),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => true,
        None => false,
    };
    if local {
        Url::parse(&format!("http://{input}"))
    } else {
        Ok(https)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn route(base: &Url, path: &str) -> Result<Url, Error> {
    let joined = format!("{}{}", base.as_str().trim_end_matches('/'), path);
    Url::parse(&joined).map_err(|err| Error::HttpStatus {
        status: 0,
        body: format!("invalid lighthouse url {joined}: {err}"),
    })
}

async fn http_request(
    client: &reqwest::Client,
    base: &Url,
    req: &Request,
) -> Result<Response, Error> {
    let builder = match req {
        Request::Announce(announce) => client.post(route(base, HTTP_ANNOUNCE)?).json(announce),
        Request::Lookup(lookup) => client.post(route(base, HTTP_LOOKUP)?).json(lookup),
        Request::Resolve { id } => client.get(route(base, &format!("{HTTP_RESOLVE}/{id}"))?),
        Request::Info => client.get(route(base, HTTP_INFO)?),
    };
    let http = builder.send().await?;
    let status = http.status();
    let bytes = http.bytes().await?;
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge);
    }
    match serde_json::from_slice::<Response>(&bytes) {
        Ok(response) => Ok(response),
        Err(_) if !status.is_success() => Err(Error::HttpStatus {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }),
        Err(err) => Err(err.into()),
    }
}

async fn iroh_request(
    endpoint: &Endpoint,
    lighthouse: &EndpointAddr,
    slot: &Mutex<Option<Connection>>,
    req: &Request,
) -> Result<Response, Error> {
    let payload = serde_json::to_vec(req)?;
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge);
    }

    // Reuse the connection when we have one; on any failure drop it and retry
    // once on a fresh connection, since the cached one may have gone stale.
    let mut guard = slot.lock().await;
    let mut fresh = false;
    loop {
        let conn = match guard.as_ref() {
            Some(conn) => conn.clone(),
            None => {
                let conn = endpoint
                    .connect(lighthouse.clone(), ALPN)
                    .await
                    .map_err(Error::iroh)?;
                *guard = Some(conn.clone());
                fresh = true;
                conn
            }
        };
        match exchange(&conn, &payload).await {
            Ok(response) => return Ok(response),
            Err(err) => {
                *guard = None;
                if fresh {
                    return Err(err);
                }
            }
        }
    }
}

async fn exchange(conn: &Connection, payload: &[u8]) -> Result<Response, Error> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(Error::iroh)?;
    send.write_all(payload).await.map_err(Error::iroh)?;
    send.finish().map_err(Error::iroh)?;
    let bytes = recv
        .read_to_end(MAX_MESSAGE_SIZE)
        .await
        .map_err(Error::iroh)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_defaults_to_https() {
        let parse = |s| parse_url(s).unwrap().to_string();
        assert_eq!(parse("iroh.ichor.io"), "https://iroh.ichor.io/");
        assert_eq!(parse("iroh.ichor.io:8443"), "https://iroh.ichor.io:8443/");
        assert_eq!(parse("iroh.ichor.io/lighthouse"), "https://iroh.ichor.io/lighthouse");
    }

    #[test]
    fn local_and_ip_hosts_default_to_http() {
        let parse = |s| parse_url(s).unwrap().to_string();
        assert_eq!(parse("localhost:8080"), "http://localhost:8080/");
        assert_eq!(parse("127.0.0.1:8080"), "http://127.0.0.1:8080/");
        assert_eq!(parse("[::1]:8080"), "http://[::1]:8080/");
        assert_eq!(parse("10.0.0.5:443"), "http://10.0.0.5:443/");
    }

    #[test]
    fn explicit_scheme_is_kept() {
        let parse = |s| parse_url(s).unwrap().to_string();
        assert_eq!(parse("http://iroh.ichor.io"), "http://iroh.ichor.io/");
        assert_eq!(parse("https://localhost:8080"), "https://localhost:8080/");
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_url("").is_err());
        assert!(parse_url("not a host").is_err());
    }
}
