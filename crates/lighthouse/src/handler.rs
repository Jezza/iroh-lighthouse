//! The single, carrier-agnostic request handler.
//!
//! Every rule of the protocol lives here: freshness, signatures, TTL clamping,
//! limits, and response shaping. Carriers only decode, call, and encode.

use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use iroh::EndpointAddr;
use iroh_lighthouse_protocol::{
    Announce, AnnounceBody, ErrorCode, Info, Lookup, Peer, Request, Response,
};

use crate::registry::{Registry, RegistryError, SizeLimits};

/// Everything the handler is allowed to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min_ttl_secs: u32,
    pub max_ttl_secs: u32,
    /// Maximum tolerated distance between a request timestamp and the server clock.
    pub max_skew_secs: u64,
    pub size: SizeLimits,
}

/// Shared state behind every carrier.
#[derive(Debug)]
pub struct Ctx {
    pub registry: Mutex<Registry>,
    pub limits: Limits,
    /// The lighthouse's own iroh address, kept current by the iroh carrier.
    pub lighthouse: RwLock<Option<EndpointAddr>>,
}

impl Ctx {
    pub fn new(registry: Registry, limits: Limits) -> Self {
        Self {
            registry: Mutex::new(registry),
            limits,
            lighthouse: RwLock::new(None),
        }
    }

    /// Lock the registry, recovering from a poisoned lock: the registry is
    /// plain data, so a panic mid-update cannot leave it harmfully inconsistent.
    pub fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Record the lighthouse's current iroh address for the info request.
    pub fn set_lighthouse(&self, addr: Option<EndpointAddr>) {
        *self
            .lighthouse
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = addr;
    }
}

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Handle a request against the wall clock.
pub fn handle(ctx: &Ctx, req: Request) -> Response {
    handle_at(ctx, req, now_unix())
}

/// Handle a request as if the current time were `now`.
pub fn handle_at(ctx: &Ctx, req: Request, now: u64) -> Response {
    match req {
        Request::Announce(announce) => handle_announce(ctx, announce, now),
        Request::Lookup(lookup) => handle_lookup(ctx, lookup, now),
        Request::Resolve { id } => match lock(ctx).resolve(&id, now) {
            Some(peer) => Response::Resolved { peer },
            None => Response::error(
                ErrorCode::NotFound,
                "no directory entry for that endpoint id",
            ),
        },
        Request::Info => Response::Info(Info {
            version: env!("CARGO_PKG_VERSION").to_string(),
            lighthouse: ctx
                .lighthouse
                .read()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            min_ttl_secs: ctx.limits.min_ttl_secs,
            max_ttl_secs: ctx.limits.max_ttl_secs,
            max_peers_per_topic: u32::try_from(ctx.limits.size.max_peers_per_topic)
                .unwrap_or(u32::MAX),
        }),
    }
}

fn handle_announce(ctx: &Ctx, announce: Announce, now: u64) -> Response {
    if let Err(resp) = check_fresh(announce.body.ts, now, ctx.limits.max_skew_secs) {
        return resp;
    }
    if let Err(err) = announce.verify() {
        return Response::error(ErrorCode::BadSignature, err.to_string());
    }
    let AnnounceBody {
        topic,
        addr,
        ttl_secs,
        ts,
    } = announce.body;

    let mut registry = lock(ctx);
    if ttl_secs == 0 {
        registry.unregister(topic, &addr.id);
        return Response::Announced {
            ttl_secs: 0,
            peers: Vec::new(),
        };
    }

    let ttl_secs = ttl_secs.clamp(ctx.limits.min_ttl_secs, ctx.limits.max_ttl_secs);
    let expires_at = ts.saturating_add(u64::from(ttl_secs));
    let self_id = addr.id;
    match registry.announce(topic, addr, now, expires_at, ctx.limits.size) {
        Ok(()) => {}
        Err(err @ RegistryError::TopicFull) => {
            return Response::error(ErrorCode::TopicFull, err.to_string());
        }
        Err(err @ RegistryError::TooManyTopics) => {
            return Response::error(ErrorCode::TooManyTopics, err.to_string());
        }
    }
    let peers: Vec<Peer> = topic
        .map(|topic| {
            registry
                .lookup(&topic, now)
                .into_iter()
                .filter(|peer| peer.addr.id != self_id)
                .collect()
        })
        .unwrap_or_default();
    Response::Announced { ttl_secs, peers }
}

fn handle_lookup(ctx: &Ctx, lookup: Lookup, now: u64) -> Response {
    if let Err(resp) = check_fresh(lookup.body.ts, now, ctx.limits.max_skew_secs) {
        return resp;
    }
    if let Err(err) = lookup.verify() {
        return Response::error(ErrorCode::BadSignature, err.to_string());
    }
    let peers = lock(ctx).lookup(&lookup.body.topic, now);
    Response::Peers { peers }
}

fn check_fresh(ts: u64, now: u64, max_skew_secs: u64) -> Result<(), Response> {
    if now.abs_diff(ts) > max_skew_secs {
        return Err(Response::error(
            ErrorCode::StaleTimestamp,
            format!("timestamp {ts} is more than {max_skew_secs}s away from server time {now}"),
        ));
    }
    Ok(())
}

fn lock(ctx: &Ctx) -> std::sync::MutexGuard<'_, Registry> {
    ctx.registry()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::{EndpointId, SecretKey};
    use iroh_lighthouse_protocol::Topic;
    use iroh_lighthouse_protocol::{AnnounceBody, LookupBody, Peer};

    use super::*;

    const LIMITS: Limits = Limits {
        min_ttl_secs: 10,
        max_ttl_secs: 3600,
        max_skew_secs: 300,
        size: SizeLimits {
            max_peers_per_topic: 2,
            max_topics: 2,
        },
    };
    const NOW: u64 = 1_757_850_000;

    fn ctx() -> Ctx {
        Ctx::new(Registry::default(), LIMITS)
    }

    struct Node {
        key: SecretKey,
        addr: EndpointAddr,
    }

    fn node(port: u16) -> Node {
        let key = SecretKey::generate();
        let addr =
            EndpointAddr::new(key.public()).with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)));
        Node { key, addr }
    }

    fn announce(node: &Node, topic: Option<&Topic>, ttl: u32, ts: u64) -> Request {
        Request::Announce(
            AnnounceBody {
                topic: topic.map(Topic::id),
                addr: node.addr.clone(),
                ttl_secs: ttl,
                ts,
            }
            .sign(&node.key, topic),
        )
    }

    fn lookup(topic: &Topic, ts: u64) -> Request {
        Request::Lookup(
            LookupBody {
                topic: topic.id(),
                ts,
            }
            .sign(topic),
        )
    }

    fn ids(peers: &[Peer]) -> Vec<EndpointId> {
        peers.iter().map(|p| p.addr.id).collect()
    }

    fn error_code(resp: &Response) -> ErrorCode {
        match resp {
            Response::Error(e) => e.code,
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn first_announce_is_accepted_with_echoed_ttl_and_no_peers() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let resp = handle_at(&ctx, announce(&node(1), Some(&topic), 3600, NOW), NOW);
        assert_eq!(
            resp,
            Response::Announced {
                ttl_secs: 3600,
                peers: vec![]
            }
        );
    }

    #[test]
    fn announce_returns_other_members_but_not_the_caller() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let (a, b) = (node(1), node(2));
        handle_at(&ctx, announce(&a, Some(&topic), 3600, NOW), NOW);
        match handle_at(&ctx, announce(&b, Some(&topic), 3600, NOW), NOW) {
            Response::Announced { peers, .. } => assert_eq!(ids(&peers), vec![a.addr.id]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn lookup_returns_every_member() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let (a, b) = (node(1), node(2));
        handle_at(&ctx, announce(&a, Some(&topic), 3600, NOW), NOW);
        handle_at(&ctx, announce(&b, Some(&topic), 3600, NOW + 1), NOW + 1);
        match handle_at(&ctx, lookup(&topic, NOW + 2), NOW + 2) {
            Response::Peers { peers } => assert_eq!(ids(&peers), vec![b.addr.id, a.addr.id]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn lookup_with_a_different_secret_sees_nothing() {
        let ctx = ctx();
        let topic = Topic::with_secret("t", b"a");
        handle_at(&ctx, announce(&node(1), Some(&topic), 3600, NOW), NOW);
        let other = Topic::with_secret("t", b"b");
        assert_eq!(
            handle_at(&ctx, lookup(&other, NOW), NOW),
            Response::Peers { peers: vec![] }
        );
    }

    #[test]
    fn stale_timestamps_are_rejected_in_both_directions() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let past = handle_at(&ctx, announce(&node(1), Some(&topic), 60, NOW - 301), NOW);
        assert_eq!(error_code(&past), ErrorCode::StaleTimestamp);
        let future = handle_at(&ctx, lookup(&topic, NOW + 301), NOW);
        assert_eq!(error_code(&future), ErrorCode::StaleTimestamp);
        let edge = handle_at(&ctx, announce(&node(1), Some(&topic), 60, NOW - 300), NOW);
        assert!(
            matches!(edge, Response::Announced { .. }),
            "skew is inclusive"
        );
    }

    #[test]
    fn bad_node_signature_is_rejected() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let victim = node(1);
        let attacker = node(2);
        let forged = Request::Announce(
            AnnounceBody {
                topic: Some(topic.id()),
                addr: victim.addr.clone(),
                ttl_secs: 60,
                ts: NOW,
            }
            .sign(&attacker.key, Some(&topic)),
        );
        assert_eq!(
            error_code(&handle_at(&ctx, forged, NOW)),
            ErrorCode::BadSignature
        );
        assert_eq!(
            handle_at(&ctx, lookup(&topic, NOW), NOW),
            Response::Peers { peers: vec![] }
        );
    }

    #[test]
    fn bad_topic_signature_is_rejected() {
        let ctx = ctx();
        let topic = Topic::with_secret("t", b"right");
        let wrong = Topic::with_secret("t", b"wrong");
        let n = node(1);
        let forged = Request::Announce(
            AnnounceBody {
                topic: Some(topic.id()),
                addr: n.addr.clone(),
                ttl_secs: 60,
                ts: NOW,
            }
            .sign(&n.key, Some(&wrong)),
        );
        assert_eq!(
            error_code(&handle_at(&ctx, forged, NOW)),
            ErrorCode::BadSignature
        );

        let forged_lookup = Request::Lookup(
            LookupBody {
                topic: topic.id(),
                ts: NOW,
            }
            .sign(&wrong),
        );
        assert_eq!(
            error_code(&handle_at(&ctx, forged_lookup, NOW)),
            ErrorCode::BadSignature
        );
    }

    #[test]
    fn ttl_is_clamped_and_expiry_is_relative_to_the_signed_timestamp() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let (a, b) = (node(1), node(2));

        let too_short = handle_at(&ctx, announce(&a, Some(&topic), 5, NOW), NOW);
        assert!(matches!(
            too_short,
            Response::Announced { ttl_secs: 10, .. }
        ));

        let too_long = handle_at(&ctx, announce(&a, Some(&topic), 10_000, NOW - 100), NOW);
        assert!(matches!(
            too_long,
            Response::Announced { ttl_secs: 3600, .. }
        ));

        match handle_at(&ctx, announce(&b, Some(&topic), 60, NOW), NOW) {
            Response::Announced { peers, .. } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].expires_in_secs, 3500, "(NOW - 100) + 3600 - NOW");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn zero_ttl_unregisters() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let a = node(1);
        handle_at(&ctx, announce(&a, Some(&topic), 3600, NOW), NOW);
        let resp = handle_at(&ctx, announce(&a, Some(&topic), 0, NOW + 1), NOW + 1);
        assert_eq!(
            resp,
            Response::Announced {
                ttl_secs: 0,
                peers: vec![]
            }
        );
        assert_eq!(
            handle_at(&ctx, lookup(&topic, NOW + 1), NOW + 1),
            Response::Peers { peers: vec![] }
        );
    }

    #[test]
    fn size_limits_surface_as_errors() {
        let ctx = ctx();
        let (t1, t2, t3) = (Topic::new("1"), Topic::new("2"), Topic::new("3"));
        handle_at(&ctx, announce(&node(1), Some(&t1), 60, NOW), NOW);
        handle_at(&ctx, announce(&node(2), Some(&t1), 60, NOW), NOW);
        let full = handle_at(&ctx, announce(&node(3), Some(&t1), 60, NOW), NOW);
        assert_eq!(error_code(&full), ErrorCode::TopicFull);

        handle_at(&ctx, announce(&node(4), Some(&t2), 60, NOW), NOW);
        let too_many = handle_at(&ctx, announce(&node(5), Some(&t3), 60, NOW), NOW);
        assert_eq!(error_code(&too_many), ErrorCode::TooManyTopics);
    }

    #[test]
    fn directory_publish_and_resolve() {
        let ctx = ctx();
        let topic = Topic::new("t");
        let (member, published) = (node(1), node(2));
        handle_at(&ctx, announce(&member, Some(&topic), 60, NOW), NOW);
        let resp = handle_at(&ctx, announce(&published, None, 60, NOW), NOW);
        assert_eq!(
            resp,
            Response::Announced {
                ttl_secs: 60,
                peers: vec![]
            }
        );

        match handle_at(
            &ctx,
            Request::Resolve {
                id: published.addr.id,
            },
            NOW + 10,
        ) {
            Response::Resolved { peer } => {
                assert_eq!(peer.addr, published.addr);
                assert_eq!(peer.expires_in_secs, 50);
            }
            other => panic!("{other:?}"),
        }
        let hidden = handle_at(&ctx, Request::Resolve { id: member.addr.id }, NOW);
        assert_eq!(error_code(&hidden), ErrorCode::NotFound);
        let unknown = handle_at(
            &ctx,
            Request::Resolve {
                id: node(9).addr.id,
            },
            NOW,
        );
        assert_eq!(error_code(&unknown), ErrorCode::NotFound);
    }

    #[test]
    fn info_reports_limits_and_lighthouse_address() {
        let ctx = ctx();
        let me = node(7).addr;
        *ctx.lighthouse.write().unwrap() = Some(me.clone());
        assert_eq!(
            handle_at(&ctx, Request::Info, NOW),
            Response::Info(Info {
                version: env!("CARGO_PKG_VERSION").to_string(),
                lighthouse: Some(me),
                min_ttl_secs: 10,
                max_ttl_secs: 3600,
                max_peers_per_topic: 2,
            })
        );
    }
}
