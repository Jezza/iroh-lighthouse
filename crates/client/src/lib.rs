//! Topic rendezvous and address lookup for iroh nodes.
//!
//! A lighthouse is a server reachable by URL (HTTPS) or natively over iroh.
//! Nodes announce themselves on a topic with a TTL and receive the other nodes
//! on that topic in the same round trip.

pub mod client;
pub mod lookup;
pub mod session;

pub use client::{Announced, Error, Lighthouse, parse_url};
pub use iroh_lighthouse_protocol::{self as protocol, Topic, TopicId};
pub use lookup::LighthouseLookup;
pub use session::{DEFAULT_POLL_INTERVAL, Session};
