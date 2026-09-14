//! Topic rendezvous and address lookup for iroh nodes.
//!
//! A lighthouse is a server reachable by URL (HTTPS) or natively over iroh.
//! Nodes announce themselves on a topic with a TTL and receive the other nodes
//! on that topic in the same round trip.

pub mod client;
pub mod lookup;
pub mod protocol;
pub mod session;
pub mod topic;

pub use client::{Announced, Error, Lighthouse};
pub use lookup::LighthouseLookup;
pub use session::{DEFAULT_POLL_INTERVAL, Session};
pub use topic::{Topic, TopicId};
