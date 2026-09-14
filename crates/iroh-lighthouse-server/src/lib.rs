//! The iroh-lighthouse server as a library, so it can be embedded and tested
//! in-process. The `iroh-lighthouse-server` binary is a thin wrapper.

pub mod cli;
pub mod handler;
pub mod http;
pub mod iroh_carrier;
pub mod registry;
pub mod server;
pub mod snapshot;

pub use server::{Config, IrohConfig, Server, ServerError, SnapshotConfig};
