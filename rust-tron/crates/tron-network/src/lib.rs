//! External and application P2P ownership boundary.
//! Legacy discovery remains separate from authenticated backup datagrams.
pub mod discovery;
pub mod dns;
pub mod persistence;

pub mod compression;
pub mod connection;
pub mod framing;
pub mod handshake;
pub mod tcp;
pub mod session;
pub mod app_hello;
pub mod app_message;
pub mod peer;
pub mod stats;
pub mod handlers;
pub mod relay;
pub mod sync;
pub mod watchdog;
pub mod service;
pub mod gossip;
