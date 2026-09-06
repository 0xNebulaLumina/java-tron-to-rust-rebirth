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
