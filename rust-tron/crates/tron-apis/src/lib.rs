//! Generated canonical gRPC API surface.
//!
//! Runtime API implementations remain owned by C022-C024 and C026. This crate only gives callers
//! stable names for the generated clients, server traits, and protobuf messages.

pub use tron_protocol::protocol::*;

pub mod wallet {
    pub use tron_protocol::protocol::{wallet_client, wallet_server};
}

pub mod solidity {
    pub use tron_protocol::protocol::{wallet_solidity_client, wallet_solidity_server};
}

pub mod extension {
    pub use tron_protocol::protocol::{wallet_extension_client, wallet_extension_server};
}

pub mod database {
    pub use tron_protocol::protocol::{database_client, database_server};
}

pub mod monitor {
    pub use tron_protocol::protocol::{monitor_client, monitor_server};
}

pub mod network {
    pub use tron_protocol::protocol::{network_client, network_server};
}

pub mod zksnark {
    pub use tron_protocol::protocol::{tron_zksnark_client, tron_zksnark_server};
}
