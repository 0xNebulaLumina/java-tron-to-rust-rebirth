//! Canonical TRON protobuf and gRPC types generated from the pinned schemas.
pub mod extensions;
pub mod ordered_map;
pub mod wire;

/// Types and services in the canonical `protocol` protobuf package.
pub mod protocol {
    tonic::include_proto!("protocol");
}

/// Vendored well-known types used by the canonical schemas.
pub mod google {
    pub mod protobuf {
        tonic::include_proto!("google.protobuf");
    }
}

/// Normalized descriptor set for the exact schemas compiled into this crate.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/protocol.v1.pb"));

/// Canonical prefix used by protobuf `Any` for generated TRON messages.
pub const TYPE_URL_PREFIX: &str = extensions::TYPE_URL_PREFIX;
