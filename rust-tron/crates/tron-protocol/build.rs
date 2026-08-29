use std::{env, fs, path::PathBuf};

use prost::Message;
use prost_types::FileDescriptorSet;

const PROTOS: &[&str] = &[
    "proto/api/api.proto",
    "proto/api/zksnark.proto",
    "proto/core/Discover.proto",
    "proto/core/Tron.proto",
    "proto/core/TronInventoryItems.proto",
    "proto/core/contract/account_contract.proto",
    "proto/core/contract/asset_issue_contract.proto",
    "proto/core/contract/balance_contract.proto",
    "proto/core/contract/common.proto",
    "proto/core/contract/exchange_contract.proto",
    "proto/core/contract/market_contract.proto",
    "proto/core/contract/proposal_contract.proto",
    "proto/core/contract/shield_contract.proto",
    "proto/core/contract/smart_contract.proto",
    "proto/core/contract/storage_contract.proto",
    "proto/core/contract/vote_asset_contract.proto",
    "proto/core/contract/witness_contract.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for path in PROTOS {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed=proto/google/protobuf/any.proto");
    println!("cargo:rerun-if-changed=descriptors/protocol.v1.pb");
    // protoc-bin-vendored 3.1.0 supplies protoc; prost/prost-build 0.13.5 and
    // tonic/tonic-build 0.12.3 are pinned by the workspace manifests and lockfile.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    let generated_descriptor = output.join("protocol.v1.pb");
    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc);
    // Every generated protobuf map uses BTreeMap. This makes encoding messages
    // constructed in Rust independent of map insertion order.
    prost.btree_map(["."]);
    // file_descriptor_set_path includes imports and source information. Source
    // information is removed only during normalization below.
    prost.file_descriptor_set_path(&generated_descriptor);

    // Generate messages (including the vendored google.protobuf.Any) and both
    // client and server modules for all seven services declared by the inputs.
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_well_known_types(true)
        .compile_protos_with_config(prost, PROTOS, &["proto"])?;

    let bytes = fs::read(&generated_descriptor)?;
    let mut descriptor = FileDescriptorSet::decode(bytes.as_slice())?;
    descriptor.file.sort_by(|left, right| left.name.cmp(&right.name));
    for file in &mut descriptor.file {
        file.source_code_info = None;
    }
    let normalized = descriptor.encode_to_vec();
    fs::write(&generated_descriptor, &normalized)?;

    let canonical = fs::read("descriptors/protocol.v1.pb")?;
    if normalized != canonical {
        return Err("generated normalized descriptor differs from descriptors/protocol.v1.pb".into());
    }

    Ok(())
}
