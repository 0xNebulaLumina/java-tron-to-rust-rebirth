use std::collections::{BTreeMap, BTreeSet, VecDeque};

use prost::Message;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorSet};
use tron_protocol::{
    google::protobuf::Any,
    ordered_map::{OrderedMapEncoder, OrderedMapError, OrderedMapLimits},
    protocol::{
        block_header, inventory, pbft_message, r#return, transaction, Account, Block, BlockHeader,
        Inventory, PbftMessage, Return, SpendDescription, Transaction,
    },
    wire::{encode_constructed, PreservedMessage},
    FILE_DESCRIPTOR_SET,
};

const LEGACY_ENUMS: [&str; 21] = [
    "core/contract/common.proto:ResourceCode",
    "core/contract/smart_contract.proto:SmartContract.ABI.Entry.EntryType",
    "core/contract/smart_contract.proto:SmartContract.ABI.Entry.StateMutabilityType",
    "core/Tron.proto:AccountType",
    "core/Tron.proto:ReasonCode",
    "core/Tron.proto:Proposal.State",
    "core/Tron.proto:MarketOrder.State",
    "core/Tron.proto:Permission.PermissionType",
    "core/Tron.proto:Transaction.Contract.ContractType",
    "core/Tron.proto:Transaction.Result.code",
    "core/Tron.proto:Transaction.Result.contractResult",
    "core/Tron.proto:TransactionInfo.code",
    "core/Tron.proto:BlockInventory.Type",
    "core/Tron.proto:Inventory.InventoryType",
    "core/Tron.proto:Items.ItemType",
    "core/Tron.proto:PBFTMessage.MsgType",
    "core/Tron.proto:PBFTMessage.DataType",
    "api/api.proto:Return.response_code",
    "api/api.proto:TransactionSignWeight.Result.response_code",
    "api/api.proto:TransactionApprovedList.Result.response_code",
    "api/zksnark.proto:ZksnarkResponse.Code",
];

#[test]
fn generated_service_surface_is_exact() {
    let descriptor = descriptor();
    let actual: BTreeMap<_, _> = descriptor
        .file
        .iter()
        .flat_map(|file| {
            file.service.iter().map(|service| {
                (
                    service.name.as_deref().unwrap(),
                    service.method.len(),
                )
            })
        })
        .collect();
    let expected = BTreeMap::from([
        ("Database", 4),
        ("Monitor", 1),
        ("Network", 0),
        ("TronZksnark", 1),
        ("Wallet", 147),
        ("WalletExtension", 4),
        ("WalletSolidity", 47),
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn enum_zero_rule_matches_java_allowlist() {
    let descriptor = descriptor();
    let legacy: BTreeSet<_> = LEGACY_ENUMS.into_iter().collect();
    let mut live_legacy = BTreeSet::new();
    let mut violations = Vec::new();

    for file in &descriptor.file {
        let Some(file_name) = file.name.as_deref() else {
            continue;
        };
        if file_name.starts_with("google/") || file_name.starts_with("grpc/") {
            continue;
        }
        for (name, enumeration) in enums(file) {
            let identifier = format!("{file_name}:{name}");
            if legacy.contains(identifier.as_str()) {
                live_legacy.insert(identifier);
                continue;
            }
            if let Some(zero) = enumeration.value.iter().find(|value| value.number == Some(0)) {
                let zero_name = zero.name.as_deref().unwrap_or_default();
                if !zero_name.starts_with("UNKNOWN_") {
                    violations.push(format!("{identifier}={zero_name}"));
                }
            }
        }
    }

    assert!(violations.is_empty(), "enum-zero violations: {violations:?}");
    assert_eq!(live_legacy, legacy.into_iter().map(str::to_owned).collect());
}

#[test]
fn high_risk_wire_shapes_remain_present() {
    let descriptor = descriptor();
    let transaction = message(&descriptor, "protocol.Transaction");
    assert_field(transaction, "raw_data", 1, ".protocol.Transaction.raw", false, false);

    let contract = nested_message(transaction, "Contract");
    assert_field(contract, "type", 1, ".protocol.Transaction.Contract.ContractType", false, false);
    assert_field(contract, "parameter", 2, ".google.protobuf.Any", false, false);
    assert_field(contract, "ContractName", 4, "", false, false);
    assert_field(contract, "Permission_id", 5, "", false, false);

    let account = message(&descriptor, "protocol.Account");
    let asset = account.field.iter().find(|field| field.name.as_deref() == Some("asset")).unwrap();
    assert_eq!(asset.number, Some(6));
    let map_entry = message(&descriptor, asset.type_name.as_deref().unwrap().trim_start_matches('.'));
    assert_eq!(map_entry.options.as_ref().and_then(|options| options.map_entry), Some(true));

    let ivk = message(&descriptor, "protocol.IvkDecryptTRC20Parameters");
    let events = ivk.field.iter().find(|field| field.name.as_deref() == Some("events")).unwrap();
    assert_eq!(events.number, Some(7));
    assert_eq!(events.options.as_ref().and_then(|options| options.deprecated), Some(true));

    assert!(message_exists(&descriptor, "protocol.TransactionExtention"));
    assert!(message_exists(&descriptor, "protocol.BlockExtention"));
}

fn descriptor() -> FileDescriptorSet {
    FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap()
}

fn enums(file: &prost_types::FileDescriptorProto) -> Vec<(String, &EnumDescriptorProto)> {
    let mut output = Vec::new();
    for enumeration in &file.enum_type {
        output.push((enumeration.name.clone().unwrap(), enumeration));
    }
    let mut queue: VecDeque<_> = file
        .message_type
        .iter()
        .map(|message| (message.name.clone().unwrap(), message))
        .collect();
    while let Some((name, message)) = queue.pop_front() {
        for enumeration in &message.enum_type {
            output.push((format!("{name}.{}", enumeration.name.as_deref().unwrap()), enumeration));
        }
        for nested in &message.nested_type {
            queue.push_back((format!("{name}.{}", nested.name.as_deref().unwrap()), nested));
        }
    }
    output
}

fn message<'a>(descriptor: &'a FileDescriptorSet, full_name: &str) -> &'a DescriptorProto {
    let (package, relative) = full_name.split_once('.').unwrap();
    let mut parts = relative.split('.');
    let first = parts.next().unwrap();
    let file = descriptor.file.iter().find(|file| file.package.as_deref() == Some(package) && file.message_type.iter().any(|message| message.name.as_deref() == Some(first))).unwrap();
    let mut current = file.message_type.iter().find(|message| message.name.as_deref() == Some(first)).unwrap();
    for part in parts {
        current = nested_message(current, part);
    }
    current
}

fn nested_message<'a>(message: &'a DescriptorProto, name: &str) -> &'a DescriptorProto {
    message.nested_type.iter().find(|nested| nested.name.as_deref() == Some(name)).unwrap()
}

fn message_exists(descriptor: &FileDescriptorSet, name: &str) -> bool {
    std::panic::catch_unwind(|| message(descriptor, name)).is_ok()
}

fn assert_field(message: &DescriptorProto, name: &str, tag: i32, type_name: &str, repeated: bool, deprecated: bool) {
    let field = message.field.iter().find(|field| field.name.as_deref() == Some(name)).unwrap();
    assert_eq!(field.number, Some(tag));
    assert_eq!(field.type_name.as_deref().unwrap_or_default(), type_name);
    assert_eq!(field.label == Some(prost_types::field_descriptor_proto::Label::Repeated as i32), repeated);
    assert_eq!(field.options.as_ref().and_then(|options| options.deprecated).unwrap_or(false), deprecated);
}


fn assert_preserved<M>(bytes: &[u8], expected_size: usize)
where
    M: Message + Default,
{
    assert_eq!(bytes.len(), expected_size);
    let preserved = PreservedMessage::<M>::decode(bytes).unwrap();
    assert_eq!(preserved.original_bytes(), bytes);
    for _ in 0..3 {
        assert_eq!(preserved.emit_original(), bytes);
    }
}

fn assert_malformed<M>(bytes: &[u8], expected_size: usize)
where
    M: Message + Default,
{
    assert_eq!(bytes.len(), expected_size);
    assert!(PreservedMessage::<M>::decode(bytes).is_err());
}

#[test]
fn all_fixture_families_cross_generated_raw_wire_boundary() {
    assert_preserved::<Transaction>(include_bytes!("fixtures/protocol/transaction.bin"), 36);
    assert_preserved::<Transaction>(include_bytes!("fixtures/protocol/transaction-unknown.bin"), 40);
    assert_malformed::<Transaction>(include_bytes!("fixtures/protocol/transaction-malformed.bin"), 41);

    assert_preserved::<Block>(include_bytes!("fixtures/protocol/block.bin"), 41);
    assert_preserved::<Block>(include_bytes!("fixtures/protocol/block-unknown.bin"), 45);
    assert_malformed::<Block>(include_bytes!("fixtures/protocol/block-malformed.bin"), 46);

    assert_preserved::<Account>(include_bytes!("fixtures/protocol/account.bin"), 30);
    assert_preserved::<Account>(include_bytes!("fixtures/protocol/account-unknown.bin"), 34);
    assert_malformed::<Account>(include_bytes!("fixtures/protocol/account-malformed.bin"), 35);

    assert_preserved::<SpendDescription>(include_bytes!("fixtures/protocol/shielded.bin"), 45);
    assert_preserved::<SpendDescription>(include_bytes!("fixtures/protocol/shielded-unknown.bin"), 49);
    assert_malformed::<SpendDescription>(include_bytes!("fixtures/protocol/shielded-malformed.bin"), 50);

    assert_preserved::<PbftMessage>(include_bytes!("fixtures/protocol/pbft.bin"), 34);
    assert_preserved::<PbftMessage>(include_bytes!("fixtures/protocol/pbft-unknown.bin"), 38);
    assert_malformed::<PbftMessage>(include_bytes!("fixtures/protocol/pbft-malformed.bin"), 39);

    assert_preserved::<Inventory>(include_bytes!("fixtures/protocol/inventory.bin"), 28);
    assert_preserved::<Inventory>(include_bytes!("fixtures/protocol/inventory-unknown.bin"), 32);
    assert_malformed::<Inventory>(include_bytes!("fixtures/protocol/inventory-malformed.bin"), 33);

    assert_preserved::<Return>(include_bytes!("fixtures/protocol/api-return.bin"), 25);
    assert_preserved::<Return>(include_bytes!("fixtures/protocol/api-return-unknown.bin"), 29);
    assert_malformed::<Return>(include_bytes!("fixtures/protocol/api-return-malformed.bin"), 30);
}

#[test]
fn canonical_fixtures_decode_known_values_and_match_rust_construction() {
    let transaction = Transaction::decode(include_bytes!("fixtures/protocol/transaction.bin").as_slice()).unwrap();
    let raw = transaction.raw_data.as_ref().unwrap();
    assert_eq!((raw.ref_block_bytes.as_slice(), raw.expiration, raw.timestamp, raw.fee_limit), (&[1, 2][..], 1_700_000_060_000, 1_700_000_000_000, 1_000_000));
    let constructed = Transaction {
        raw_data: Some(transaction::Raw { ref_block_bytes: vec![1, 2], expiration: 1_700_000_060_000, timestamp: 1_700_000_000_000, fee_limit: 1_000_000, ..Default::default() }),
        signature: vec![b"signature".to_vec()],
        ..Default::default()
    };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/transaction.bin"));

    let block = Block::decode(include_bytes!("fixtures/protocol/block.bin").as_slice()).unwrap();
    let header = block.block_header.as_ref().unwrap();
    let block_raw = header.raw_data.as_ref().unwrap();
    assert_eq!((block_raw.timestamp, block_raw.number, block_raw.witness_address.as_slice(), block_raw.version), (1_700_000_000_000, 42, b"witness".as_slice(), 31));
    let constructed = Block { block_header: Some(BlockHeader { raw_data: Some(block_header::Raw { timestamp: 1_700_000_000_000, number: 42, witness_address: b"witness".to_vec(), version: 31, ..Default::default() }), witness_signature: b"block-signature".to_vec() }), ..Default::default() };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/block.bin"));

    let account = Account::decode(include_bytes!("fixtures/protocol/account.bin").as_slice()).unwrap();
    assert_eq!((account.account_name.as_slice(), account.address.as_slice(), account.balance), (b"alice".as_slice(), b"A123".as_slice(), 1_000));
    assert_eq!(account.asset, BTreeMap::from([("A".to_owned(), 1), ("Z".to_owned(), 9)]));
    let constructed = Account { account_name: b"alice".to_vec(), address: b"A123".to_vec(), balance: 1_000, asset: BTreeMap::from([("A".to_owned(), 1), ("Z".to_owned(), 9)]), ..Default::default() };
    assert_eq!(Account::decode(encode_constructed(&constructed).as_slice()).unwrap(), account);

    let spend = SpendDescription::decode(include_bytes!("fixtures/protocol/shielded.bin").as_slice()).unwrap();
    assert_eq!((spend.value_commitment.as_slice(), spend.anchor.as_slice(), spend.nullifier.as_slice(), spend.rk.as_slice(), spend.zkproof.as_slice(), spend.spend_authority_signature.as_slice()), (b"vc".as_slice(), b"anchor".as_slice(), b"nullifier".as_slice(), b"rk".as_slice(), b"proof".as_slice(), b"signature".as_slice()));
    let constructed = SpendDescription { value_commitment: b"vc".to_vec(), anchor: b"anchor".to_vec(), nullifier: b"nullifier".to_vec(), rk: b"rk".to_vec(), zkproof: b"proof".to_vec(), spend_authority_signature: b"signature".to_vec() };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/shielded.bin"));

    let pbft = PbftMessage::decode(include_bytes!("fixtures/protocol/pbft.bin").as_slice()).unwrap();
    let pbft_raw = pbft.raw_data.as_ref().unwrap();
    assert_eq!((pbft_raw.msg_type, pbft_raw.data_type, pbft_raw.view_n, pbft_raw.epoch, pbft_raw.data.as_slice()), (pbft_message::MsgType::Commit as i32, pbft_message::DataType::Block as i32, 7, 42, b"block-id".as_slice()));
    let constructed = PbftMessage { raw_data: Some(pbft_message::Raw { msg_type: pbft_message::MsgType::Commit as i32, data_type: pbft_message::DataType::Block as i32, view_n: 7, epoch: 42, data: b"block-id".to_vec() }), signature: b"pbft-signature".to_vec() };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/pbft.bin"));

    let inventory = Inventory::decode(include_bytes!("fixtures/protocol/inventory.bin").as_slice()).unwrap();
    assert_eq!(inventory.r#type, inventory::InventoryType::Block as i32);
    assert_eq!(inventory.ids, [b"transaction-id".to_vec(), b"block-id".to_vec()]);
    let constructed = Inventory { r#type: inventory::InventoryType::Block as i32, ids: vec![b"transaction-id".to_vec(), b"block-id".to_vec()] };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/inventory.bin"));

    let response = Return::decode(include_bytes!("fixtures/protocol/api-return.bin").as_slice()).unwrap();
    assert!(response.result);
    assert_eq!((response.code, response.message.as_slice()), (r#return::ResponseCode::BandwithError as i32, b"bandwidth exhausted".as_slice()));
    let constructed = Return { result: true, code: r#return::ResponseCode::BandwithError as i32, message: b"bandwidth exhausted".to_vec() };
    assert_eq!(encode_constructed(&constructed), include_bytes!("fixtures/protocol/api-return.bin"));
}

#[test]
fn raw_preservation_keeps_map_order_presence_and_any_bytes() {
    let account = PreservedMessage::<Account>::decode(include_bytes!("fixtures/protocol/account.bin")).unwrap();
    let reversed = PreservedMessage::<Account>::decode(include_bytes!("fixtures/protocol/account-map-reversed.bin")).unwrap();
    assert_eq!(account.original_bytes().len(), 30);
    assert_eq!(reversed.original_bytes().len(), 30);
    assert_eq!(account.message(), reversed.message());
    assert_ne!(account.original_bytes(), reversed.original_bytes());
    assert_eq!(account.emit_original().as_slice(), include_bytes!("fixtures/protocol/account.bin"));
    assert_eq!(reversed.emit_original().as_slice(), include_bytes!("fixtures/protocol/account-map-reversed.bin"));

    let absent = PreservedMessage::<Transaction>::decode(include_bytes!("fixtures/protocol/presence-absent.bin")).unwrap();
    let explicit_default = PreservedMessage::<Transaction>::decode(include_bytes!("fixtures/protocol/presence-default.bin")).unwrap();
    assert_eq!(absent.original_bytes().len(), 2);
    assert_eq!(explicit_default.original_bytes().len(), 4);
    assert_eq!(absent.message(), explicit_default.message());
    assert_ne!(absent.emit_original(), explicit_default.emit_original());

    let any_bytes = include_bytes!("fixtures/extensions/example_any.bin");
    let any = PreservedMessage::<Any>::decode(any_bytes).unwrap();
    assert_eq!(any_bytes.len(), 97);
    assert_eq!(any.message().type_url, "type.googleapis.com/org.tron.example.actuator.ExampleContract");
    assert!(!any.message().value.is_empty());
    assert_eq!(any.emit_original().as_slice(), any_bytes);
}
#[test]
fn ordered_map_encoder_matches_java_in_both_insertion_orders_for_every_map_field() {
    let rows = map_rows();
    assert_eq!(rows.len(), 15);

    for (field, java_forward, java_reverse) in rows {
        let rust_forward = encode_map_row(&field, false);
        let rust_reverse = encode_map_row(&field, true);
        assert_ne!(java_forward, java_reverse, "{field} must exercise insertion order");
        assert_eq!(rust_forward, java_forward, "{field} forward Rust bytes differ from Java");
        assert_eq!(rust_reverse, java_reverse, "{field} reverse Rust bytes differ from Java");
    }
}

#[test]
fn ordered_map_encoder_enforces_entry_and_byte_bounds_transactionally() {
    let mut entries = OrderedMapEncoder::new(OrderedMapLimits::new(1, usize::MAX));
    entries.push_string_i64(6, "A", 1).unwrap();
    let retained = entries.as_bytes().to_vec();
    assert_eq!(
        entries.push_string_i64(6, "Z", 9).unwrap_err(),
        OrderedMapError::EntryLimit { max_entries: 1 }
    );
    assert_eq!(entries.entry_count(), 1);
    assert_eq!(entries.as_bytes(), retained);

    let mut bytes = OrderedMapEncoder::new(OrderedMapLimits::new(2, 6));
    bytes.push_i64_i64(3, 1, 1).unwrap();
    let retained = bytes.as_bytes().to_vec();
    assert_eq!(
        bytes.push_i64_i64(3, 9, 9).unwrap_err(),
        OrderedMapError::EncodedLengthLimit { max_encoded_len: 6 }
    );
    assert_eq!(bytes.entry_count(), 1);
    assert_eq!(bytes.as_bytes(), retained);
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn map_rows() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let manifest = include_str!("../../../../docs/oracles/protocol-fixtures.v1.json");
    let section = manifest.split("\"java_map_serialization\"").nth(1).unwrap();
    section
        .split("\"field\": \"")
        .skip(1)
        .map(|row| {
            let field = row.split('"').next().unwrap().to_owned();
            let forward = row
                .split("\"forward_hex\": \"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let reverse = row
                .split("\"reverse_hex\": \"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            (field, hex_bytes(forward), hex_bytes(reverse))
        })
        .collect()
}

fn encode_map_row(field: &str, reverse: bool) -> Vec<u8> {
    let mut encoder = OrderedMapEncoder::new(OrderedMapLimits::new(2, 64));
    match field {
        "protocol.Account.asset" => push_string_i64_pair(&mut encoder, 6, reverse),
        "protocol.Account.assetV2" => push_string_i64_pair(&mut encoder, 56, reverse),
        "protocol.Account.free_asset_net_usage" => push_string_i64_pair(&mut encoder, 20, reverse),
        "protocol.Account.free_asset_net_usageV2" => push_string_i64_pair(&mut encoder, 59, reverse),
        "protocol.Account.latest_asset_operation_time" => push_string_i64_pair(&mut encoder, 18, reverse),
        "protocol.Account.latest_asset_operation_timeV2" => push_string_i64_pair(&mut encoder, 58, reverse),
        "protocol.AccountNetMessage.assetNetLimit" => push_string_i64_pair(&mut encoder, 6, reverse),
        "protocol.AccountNetMessage.assetNetUsed" => push_string_i64_pair(&mut encoder, 5, reverse),
        "protocol.AccountResourceMessage.assetNetLimit" => push_string_i64_pair(&mut encoder, 6, reverse),
        "protocol.AccountResourceMessage.assetNetUsed" => push_string_i64_pair(&mut encoder, 5, reverse),
        "protocol.NodeInfo.cheatWitnessInfoMap" => push_string_string_pair(&mut encoder, 11, reverse),
        "protocol.Proposal.parameters" => push_i64_i64_pair(&mut encoder, 3, reverse),
        "protocol.ProposalCreateContract.parameters" => push_i64_i64_pair(&mut encoder, 2, reverse),
        "protocol.Transaction.Result.cancel_unfreezeV2_amount" => {
            push_string_i64_pair(&mut encoder, 28, reverse)
        }
        "protocol.TransactionInfo.cancel_unfreezeV2_amount" => {
            push_string_i64_pair(&mut encoder, 29, reverse)
        }
        unknown => panic!("unhandled Java map oracle field: {unknown}"),
    }
    encoder.finish()
}

fn push_string_i64_pair(encoder: &mut OrderedMapEncoder, field: u32, reverse: bool) {
    let pairs = if reverse { [("Z", 9), ("A", 1)] } else { [("A", 1), ("Z", 9)] };
    for (key, value) in pairs {
        encoder.push_string_i64(field, key, value).unwrap();
    }
}

fn push_string_string_pair(encoder: &mut OrderedMapEncoder, field: u32, reverse: bool) {
    let pairs = if reverse { [("Z", "Z"), ("A", "A")] } else { [("A", "A"), ("Z", "Z")] };
    for (key, value) in pairs {
        encoder.push_string_string(field, key, value).unwrap();
    }
}

fn push_i64_i64_pair(encoder: &mut OrderedMapEncoder, field: u32, reverse: bool) {
    let pairs = if reverse { [(9, 9), (1, 1)] } else { [(1, 1), (9, 9)] };
    for (key, value) in pairs {
        encoder.push_i64_i64(field, key, value).unwrap();
    }
}
