use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use tron_state::store::StoreKind;
use tron_state::value::{BlockIndexValue, TransactionHistoryValue, TransactionValue, decode_witness_schedule, decode_zk_proof_value, encode_witness_schedule, zk_proof_value};
use tron_state::{StateStore, StoreEntry};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

const RUST_DISPATCH: &str = "rust_dispatch";
struct Artifact<'a> { raw: &'a str, rows: Vec<Row> }
struct Row { id:String,row_kind:String,schema:String,store:Option<String>,db_name:Option<String>,key_hex:String,value_hex:String,unknown_value_hex:Option<String>,known_field_tag:Option<u32> }
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
enum DispatchKind { StoreAccount, StoreAccountIdIndex, StoreAccountIndex, StoreAccountAsset, StoreAssetIssue, StoreAssetIssueV2, StoreBlock, StoreBlockIndex, StoreTransaction, StoreTransactionCache, StoreTransactionRet, StoreTransactionHistory, StoreRecentBlock, StoreRecentTransaction, StoreContract, StoreAbi, StoreCode, StoreContractState, StoreStorageRow, StoreWitness, StoreWitnessSchedule, StoreVotes, StoreProposal, StoreExchange, StoreExchangeV2, StoreMarketAccount, StoreMarketOrder, StoreMarketPairToPrice, StoreMarketPairPriceToOrder, StoreDelegatedResource, StoreDelegatedResourceAccountIndex, StoreDynamicProperties, StoreIncrementalMerkleTree, StoreNullifier, StoreZkProof, StoreTreeBlockIndex, StoreSectionBloom, StoreAccountTrace, StoreBalanceTrace, StoreDelegation, StorePbft, StoreRewardVi, StoreCommon, StoreCheckpoint, StoreTemporary, CapsuleAbiCapsule, CapsuleAccountCapsule, CapsuleAccountTraceCapsule, CapsuleAssetIssueCapsule, CapsuleBlockBalanceTraceCapsule, CapsuleBlockCapsule, CapsuleContractCapsule, CapsuleContractStateCapsule, CapsuleDelegatedResourceAccountIndexCapsule, CapsuleDelegatedResourceCapsule, CapsuleExchangeCapsule, CapsuleIncrementalMerkleTreeCapsule, CapsuleIncrementalMerkleVoucherCapsule, CapsuleMarketAccountOrderCapsule, CapsuleMarketOrderCapsule, CapsuleMarketOrderIdListCapsule, CapsuleMarketPriceCapsule, CapsulePbftSignCapsule, CapsulePedersenHashCapsule, CapsuleProposalCapsule, CapsuleReceiptCapsule, CapsuleTransactionCapsule, CapsuleTransactionInfoCapsule, CapsuleTransactionResultCapsule, CapsuleTransactionRetCapsule, CapsuleVotesCapsule, CapsuleWitnessCapsule, CapsuleBytesCapsule, CapsuleCodeCapsule, CapsuleProtoCapsule, CapsuleStorageRowCapsule, DynamicKey, DynamicDefault }
impl DispatchKind {
    fn parse(value:&str)->Self { match value {
            "StoreAccount" => Self::StoreAccount,
            "StoreAccountIdIndex" => Self::StoreAccountIdIndex,
            "StoreAccountIndex" => Self::StoreAccountIndex,
            "StoreAccountAsset" => Self::StoreAccountAsset,
            "StoreAssetIssue" => Self::StoreAssetIssue,
            "StoreAssetIssueV2" => Self::StoreAssetIssueV2,
            "StoreBlock" => Self::StoreBlock,
            "StoreBlockIndex" => Self::StoreBlockIndex,
            "StoreTransaction" => Self::StoreTransaction,
            "StoreTransactionCache" => Self::StoreTransactionCache,
            "StoreTransactionRet" => Self::StoreTransactionRet,
            "StoreTransactionHistory" => Self::StoreTransactionHistory,
            "StoreRecentBlock" => Self::StoreRecentBlock,
            "StoreRecentTransaction" => Self::StoreRecentTransaction,
            "StoreContract" => Self::StoreContract,
            "StoreAbi" => Self::StoreAbi,
            "StoreCode" => Self::StoreCode,
            "StoreContractState" => Self::StoreContractState,
            "StoreStorageRow" => Self::StoreStorageRow,
            "StoreWitness" => Self::StoreWitness,
            "StoreWitnessSchedule" => Self::StoreWitnessSchedule,
            "StoreVotes" => Self::StoreVotes,
            "StoreProposal" => Self::StoreProposal,
            "StoreExchange" => Self::StoreExchange,
            "StoreExchangeV2" => Self::StoreExchangeV2,
            "StoreMarketAccount" => Self::StoreMarketAccount,
            "StoreMarketOrder" => Self::StoreMarketOrder,
            "StoreMarketPairToPrice" => Self::StoreMarketPairToPrice,
            "StoreMarketPairPriceToOrder" => Self::StoreMarketPairPriceToOrder,
            "StoreDelegatedResource" => Self::StoreDelegatedResource,
            "StoreDelegatedResourceAccountIndex" => Self::StoreDelegatedResourceAccountIndex,
            "StoreDynamicProperties" => Self::StoreDynamicProperties,
            "StoreIncrementalMerkleTree" => Self::StoreIncrementalMerkleTree,
            "StoreNullifier" => Self::StoreNullifier,
            "StoreZkProof" => Self::StoreZkProof,
            "StoreTreeBlockIndex" => Self::StoreTreeBlockIndex,
            "StoreSectionBloom" => Self::StoreSectionBloom,
            "StoreAccountTrace" => Self::StoreAccountTrace,
            "StoreBalanceTrace" => Self::StoreBalanceTrace,
            "StoreDelegation" => Self::StoreDelegation,
            "StorePbft" => Self::StorePbft,
            "StoreRewardVi" => Self::StoreRewardVi,
            "StoreCommon" => Self::StoreCommon,
            "StoreCheckpoint" => Self::StoreCheckpoint,
            "StoreTemporary" => Self::StoreTemporary,
            "CapsuleAbiCapsule" => Self::CapsuleAbiCapsule,
            "CapsuleAccountCapsule" => Self::CapsuleAccountCapsule,
            "CapsuleAccountTraceCapsule" => Self::CapsuleAccountTraceCapsule,
            "CapsuleAssetIssueCapsule" => Self::CapsuleAssetIssueCapsule,
            "CapsuleBlockBalanceTraceCapsule" => Self::CapsuleBlockBalanceTraceCapsule,
            "CapsuleBlockCapsule" => Self::CapsuleBlockCapsule,
            "CapsuleContractCapsule" => Self::CapsuleContractCapsule,
            "CapsuleContractStateCapsule" => Self::CapsuleContractStateCapsule,
            "CapsuleDelegatedResourceAccountIndexCapsule" => Self::CapsuleDelegatedResourceAccountIndexCapsule,
            "CapsuleDelegatedResourceCapsule" => Self::CapsuleDelegatedResourceCapsule,
            "CapsuleExchangeCapsule" => Self::CapsuleExchangeCapsule,
            "CapsuleIncrementalMerkleTreeCapsule" => Self::CapsuleIncrementalMerkleTreeCapsule,
            "CapsuleIncrementalMerkleVoucherCapsule" => Self::CapsuleIncrementalMerkleVoucherCapsule,
            "CapsuleMarketAccountOrderCapsule" => Self::CapsuleMarketAccountOrderCapsule,
            "CapsuleMarketOrderCapsule" => Self::CapsuleMarketOrderCapsule,
            "CapsuleMarketOrderIdListCapsule" => Self::CapsuleMarketOrderIdListCapsule,
            "CapsuleMarketPriceCapsule" => Self::CapsuleMarketPriceCapsule,
            "CapsulePbftSignCapsule" => Self::CapsulePbftSignCapsule,
            "CapsulePedersenHashCapsule" => Self::CapsulePedersenHashCapsule,
            "CapsuleProposalCapsule" => Self::CapsuleProposalCapsule,
            "CapsuleReceiptCapsule" => Self::CapsuleReceiptCapsule,
            "CapsuleTransactionCapsule" => Self::CapsuleTransactionCapsule,
            "CapsuleTransactionInfoCapsule" => Self::CapsuleTransactionInfoCapsule,
            "CapsuleTransactionResultCapsule" => Self::CapsuleTransactionResultCapsule,
            "CapsuleTransactionRetCapsule" => Self::CapsuleTransactionRetCapsule,
            "CapsuleVotesCapsule" => Self::CapsuleVotesCapsule,
            "CapsuleWitnessCapsule" => Self::CapsuleWitnessCapsule,
            "CapsuleBytesCapsule" => Self::CapsuleBytesCapsule,
            "CapsuleCodeCapsule" => Self::CapsuleCodeCapsule,
            "CapsuleProtoCapsule" => Self::CapsuleProtoCapsule,
            "CapsuleStorageRowCapsule" => Self::CapsuleStorageRowCapsule,
            "DynamicKey" => Self::DynamicKey,
            "DynamicDefault" => Self::DynamicDefault,
        other=>panic!("unknown dispatch variant {other}"),
    } }
}
fn path(name:&str)->PathBuf{let nonce=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();std::env::temp_dir().join(format!("tron-state-{name}-{}-{nonce}",std::process::id()))}
fn manager()->StorageManager{StorageManager::new(OpenRequirements{identity:StorageIdentity{network:"c008".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]})}
fn hex(value:&str)->Vec<u8>{assert_eq!(value.len()%2,0);value.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()}
fn json_string(object:&str,name:&str)->Option<String>{let marker=format!("\"{name}\": ");let tail=object.split_once(&marker)?.1;if tail.starts_with("null"){return None}let quoted=tail.strip_prefix('"')?;Some(quoted.split_once('"')?.0.to_owned())}
fn json_u32(object:&str,name:&str)->Option<u32>{let marker=format!("\"{name}\": ");let tail=object.split_once(&marker)?.1;if tail.starts_with("null"){return None}Some(tail.split(|c:char|!c.is_ascii_digit()).next().unwrap().parse().unwrap())}
fn artifact(raw:&str)->Artifact<'_>{let rows=raw.split_once("\"rows\": [").unwrap().1.split_once("],\n  \"rows_sha256\"").unwrap().0.split("    {").skip(1).map(|o|Row{id:json_string(o,"id").unwrap(),row_kind:json_string(o,"row_kind").unwrap(),schema:json_string(o,"schema").unwrap(),store:json_string(o,"store"),db_name:json_string(o,"db_name"),key_hex:json_string(o,"key_hex").unwrap(),value_hex:json_string(o,"value_hex").unwrap(),unknown_value_hex:json_string(o,"unknown_value_hex"),known_field_tag:json_u32(o,"known_field_tag")}).collect();Artifact{raw,rows}}
fn dispatch_field(raw:&str,id:&str,field:&str)->String{let marker=format!("\"{id}\": {{");let object=raw.split_once(&marker).unwrap_or_else(||panic!("missing dispatch {id}")).1.split_once("    }").unwrap().0;json_string(object,field).unwrap_or_else(||panic!("missing {field} for {id}"))}

fn dispatch_proto<M:Message+Default>(row:&Row){
    let known=hex(&row.value_hex);assert!(!known.is_empty(),"{} known protobuf",row.id);assert!(row.known_field_tag.unwrap()>0,"{} known tag",row.id);
    let decoded=M::decode(known.as_slice()).unwrap_or_else(|e|panic!("{} known decode: {e}",row.id));assert_eq!(decoded.encode_to_vec(),known,"{} known fields",row.id);
    let unknown=hex(row.unknown_value_hex.as_deref().expect("protobuf unknown variant"));let mut capsule=tron_state::ProtoCapsule::<M>::decode(unknown.clone(),"C008 typed capsule").unwrap();assert_eq!(capsule.data(),unknown,"{} raw preservation",row.id);let _=capsule.instance_mut();assert_eq!(capsule.data(),known,"{} mutation",row.id);
}
fn dispatch_raw_capsule(row:&Row){assert!(!hex(&row.value_hex).is_empty(),"{} raw capsule",row.id);assert!(row.unknown_value_hex.is_none());}
fn dispatch_store(row:&Row,state:&StateStore,kind:StoreKind){
    let expected_store=format!("{kind:?}");assert_eq!(row.store.as_deref(),Some(expected_store.as_str()));assert_eq!(kind.db_name(),row.db_name.as_deref().unwrap(),"{} db",row.id);let key=hex(&row.key_hex);let value=hex(&row.value_hex);
    match kind {
        StoreKind::AccountIdIndex=>assert_eq!(tron_state::keys::account_id_key(b"MiXeD-CaSe-Id").unwrap(),key),
        StoreKind::AccountIndex=>assert_eq!(tron_state::keys::account_name_key(b"account-name"),key),
        StoreKind::BlockIndex=>{assert_eq!(tron_state::keys::block_index_key(8).as_slice(),key);if value.len()==32{assert_eq!(BlockIndexValue::decode(&value).unwrap().encode(),value)}},
        StoreKind::Transaction=>assert_eq!(TransactionValue::decode(&value).unwrap().encode(),value),
        StoreKind::TransactionRet=>assert_eq!(tron_state::keys::transaction_result_key(11).as_slice(),key),
        StoreKind::TransactionHistory=>assert_eq!(TransactionHistoryValue::decode(&value).unwrap().encode(),value),
        StoreKind::RecentBlock=>assert_eq!(tron_state::keys::recent_block_key(0x1234).as_slice(),key),
        StoreKind::WitnessSchedule=>{let decoded=decode_witness_schedule(&value).unwrap();assert_eq!(encode_witness_schedule(&decoded),value)},
        StoreKind::ZkProof=>{let valid=decode_zk_proof_value(&value).unwrap();assert_eq!(zk_proof_value(valid).as_slice(),value)},
        _=>{}
    }
    let store=state.store(kind);assert_eq!(store.entry(&key),StoreEntry::Absent,"{}",row.id);store.put(&key,&value).unwrap();assert_eq!(store.entry(&key),StoreEntry::Present(value.clone()),"{}",row.id);assert!(store.delete_present(&key).unwrap(),"{}",row.id);assert_eq!(store.entry(&key),StoreEntry::Absent,"{}",row.id);
}
fn dispatch_row(row:&Row,raw:&str,state:&StateStore){
    let case_id=dispatch_field(raw,&row.id,"case_id");assert_eq!(case_id,row.id);let function_kind=dispatch_field(raw,&row.id,"function_kind");let kind=DispatchKind::parse(&dispatch_field(raw,&row.id,"enum_variant"));
    match kind {
        DispatchKind::StoreAccount => dispatch_store(row,state,StoreKind::Account),
        DispatchKind::StoreAccountIdIndex => dispatch_store(row,state,StoreKind::AccountIdIndex),
        DispatchKind::StoreAccountIndex => dispatch_store(row,state,StoreKind::AccountIndex),
        DispatchKind::StoreAccountAsset => dispatch_store(row,state,StoreKind::AccountAsset),
        DispatchKind::StoreAssetIssue => dispatch_store(row,state,StoreKind::AssetIssue),
        DispatchKind::StoreAssetIssueV2 => dispatch_store(row,state,StoreKind::AssetIssueV2),
        DispatchKind::StoreBlock => dispatch_store(row,state,StoreKind::Block),
        DispatchKind::StoreBlockIndex => dispatch_store(row,state,StoreKind::BlockIndex),
        DispatchKind::StoreTransaction => dispatch_store(row,state,StoreKind::Transaction),
        DispatchKind::StoreTransactionCache => dispatch_store(row,state,StoreKind::TransactionCache),
        DispatchKind::StoreTransactionRet => dispatch_store(row,state,StoreKind::TransactionRet),
        DispatchKind::StoreTransactionHistory => dispatch_store(row,state,StoreKind::TransactionHistory),
        DispatchKind::StoreRecentBlock => dispatch_store(row,state,StoreKind::RecentBlock),
        DispatchKind::StoreRecentTransaction => dispatch_store(row,state,StoreKind::RecentTransaction),
        DispatchKind::StoreContract => dispatch_store(row,state,StoreKind::Contract),
        DispatchKind::StoreAbi => dispatch_store(row,state,StoreKind::Abi),
        DispatchKind::StoreCode => dispatch_store(row,state,StoreKind::Code),
        DispatchKind::StoreContractState => dispatch_store(row,state,StoreKind::ContractState),
        DispatchKind::StoreStorageRow => dispatch_store(row,state,StoreKind::StorageRow),
        DispatchKind::StoreWitness => dispatch_store(row,state,StoreKind::Witness),
        DispatchKind::StoreWitnessSchedule => dispatch_store(row,state,StoreKind::WitnessSchedule),
        DispatchKind::StoreVotes => dispatch_store(row,state,StoreKind::Votes),
        DispatchKind::StoreProposal => dispatch_store(row,state,StoreKind::Proposal),
        DispatchKind::StoreExchange => dispatch_store(row,state,StoreKind::Exchange),
        DispatchKind::StoreExchangeV2 => dispatch_store(row,state,StoreKind::ExchangeV2),
        DispatchKind::StoreMarketAccount => dispatch_store(row,state,StoreKind::MarketAccount),
        DispatchKind::StoreMarketOrder => dispatch_store(row,state,StoreKind::MarketOrder),
        DispatchKind::StoreMarketPairToPrice => dispatch_store(row,state,StoreKind::MarketPairToPrice),
        DispatchKind::StoreMarketPairPriceToOrder => dispatch_store(row,state,StoreKind::MarketPairPriceToOrder),
        DispatchKind::StoreDelegatedResource => dispatch_store(row,state,StoreKind::DelegatedResource),
        DispatchKind::StoreDelegatedResourceAccountIndex => dispatch_store(row,state,StoreKind::DelegatedResourceAccountIndex),
        DispatchKind::StoreDynamicProperties => dispatch_store(row,state,StoreKind::DynamicProperties),
        DispatchKind::StoreIncrementalMerkleTree => dispatch_store(row,state,StoreKind::IncrementalMerkleTree),
        DispatchKind::StoreNullifier => dispatch_store(row,state,StoreKind::Nullifier),
        DispatchKind::StoreZkProof => dispatch_store(row,state,StoreKind::ZkProof),
        DispatchKind::StoreTreeBlockIndex => dispatch_store(row,state,StoreKind::TreeBlockIndex),
        DispatchKind::StoreSectionBloom => dispatch_store(row,state,StoreKind::SectionBloom),
        DispatchKind::StoreAccountTrace => dispatch_store(row,state,StoreKind::AccountTrace),
        DispatchKind::StoreBalanceTrace => dispatch_store(row,state,StoreKind::BalanceTrace),
        DispatchKind::StoreDelegation => dispatch_store(row,state,StoreKind::Delegation),
        DispatchKind::StorePbft => dispatch_store(row,state,StoreKind::Pbft),
        DispatchKind::StoreRewardVi => dispatch_store(row,state,StoreKind::RewardVi),
        DispatchKind::StoreCommon => dispatch_store(row,state,StoreKind::Common),
        DispatchKind::StoreCheckpoint => dispatch_store(row,state,StoreKind::Checkpoint),
        DispatchKind::StoreTemporary => dispatch_store(row,state,StoreKind::Temporary),
        DispatchKind::CapsuleAbiCapsule => dispatch_proto::<tron_protocol::protocol::smart_contract::Abi>(row),
        DispatchKind::CapsuleAccountCapsule => dispatch_proto::<tron_protocol::protocol::Account>(row),
        DispatchKind::CapsuleAccountTraceCapsule => dispatch_proto::<tron_protocol::protocol::AccountTrace>(row),
        DispatchKind::CapsuleAssetIssueCapsule => dispatch_proto::<tron_protocol::protocol::AssetIssueContract>(row),
        DispatchKind::CapsuleBlockBalanceTraceCapsule => dispatch_proto::<tron_protocol::protocol::BlockBalanceTrace>(row),
        DispatchKind::CapsuleBlockCapsule => dispatch_proto::<tron_protocol::protocol::Block>(row),
        DispatchKind::CapsuleContractCapsule => dispatch_proto::<tron_protocol::protocol::SmartContract>(row),
        DispatchKind::CapsuleContractStateCapsule => dispatch_proto::<tron_protocol::protocol::ContractState>(row),
        DispatchKind::CapsuleDelegatedResourceAccountIndexCapsule => dispatch_proto::<tron_protocol::protocol::DelegatedResourceAccountIndex>(row),
        DispatchKind::CapsuleDelegatedResourceCapsule => dispatch_proto::<tron_protocol::protocol::DelegatedResource>(row),
        DispatchKind::CapsuleExchangeCapsule => dispatch_proto::<tron_protocol::protocol::Exchange>(row),
        DispatchKind::CapsuleIncrementalMerkleTreeCapsule => dispatch_proto::<tron_protocol::protocol::IncrementalMerkleTree>(row),
        DispatchKind::CapsuleIncrementalMerkleVoucherCapsule => dispatch_proto::<tron_protocol::protocol::IncrementalMerkleVoucher>(row),
        DispatchKind::CapsuleMarketAccountOrderCapsule => dispatch_proto::<tron_protocol::protocol::MarketAccountOrder>(row),
        DispatchKind::CapsuleMarketOrderCapsule => dispatch_proto::<tron_protocol::protocol::MarketOrder>(row),
        DispatchKind::CapsuleMarketOrderIdListCapsule => dispatch_proto::<tron_protocol::protocol::MarketOrderIdList>(row),
        DispatchKind::CapsuleMarketPriceCapsule => dispatch_proto::<tron_protocol::protocol::MarketPrice>(row),
        DispatchKind::CapsulePbftSignCapsule => dispatch_proto::<tron_protocol::protocol::PbftCommitResult>(row),
        DispatchKind::CapsulePedersenHashCapsule => dispatch_proto::<tron_protocol::protocol::PedersenHash>(row),
        DispatchKind::CapsuleProposalCapsule => dispatch_proto::<tron_protocol::protocol::Proposal>(row),
        DispatchKind::CapsuleReceiptCapsule => dispatch_proto::<tron_protocol::protocol::ResourceReceipt>(row),
        DispatchKind::CapsuleTransactionCapsule => dispatch_proto::<tron_protocol::protocol::Transaction>(row),
        DispatchKind::CapsuleTransactionInfoCapsule => dispatch_proto::<tron_protocol::protocol::TransactionInfo>(row),
        DispatchKind::CapsuleTransactionResultCapsule => dispatch_proto::<tron_protocol::protocol::transaction::Result>(row),
        DispatchKind::CapsuleTransactionRetCapsule => dispatch_proto::<tron_protocol::protocol::TransactionRet>(row),
        DispatchKind::CapsuleVotesCapsule => dispatch_proto::<tron_protocol::protocol::Votes>(row),
        DispatchKind::CapsuleWitnessCapsule => dispatch_proto::<tron_protocol::protocol::Witness>(row),
        DispatchKind::CapsuleBytesCapsule => dispatch_raw_capsule(row),
        DispatchKind::CapsuleCodeCapsule => dispatch_raw_capsule(row),
        DispatchKind::CapsuleProtoCapsule => dispatch_raw_capsule(row),
        DispatchKind::CapsuleStorageRowCapsule => dispatch_raw_capsule(row),
        DispatchKind::DynamicKey=>{assert_eq!(function_kind,"dynamic_key");assert_eq!(tron_state::dynamic::key(&row.schema),Some(hex(&row.key_hex).as_slice()),"{}",row.id)},
        DispatchKind::DynamicDefault=>{assert_eq!(function_kind,"dynamic_default");assert_eq!(state.store(StoreKind::DynamicProperties).get(&hex(&row.key_hex)),Some(hex(&row.value_hex)),"{}",row.id)},
    }
}
#[test]
fn java_codec_artifact_dispatches_every_row(){let raw=include_str!("../../../../docs/oracles/c008-state-fixtures.v1.json");assert!(raw.contains(RUST_DISPATCH));let artifact=artifact(raw);let directory=path("java-codecs");let state=StateStore::new(manager().open_store(&directory).unwrap());tron_state::dynamic::initialize_missing(&state.store(StoreKind::DynamicProperties),&tron_state::dynamic::DynamicPropertyConfig::default(),0,&tron_state::dynamic::AVAILABLE_CONTRACT_TYPES).unwrap();for row in &artifact.rows{dispatch_row(row,artifact.raw,&state)}drop(state);fs::remove_dir_all(directory).unwrap();}
#[test]
fn malformed_values_are_rejected(){assert!(TransactionValue::decode(&[0x0a,0x02,0xff]).is_err());assert!(TransactionHistoryValue::decode(&[0x0a,0x02,0xff]).is_err());assert!(BlockIndexValue::decode(&[0]).is_err());assert!(decode_witness_schedule(&[0]).is_err());assert!(decode_zk_proof_value(&[2]).is_err());}
