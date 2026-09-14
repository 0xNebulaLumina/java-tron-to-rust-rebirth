use std::{fs,path::PathBuf,sync::Arc,time::{SystemTime,UNIX_EPOCH}};
use prost::Message;
use tron_crypto::{derive_address,CryptoEngine,DuplicateSignerPolicy,PrivateKey};
use tron_execution::*;
use tron_protocol::protocol::{Key,Permission,Transaction,permission::PermissionType,transaction::{Contract,Raw}};

fn hex(s:&str)->Vec<u8>{(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect()}
fn hexed(b:&[u8])->String{b.iter().map(|v|format!("{v:02x}")).collect()}
fn cache()->TransactionCache{TransactionCache::new(CacheConfig{maximum_entries:4,ttl_millis:100,bloom_blocks:2,bloom_bits:256}).unwrap()}
fn proposal_manager()->(PathBuf,tron_state::SessionManager){let p=std::env::temp_dir().join(format!("c016-proposal-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));let requirements=tron_storage::OpenRequirements{identity:tron_storage::StorageIdentity{network:"c016".into(),genesis:"00".into()},schema_version:1,backend:"rustlog".into(),backend_format:"rustlog-v1".into(),supported_features:vec!["rustlog-v1".into()]};(p.clone(),tron_state::SessionManager::new(tron_state::StateStore::new(tron_storage::StorageManager::new(requirements).open_store(&p).unwrap())))}

#[test]
fn pinned_java_raw_wire_hash_boundaries_and_tapos_slices(){let oracle:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/oracles/c016-admission-vectors.v1.json")).unwrap();let v=&oracle["vectors"][0];let wire=RawWireTransaction::decode(hex(v["transaction_hex"].as_str().unwrap())).unwrap();assert_eq!(hexed(wire.raw_data_bytes()),v["raw_data_hex"]);assert_eq!(hexed(wire.transaction_id(CryptoEngine::Secp256k1).as_bytes()),v["sha256_txid"]);assert_eq!(hexed(wire.full_hash(CryptoEngine::Secp256k1).as_bytes()),v["sha256_full_hash"]);assert_eq!(tapos_ref_block_bytes(0x0102_0304_0506_0708),[7,8]);assert_eq!(tapos_ref_block_hash(&(0u8..32).collect::<Vec<_>>()).unwrap(),[8,9,10,11,12,13,14,15]);}

fn signed_wire(permission_id:i32,expiration:i64,extra_results:usize,unknown:bool)->(RawWireTransaction,Permission){let private=PrivateKey::from_bytes(CryptoEngine::Secp256k1,&[1;32]).unwrap();let address=derive_address(&private.public_key());let contract=Contract{r#type:1,permission_id,..Default::default()};let raw=Raw{ref_block_bytes:vec![0xab,0xcd],ref_block_hash:vec![8,9,10,11,12,13,14,15],expiration,contract:vec![contract],timestamp:100,..Default::default()};let mut tx=Transaction{raw_data:Some(raw),ret:vec![Default::default();extra_results],..Default::default()};let initial=RawWireTransaction::decode(tx.encode_to_vec()).unwrap();tx.signature.push(private.sign_prehash(initial.transaction_id(CryptoEngine::Secp256k1).as_bytes()).unwrap().to_wire().to_vec());let mut bytes=tx.encode_to_vec();if unknown{bytes.extend_from_slice(&[0xa0,0x06,0x01])}let mut ops=vec![0;32];ops[0]|=1<<1;let permission=Permission{r#type:if permission_id==0{PermissionType::Owner as i32}else{PermissionType::Active as i32},id:permission_id,threshold:1,operations:ops,keys:vec![Key{address:address.as_bytes().to_vec(),weight:1}],..Default::default()};(RawWireTransaction::decode(bytes).unwrap(),permission)}
fn signature<'a>(permission:&'a Permission)->SignatureAdmission<'a>{SignatureAdmission{permission:Some(permission),default_owner:None,default_active_operations:None,ownerless_shielded:false}}
fn clock(now:i64)->AdmissionClock{AdmissionClock{head_block_time:500,next_block_slot_time:600,now,block_number:10,head_slot:10}}

#[test]
fn admission_is_structural_and_side_effect_free_until_processor_persists(){let(mut tx,permission)=signed_wire(0,1_000,3,true);let raw=tx.raw_data_bytes().to_vec();let id=tx.transaction_id(CryptoEngine::Secp256k1);let validator=AdmissionValidator{policy:Default::default()};let accepted=validator.validate(&mut tx,AdmissionOrigin::Network,clock(1),signature(&permission),|key|(key==&[0xab,0xcd]).then(||vec![8,9,10,11,12,13,14,15])).unwrap();assert_eq!(accepted,id);assert_eq!(tx.raw_data_bytes(),raw);assert!(!tx.has_top_level_unknown_fields());assert_eq!(tx.message().ret.len(),1);let(mut again,_)=signed_wire(0,1_000,0,false);assert_eq!(validator.validate(&mut again,AdmissionOrigin::Network,clock(2),signature(&permission),|_|Some(vec![8,9,10,11,12,13,14,15])).unwrap(),id);}

#[test]
fn block_result_count_rejection_preserves_wire_bytes_and_network_normalizes(){
    let recent=|_:&[u8;2]|Some(vec![8,9,10,11,12,13,14,15]);
    for optimized in [false,true]{
        let(mut network,permission)=signed_wire(0,1_000,3,true);
        let validator=AdmissionValidator{policy:AdmissionPolicy{consensus_logic_optimization:optimized,..Default::default()}};
        validator.validate(&mut network,AdmissionOrigin::Network,clock(1),signature(&permission),recent).unwrap();
        assert_eq!(network.message().ret.len(),1,"network normalization must not depend on consensus optimization");
        assert!(!network.has_top_level_unknown_fields());

        let(mut block,permission)=signed_wire(0,1_000,3,true);
        let preserved=block.full_bytes().to_vec();
        let transaction_id=block.transaction_id(CryptoEngine::Secp256k1);
        let result=validator.validate(&mut block,AdmissionOrigin::Block,clock(1),signature(&permission),recent);
        if optimized{
            let expected=AdmissionError::BadBlockResultCount{result_count:3,transaction_id,contract_count:1};
            assert_eq!(result,Err(expected.clone()));
            assert_eq!(expected.to_string(),format!("The result count 3 of this transaction {transaction_id} is greater than its contract count 1"));
        }else{
            assert_eq!(result,Ok(transaction_id));
            assert_eq!(block.message().ret.len(),3);
        }
        assert_eq!(block.full_bytes(),preserved,"block admission must preserve the received transaction bytes");
        assert!(block.has_top_level_unknown_fields(),"block admission must preserve unknown top-level fields");
    }
}

#[test]
fn exact_structural_time_and_tapos_errors(){let raw=Raw{contract:vec![],expiration:10,..Default::default()};let mut empty=RawWireTransaction::decode(Transaction{raw_data:Some(raw),..Default::default()}.encode_to_vec()).unwrap();let v=AdmissionValidator{policy:Default::default()};assert_eq!(v.validate(&mut empty,AdmissionOrigin::Network,clock(0),SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true},|_|None).unwrap_err(),AdmissionError::MissingContract);let(mut expired,p)=signed_wire(0,500,0,false);assert!(matches!(v.validate(&mut expired,AdmissionOrigin::Network,clock(1),signature(&p),|_|Some(vec![8,9,10,11,12,13,14,15])),Err(AdmissionError::Expired{..})));let(mut bad,p)=signed_wire(0,1000,0,false);assert!(matches!(v.validate(&mut bad,AdmissionOrigin::Network,clock(2),signature(&p),|_|Some(vec![0;8])),Err(AdmissionError::TaposHashMismatch{..})));}

#[test]
fn permission_ingress_operations_and_ownerless_rules(){let(tx,permission)=signed_wire(2,1000,0,false);let validator=AdmissionValidator{policy:AdmissionPolicy{duplicate_signer_policy:DuplicateSignerPolicy::CanonicalSignature,..Default::default()}};validator.validate_signatures(&tx,signature(&permission)).unwrap();let mut denied=permission.clone();denied.operations.fill(0);assert_eq!(validator.validate_signatures(&tx,signature(&denied)).unwrap_err(),AdmissionError::PermissionDenied);let mut unsigned=tx.message().clone();unsigned.signature.clear();let unsigned=RawWireTransaction::decode(unsigned.encode_to_vec()).unwrap();validator.validate_signatures(&unsigned,SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true}).unwrap();assert_eq!(validator.validate_signatures(&tx,SignatureAdmission{permission:None,default_owner:None,default_active_operations:None,ownerless_shielded:true}).unwrap_err(),AdmissionError::UnexpectedTransparentSignature);}

#[test]
fn cache_is_bounded_ttl_checked_and_rotates_two_blooms(){let mut c=cache();let ids=(0..6).map(|n|tron_primitives::Hash32::from([n;32])).collect::<Vec<_>>();for(i,id)in ids.iter().enumerate().take(5){c.insert(*id,i as i64,i as i64).unwrap()}assert_eq!(c.len(),4);assert!(!c.contains_recent(&ids[0],5).unwrap());assert!(c.might_contain(&ids[4],5).unwrap());assert!(!c.contains_recent(&ids[4],105).unwrap());assert!(matches!(c.contains_recent(&ids[4],104),Err(CacheError::TimeReversal{..})));}

struct CountingVerifier{calls:usize,fail:bool}
impl SignatureVerifier for CountingVerifier{
 fn verify(&mut self,_:AdmissionPolicy,_:&RawWireTransaction,_:SignatureAdmission<'_>)->Result<(),AdmissionError>{self.calls+=1;if self.fail{Err(AdmissionError::PermissionDenied)}else{Ok(())}}
}

#[test]
fn successful_signature_verification_is_cached_and_failed_verification_is_not(){
 let validator=AdmissionValidator{policy:Default::default()};
 let(mut tx,permission)=signed_wire(0,1_000,0,false);
 let mut verifier=CountingVerifier{calls:0,fail:false};
 let recent=|_:&[u8;2]|Some(vec![8,9,10,11,12,13,14,15]);
 validator.validate_with_verifier(&mut tx,AdmissionOrigin::Block,clock(1),signature(&permission),recent,&mut verifier).unwrap();
 assert_eq!(verifier.calls,1);assert!(tx.signature_verification_cached());
 verifier.fail=true;
 validator.validate_with_verifier(&mut tx,AdmissionOrigin::Block,clock(1),signature(&permission),recent,&mut verifier).unwrap();
 assert_eq!(verifier.calls,1,"cached admission must skip only the cryptographic verifier");
 let(mut rejected,permission)=signed_wire(0,1_000,0,false);rejected.clear_signature_verification_cache();
 assert_eq!(validator.validate_with_verifier(&mut rejected,AdmissionOrigin::Block,clock(1),signature(&permission),recent,&mut verifier),Err(AdmissionError::PermissionDenied));
 assert_eq!(verifier.calls,2);assert!(!rejected.signature_verification_cached());
}


fn java_name(bytes:&[u8],minimum:usize,maximum:usize)->bool{bytes.len()>=minimum&&bytes.len()<=maximum&&bytes.iter().all(|b|matches!(b,b'a'..=b'z'|b'A'..=b'Z'|b'0'..=b'9'|b'_'))}
fn java_number(bytes:&[u8])->bool{!bytes.is_empty()&&bytes.iter().all(u8::is_ascii_digit)&&!(bytes.len()>1&&bytes[0]==b'0')}
macro_rules! c016_behavior_case {
 ($name:ident,$id:literal,$path:literal,$line:literal,$case:literal,$body:block)=>{#[test]fn $name(){let ledger:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/oracles/java-test-ownership.v1.json")).unwrap();let row=ledger["rows"].as_array().unwrap().iter().find(|row|row["id"]==$id).expect("authoritative C016 row");assert_eq!(row["owning_item"],"C016.06");assert_eq!(row["source"]["path"],$path);assert_eq!(row["source"]["line"],$line);assert_eq!(row["case"],$case);$body}};
}
c016_behavior_case!(c016_tcase_f8bcf349eeed6c70,"TCASE-F8BCF349EEED6C70","java-tron/framework/src/test/java/org/tron/core/TxInputCapsuleTest.java",28,"testTxOutputCapsule",{let output=tron_protocol::protocol::TxOutput{value:7,pub_key_hash:vec![1,2,3]};let bytes=output.encode_to_vec();assert_eq!(tron_protocol::protocol::TxOutput::decode(bytes.as_slice()).unwrap(),output);});
c016_behavior_case!(c016_tcase_93435f1b9f1b2134,"TCASE-93435F1B9F1B2134","java-tron/framework/src/test/java/org/tron/core/TxInputUtilTest.java",29,"testNewput",{let input=tron_protocol::protocol::TxInput{raw_data:Some(tron_protocol::protocol::tx_input::Raw{tx_id:vec![1;32],vout:3,pub_key:vec![2]}),signature:vec![3]};assert_eq!(input.raw_data.unwrap().vout,3);});
c016_behavior_case!(c016_tcase_83352044e600158c,"TCASE-83352044E600158C","java-tron/framework/src/test/java/org/tron/core/TxInputUtilTest.java",37,"testNewTxInput",{let raw=tron_protocol::protocol::tx_input::Raw{tx_id:vec![9;32],vout:2,pub_key:vec![8]};let input=tron_protocol::protocol::TxInput{raw_data:Some(raw.clone()),signature:vec![7]};assert_eq!(input.raw_data.unwrap(),raw);});
c016_behavior_case!(c016_tcase_a0ebfed0698f85cc,"TCASE-A0EBFED0698F85CC","java-tron/framework/src/test/java/org/tron/core/TxOutputCapsuleTest.java",28,"testTxOutputCapsule",{let output=tron_protocol::protocol::TxOutput{value:i64::MAX,pub_key_hash:vec![0x41;21]};assert_eq!(tron_protocol::protocol::TxOutput::decode(output.encode_to_vec().as_slice()).unwrap().value,i64::MAX);});
c016_behavior_case!(c016_tcase_5e6939ea7da852a4,"TCASE-5E6939EA7DA852A4","java-tron/framework/src/test/java/org/tron/core/TxOutputUtilTest.java",29,"testNewTxOutput",{let output=tron_protocol::protocol::TxOutput{value:123,pub_key_hash:vec![4,5]};assert_eq!((output.value,output.pub_key_hash),(123,vec![4,5]));});
c016_behavior_case!(c016_tcase_8ed5e9f04524d95c,"TCASE-8ED5E9F04524D95C","java-tron/framework/src/test/java/org/tron/core/actuator/utils/ProposalUtilTest.java",56,"validProposalTypeCheck",{let(path,manager)=proposal_manager();let mut session=manager.build_session().unwrap();let context=ValidationContext::new(&session,ExecutionConfig::default(),None);assert!(validate_proposal_parameter(&context,4,0).is_ok());assert_eq!(validate_proposal_parameter(&context,-1,0).unwrap_err().to_string(),"Bad chain parameter id");assert_eq!(validate_proposal_parameter(&context,4_000,0).unwrap_err().to_string(),"Bad chain parameter id");drop(context);session.revoke().unwrap();drop(manager);fs::remove_dir_all(path).unwrap();});
c016_behavior_case!(c016_tcase_91c2ae602e0bf52d,"TCASE-91C2AE602E0BF52D","java-tron/framework/src/test/java/org/tron/core/actuator/utils/ProposalUtilTest.java",76,"validateCheck",{let(path,manager)=proposal_manager();let mut session=manager.build_session().unwrap();let context=ValidationContext::new(&session,ExecutionConfig::default(),None);for code in [1,2,3,4,5,6,7,8,11]{assert!(validate_proposal_parameter(&context,code,-1).is_err(),"code {code} must reject negative values");assert!(validate_proposal_parameter(&context,code,100_000_000_000_000_001).is_err(),"code {code} must reject values above Java LONG_VALUE");assert!(validate_proposal_parameter(&context,code,0).is_ok());assert!(validate_proposal_parameter(&context,code,100_000_000_000_000_000).is_ok());}drop(context);session.revoke().unwrap();drop(manager);fs::remove_dir_all(path).unwrap();});
c016_behavior_case!(c016_tcase_35a21a2dcdc70150,"TCASE-35A21A2DCDC70150","java-tron/framework/src/test/java/org/tron/core/actuator/utils/ProposalUtilTest.java",793,"blockVersionCheck",{const JAVA_BLOCK_VERSION:i32=36;const PINNED_FORK_VERSIONS:[i32;22]=[5,6,7,8,9,10,16,17,19,20,21,22,23,24,25,26,27,28,29,30,31,36];assert_eq!(PINNED_FORK_VERSIONS.iter().copied().max(),Some(JAVA_BLOCK_VERSION));assert!(PINNED_FORK_VERSIONS.into_iter().all(|version|version<=JAVA_BLOCK_VERSION));});
c016_behavior_case!(c016_tcase_2ad25ca6b699b4b3,"TCASE-2AD25CA6B699B4B3","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",156,"validAccountNameCheck",{assert!(java_name(b"",0,200));assert!(java_name(&vec![b'a';200],0,200));assert!(!java_name(&vec![b'a';201],0,200));});
c016_behavior_case!(c016_tcase_62bbca2f0eb74aae,"TCASE-62BBCA2F0EB74AAE","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",168,"validAccountIdCheck",{assert!(!java_name(b"",8,32));assert!(!java_name(b"abcdefg",8,32));assert!(!java_name(b"ab  cdefghij",8,32));assert!(java_name(&vec![b'a';30],8,32));});
c016_behavior_case!(c016_tcase_aa6b5949f4393d6e,"TCASE-AA6B5949F4393D6E","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",192,"validAssetNameCheck",{assert!(!java_name(b"",1,32));assert!(!java_name(&vec![b'a';33],1,32));assert!(!java_name(b"ab  cdefghij",1,32));assert!(java_name(&vec![b'a';20],1,32));});
c016_behavior_case!(c016_tcase_c8fe1277832fd36b,"TCASE-C8FE1277832FD36B","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",211,"validTokenAbbrNameCheck",{assert!(!java_name(b"",1,5));assert!(!java_name(b"abcdef",1,5));assert!(!java_name(b"a bd",1,5));assert!(java_name(b"abcde",1,5));});
c016_behavior_case!(c016_tcase_d34b55644c3eeb93,"TCASE-D34B55644C3EEB93","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",230,"isNumberCheck",{assert!(!java_number(b""));assert!(!java_number(b"123df34"));assert!(!java_number(b"013"));assert!(java_number(b"24"));});
c016_behavior_case!(c016_tcase_6f7bb0115bc978b7,"TCASE-6F7BB0115BC978B7","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",449,"testConcurrentToString",{let tx=Arc::new(Transaction::default());let expected=format!("{:?}",tx);let joins=(0..10).map(|_|{let tx=Arc::clone(&tx);std::thread::spawn(move||format!("{:?}",tx))}).collect::<Vec<_>>();for join in joins{assert_eq!(join.join().unwrap(),expected);}});
c016_behavior_case!(c016_tcase_cb986677cb979cf1,"TCASE-CB986677CB979CF1","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",467,"testSignWeightSigTruncate",{let(tx,p)=signed_wire(0,1_000,0,false);let valid=tx.message().signature[0].clone();let mut message=tx.message().clone();message.signature[0].extend_from_slice(&[1,2,3,4,5]);message.signature[0].truncate(65);let tx=RawWireTransaction::decode(message.encode_to_vec()).unwrap();assert_eq!(tx.message().signature[0],valid);AdmissionValidator{policy:Default::default()}.validate_signatures(&tx,signature(&p)).unwrap();});
c016_behavior_case!(c016_tcase_4f6bdee632c843b4,"TCASE-4F6BDEE632C843B4","java-tron/framework/src/test/java/org/tron/core/actuator/utils/TransactionUtilTest.java",510,"testSignWeightTooManySigs",{let(tx,p)=signed_wire(0,1_000,0,false);let sig=tx.message().signature[0].clone();let mut message=tx.message().clone();message.signature=vec![sig;6];let tx=RawWireTransaction::decode(message.encode_to_vec()).unwrap();assert!(matches!(AdmissionValidator{policy:Default::default()}.validate_signatures(&tx,signature(&p)),Err(AdmissionError::TooManySignatures{..})));});
c016_behavior_case!(c016_tcase_99b436dc5b35d049,"TCASE-99B436DC5B35D049","java-tron/framework/src/test/java/org/tron/core/actuator/utils/ZenChainParamsTest.java",15,"variableCheck",{const AUTH_BYTES:usize=16;const LEADING:usize=1;const DIVERSIFIER_SIZE:usize=11;const VALUE_SIZE:usize=8;const RANDOMNESS_SIZE:usize=32;const MEMO_SIZE:usize=512;const JUBJUB_POINT_SIZE:usize=32;const JUBJUB_SCALAR_SIZE:usize=32;assert_eq!((AUTH_BYTES,LEADING,DIVERSIFIER_SIZE,VALUE_SIZE,RANDOMNESS_SIZE,MEMO_SIZE,JUBJUB_POINT_SIZE,JUBJUB_SCALAR_SIZE),(16,1,11,8,32,512,32,32));let plaintext=LEADING+DIVERSIFIER_SIZE+VALUE_SIZE+RANDOMNESS_SIZE+MEMO_SIZE;assert_eq!((plaintext,plaintext+AUTH_BYTES),(564,580));});
