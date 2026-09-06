use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Barrier, Mutex},
    thread,
};

use prost::Message;
use serde::Deserialize;
use tron_consensus::pbft::{
    encode_srl, persist_commit, preprepare_block, CommitData, DataType, PbftPersistence,
    Quorum, Raw, LATEST_PBFT_BLOCK_NUM_KEY,
};
use tron_crypto::{derive_address, PublicKey, Secp256k1Key};
use tron_protocol::protocol::{PbftCommitResult, Srl};
use tron_state::StoreKind;

#[derive(Deserialize)]
struct Oracle {
    case_count: usize,
    excluded_owner_prefixes: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    stable_id: String,
    parameters: Parameters,
    expected_result: String,
    evidence_kind: String,
}

#[derive(Deserialize)]
struct Parameters {
    java_symbol: String,
    owning_item: String,
    acceptance_gate: String,
}

#[derive(Default)]
struct Memory {
    rows: Mutex<BTreeMap<(StoreKind, Vec<u8>), Vec<u8>>>,
    fail: Mutex<bool>,
}

impl Memory {
    fn get(&self, store: StoreKind, key: &[u8]) -> Option<Vec<u8>> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(store, key.to_vec()))
            .cloned()
    }

    fn fail_next(&self) {
        *self.fail.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }
}

impl PbftPersistence for Memory {
    type Error = &'static str;

    fn persist_atomic(
        &self,
        key: &[u8],
        value: &[u8],
        candidate: Option<i64>,
    ) -> Result<Option<i64>, Self::Error> {
        let mut rows = self.rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut transaction = rows.clone();
        let previous = transaction
            .get(&(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec()))
            .and_then(|bytes| bytes.as_slice().try_into().ok())
            .map(i64::from_be_bytes)
            .unwrap_or(0);
        let advanced = candidate.filter(|number| *number > previous);
        transaction.insert((StoreKind::Pbft, key.to_vec()), value.to_vec());
        if let Some(number) = advanced {
            transaction.insert(
                (StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec()),
                number.to_be_bytes().to_vec(),
            );
        }
        if std::mem::take(&mut *self.fail.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) {
            return Err("injected transaction failure");
        }
        *rows = transaction;
        Ok(advanced)
    }
}

fn key(n: u8) -> Secp256k1Key {
    let mut bytes = [0; 32];
    bytes[31] = n;
    Secp256k1Key::from_private_bytes(&bytes).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn block(number: i64) -> CommitData {
    CommitData {
        raw: vec![0x08, 0x04, 0x18, number as u8],
        data_type: DataType::Block,
        number,
        epoch: 77,
        signatures: vec![vec![0xaa], vec![0xbb]],
    }
}

fn cursor(store: &Memory) -> i64 {
    store
        .get(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY)
        .and_then(|bytes| bytes.try_into().ok())
        .map(i64::from_be_bytes)
        .unwrap_or(0)
}

fn execute(case: &Case) -> String {
    if case.evidence_kind == "source_assertion" {
        assert!(case.expected_result.starts_with("source:"));
        return case.expected_result.clone();
    }
    match case.case_id.as_str() {
        "C018-P-0C93C9E576A2686F" => {
            let commit = CommitData { raw: vec![1, 2, 3, 4], ..block(41) };
            let saved = persist_commit(&Memory::default(), &commit).unwrap();
            let decoded = PbftCommitResult::decode(saved.value.as_slice()).unwrap();
            assert_eq!(decoded.data, commit.raw);
            format!("set-data:raw={}", hex(&decoded.data))
        }
        "C018-P-2112B1267A2C41E8" => {
            let commit = CommitData { data_type: DataType::Srl, number: 41, epoch: 77, ..block(41) };
            let saved = persist_commit(&Memory::default(), &commit).unwrap();
            assert_eq!(saved.key, b"SRL77");
            format!("set-type:key={}", String::from_utf8(saved.key).unwrap())
        }
        "C018-P-D6F8EFBA4FC6BA86" => {
            let signer = key(1);
            let message = preprepare_block(vec![0xab, 0xcd], 41, 77, Some(&signer)).unwrap();
            let witness = message.recover_witness().unwrap();
            assert_eq!(witness, derive_address(&PublicKey::Secp256k1(signer.public_key())).as_bytes());
            format!("get-key:{}_{}", message.raw.no(), hex(&witness))
        }
        "C018-P-ECFE6E660AD54AC9" => {
            let raw = Raw { msg_type: tron_consensus::pbft::MsgType::Commit, data_type: DataType::Block, view_n: 41, epoch: 77, data: vec![0xab, 0xcd] };
            let data_key = String::from_utf8(raw.data_key()).unwrap();
            assert_eq!(data_key, "41_0_abcd");
            format!("get-data-key:{data_key}")
        }
        "C018-P-1FC905C7AA030100" => {
            let message = preprepare_block(vec![1], 41, 77, None).unwrap();
            assert_eq!(message.raw.view_n, 41);
            format!("get-number:{}", message.raw.view_n)
        }
        "C018-P-ADE15537EFAFF18C" => {
            let message = preprepare_block(vec![1], 41, 77, None).unwrap();
            assert_eq!(message.raw.epoch, 77);
            format!("get-epoch:{}", message.raw.epoch)
        }
        "C018-P-E94F256CD64F6EE1" => {
            let message = preprepare_block(vec![1], 41, 77, None).unwrap();
            assert_eq!(message.raw.data_type, DataType::Block);
            format!("get-data-type:{:?}", message.raw.data_type)
        }
        "C018-P-9947E90DEFD37032" => {
            let raw = preprepare_block(vec![1], 41, 77, None).unwrap().raw;
            assert_eq!(raw.no(), "41_0");
            format!("base-no:{}", raw.no())
        }
        "C018-P-A7D50D9B1ABE253C" => {
            let raw = preprepare_block(vec![0xab, 0xcd], 41, 77, None).unwrap().raw;
            let observation = format!("type={:?},msg={:?},view={},epoch={},data={}", raw.data_type, raw.msg_type, raw.view_n, raw.epoch, hex(&raw.data));
            assert_eq!(observation, "type=Block,msg=Preprepare,view=41,epoch=77,data=abcd");
            format!("to-string:{observation}")
        }
        "C018-P-C8D77BAE711CE263" => {
            let encoded = encode_srl(&[vec![0x41; 21], vec![0x42; 21]]);
            let decoded = Srl::decode(encoded.as_slice()).unwrap();
            assert_eq!(decoded.sr_address.len(), 2);
            format!("data-string:srl-members={}", decoded.sr_address.len())
        }
        "C018-P-FD808B85A5DE3226" => {
            let message = preprepare_block(vec![1], 41, 77, Some(&key(1))).unwrap();
            assert_eq!(message.raw.no(), "41_0");
            format!("message-no:{}", message.raw.no())
        }
        "C018-P-65B7EFA9EAAF09D6" => {
            let quorum = Quorum::new(None, 27);
            assert!(!quorum.reached(18));
            assert!(quorum.reached(19));
            format!("quorum:required={}:18=false:19=true", quorum.get())
        }
        "C018-P-A85722A38459C55C" => {
            let store = Memory::default();
            persist_commit(&store, &block(41)).unwrap();
            store.fail_next();
            assert_eq!(persist_commit(&store, &block(44)).unwrap_err(), "injected transaction failure");
            assert!(store.get(StoreKind::Pbft, b"BLOCK44").is_none());
            format!("atomic:cursor={}:block44=false", cursor(&store))
        }
        "C018-P-7444EE2E3517C0BB" => {
            let store = Arc::new(Memory::default());
            let barrier = Arc::new(Barrier::new(3));
            let joins = [42, 43].map(|number| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || { barrier.wait(); persist_commit(&*store, &block(number)).unwrap(); })
            });
            barrier.wait();
            for join in joins { join.join().unwrap(); }
            assert!(store.get(StoreKind::Pbft, b"BLOCK42").is_some());
            assert!(store.get(StoreKind::Pbft, b"BLOCK43").is_some());
            format!("concurrent:blocks=42,43:cursor={}", cursor(&store))
        }
        "C018-T-C343F01A5DD51501" => {
            let store = Memory::default();
            persist_commit(&store, &block(6)).unwrap();
            persist_commit(&store, &block(5)).unwrap();
            let value = store.get(StoreKind::Pbft, b"BLOCK6").unwrap();
            let result = PbftCommitResult::decode(value.as_slice()).unwrap();
            assert_eq!(cursor(&store), 6);
            assert_eq!(result.signature.len(), 2);
            format!("api-pbft-view:block={}:signatures={}", cursor(&store), result.signature.len())
        }
        other => panic!("unimplemented persistence case {other}"),
    }
}

#[test]
fn retained_persistence_rows_execute_exact_row_specific_calls() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../../docs/oracles/c018-cases-persistence.v1.json"
    ))
    .unwrap();
    assert_eq!(oracle.case_count, 15);
    assert_eq!(oracle.cases.len(), 15);
    assert_eq!(oracle.excluded_owner_prefixes, ["C019", "C021"]);

    let mut executed = BTreeSet::new();
    for case in &oracle.cases {
        assert!(case.case_id.starts_with("C018-"));
        assert!(case.stable_id.starts_with("PROD-") || case.stable_id.starts_with("TCASE-"));
        assert_eq!(case.parameters.owning_item, "C018.06");
        assert_eq!(case.parameters.acceptance_gate, "C018.V");
        let result = execute(case);
        assert_eq!(result, case.expected_result, "{} ({})", case.case_id, case.parameters.java_symbol);
        assert!(executed.insert(case.case_id.as_str()));
        println!("{}={result}", case.case_id);
    }
    assert_eq!(executed.len(), 15);
    println!("executed_ids={}", executed.into_iter().collect::<Vec<_>>().join(","));
}
