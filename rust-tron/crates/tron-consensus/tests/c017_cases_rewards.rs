use std::{collections::BTreeSet, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use num_bigint::BigInt;
use prost::Message;
use serde::Deserialize;
use serde_json::Value;
use tron_consensus::{
    accumulate_vi, adjust_allowance, delegation_brokerage_key, delegation_key,
    pay_block_reward, pay_fee_pool_reward, pay_standby_rewards,
    pay_transaction_fee_reward, query_reward, reward_vi, standby_distribution, withdraw_reward,
    ConsensusRead, StateFacade, VI_SCALE,
};
use tron_protocol::protocol::{Account, Vote};
use tron_state::{dynamic, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Deserialize)]
struct Oracle { cases: Vec<Case> }
#[derive(Deserialize)]
struct Case { case_id: String, operation: String, parameters: Value, expected: String }

fn temporary_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "c017-cases-rewards-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ))
}

fn storage_manager() -> StorageManager {
    StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c017-cases-rewards".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    })
}

fn with_state<T>(run: impl FnOnce(&StateFacade<'_>) -> T) -> T {
    let directory = temporary_path();
    let root = StateStore::new(storage_manager().open_store(&directory).unwrap());
    let sessions = SessionManager::new(root.clone());
    let mut session = sessions.build_session().unwrap();
    let result = run(&StateFacade::new(&session));
    session.revoke().unwrap();
    drop(sessions);
    drop(root);
    fs::remove_dir_all(directory).unwrap();
    result
}

fn save_dynamic(state: &StateFacade<'_>, name: &str, value: i64) {
    state.store_put(StoreKind::DynamicProperties, dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
}

fn save_account(state: &StateFacade<'_>, address: &[u8], allowance: i64, votes: Vec<Vote>) {
    state.store_put(StoreKind::Account, address, &Account {
        address: address.to_vec(), allowance, votes, ..Default::default()
    }.encode_to_vec()).unwrap();
}

fn save_i64(state: &StateFacade<'_>, key: Vec<u8>, value: i64) {
    state.store_put(StoreKind::Delegation, &key, &value.to_be_bytes()).unwrap();
}

fn account(state: &StateFacade<'_>, address: &[u8]) -> Account {
    Account::decode(state.store_get(StoreKind::Account, address).unwrap().as_slice()).unwrap()
}

fn configured_payment(gross: i64, brokerage: i32, pay: fn(&StateFacade<'_>, &[u8], i64) -> Result<tron_consensus::RewardPayment, tron_consensus::StateError>) -> (i64, i64, i64) {
    with_state(|state| {
        let witness = vec![0x41; 21];
        save_dynamic(state, "CURRENT_CYCLE_NUMBER", 7);
        save_account(state, &witness, 0, vec![]);
        state.store_put(StoreKind::Delegation, &delegation_brokerage_key(7, &witness), &brokerage.to_be_bytes()).unwrap();
        let payment = pay(state, &witness, gross).unwrap();
        let stored = i64::from_be_bytes(state.delegation(&delegation_key(7, &witness, "reward")).unwrap().try_into().unwrap());
        assert_eq!(stored, payment.voter_reward);
        assert_eq!(account(state, &witness).allowance, payment.brokerage);
        (payment.gross, payment.voter_reward, payment.brokerage)
    })
}

fn query_fixture(state: &StateFacade<'_>, voter: &[u8], witness: &[u8], effective: i64, votes: i64) {
    save_dynamic(state, "CHANGE_DELEGATION", 1);
    save_dynamic(state, "CURRENT_CYCLE_NUMBER", 2);
    save_dynamic(state, "NEW_REWARD_ALGORITHM_EFFECTIVE_CYCLE", effective);
    save_account(state, voter, 5, vec![Vote { vote_address: witness.to_vec(), vote_count: votes }]);
    for cycle in 0..2 {
        save_i64(state, delegation_key(cycle, witness, "reward"), 100);
        save_i64(state, delegation_key(cycle, witness, "vote"), 100);
    }
}

#[test]
fn retained_reward_rows_execute_exact_family_cases() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c017-cases-rewards.v1.json")).unwrap();
    let reconciliation: Value = serde_json::from_str(include_str!("../../../../docs/oracles/c017-ownership-reconciliation.v1.json")).unwrap();
    let retained: BTreeSet<String> = reconciliation["case_table"].as_array().unwrap().iter()
        .filter(|row| row["suite"] == "c017_rewards")
        .map(|row| row["case_id"].as_str().unwrap().to_owned()).collect();
    let declared: BTreeSet<String> = oracle.cases.iter().map(|case| case.case_id.clone()).collect();
    assert_eq!(declared, retained);
    assert_eq!(declared.len(), oracle.cases.len(), "duplicate reward case_id");

    let mut executed = Vec::new();
    for case in oracle.cases {
        let result = match case.case_id.as_str() {
            "C017-P-0779F109EAECC6F0" => {
                let (gross, voter, brokerage) = configured_payment(10, 20, pay_block_reward);
                assert_eq!((gross, voter, brokerage), (10, 8, 2));
                format!("gross={gross},voter={voter},brokerage={brokerage}")
            }
            "C017-P-492CC6F97EFAF303" => {
                let (gross, voter, brokerage) = configured_payment(15, 20, pay_transaction_fee_reward);
                assert_eq!((gross, voter, brokerage), (15, 12, 3));
                format!("gross={gross},voter={voter},brokerage={brokerage}")
            }
            "C017-P-331745E4E01FCFED" => {
                let (gross, voter, brokerage) = configured_payment(25, 20, pay_block_reward);
                assert_eq!((gross, voter, brokerage), (25, 20, 5));
                format!("gross={gross},voter={voter},brokerage={brokerage}")
            }
            "C017-P-07695C1B63358FFE" => with_state(|state| {
                let a = vec![0x41; 21]; let b = vec![0x42; 21];
                save_dynamic(state, "CURRENT_CYCLE_NUMBER", 3);
                save_account(state, &a, 0, vec![]); save_account(state, &b, 0, vec![]);
                let paid = pay_standby_rewards(state, &[(a.clone(), 1), (b.clone(), 2)], 100).unwrap();
                assert_eq!(paid.iter().map(|p| p.gross).collect::<Vec<_>>(), vec![33, 66]);
                assert_eq!((account(state, &a).allowance, account(state, &b).allowance), (6, 13));
                "payments=33:66".to_owned()
            }),
            "C017-P-E55D50E58966E317" => {
                let (_, reward, allowance) = configured_payment(50, 20, pay_block_reward);
                assert_eq!((allowance, reward), (10, 40));
                format!("allowance={allowance},reward={reward}")
            }
            "C017-P-59369D01BE2713C8" => {
                let (_, reward, allowance) = configured_payment(30, 20, pay_transaction_fee_reward);
                assert_eq!((allowance, reward), (6, 24));
                format!("allowance={allowance},reward={reward}")
            }
            "C017-P-37EA3500936804FE" => with_state(|state| {
                let voter = vec![0x41; 21]; let witness = vec![0x42; 21];
                query_fixture(state, &voter, &witness, i64::MAX, 10);
                let withdrawal = withdraw_reward(state, &voter).unwrap();
                let allowance = account(state, &voter).allowance;
                assert_eq!((withdrawal.reward, withdrawal.begin_cycle, withdrawal.end_cycle, allowance), (20, 2, 3, 25));
                format!("withdrawn={},begin={},end={},allowance={allowance}", withdrawal.reward, withdrawal.begin_cycle, withdrawal.end_cycle)
            }),
            "C017-P-5BEF07444F537224" => with_state(|state| {
                let voter = vec![0x41; 21]; let witness = vec![0x42; 21];
                query_fixture(state, &voter, &witness, i64::MAX, 10);
                let reward = query_reward(state, &voter).unwrap();
                assert_eq!(reward, 25);
                format!("query={reward}")
            }),
            "C017-P-604F98175C127B5E" => with_state(|state| {
                let address = vec![0x41; 21]; save_account(state, &address, 40, vec![]);
                adjust_allowance(state, &address, -15).unwrap();
                let allowance = account(state, &address).allowance;
                assert_eq!(allowance, 25);
                format!("allowance={allowance}")
            }),
            "C017-P-50C3B72D607C6F69" => {
                let reward = reward_vi(&BigInt::from(7), &(BigInt::from(33) * BigInt::from(VI_SCALE)), 2);
                assert_eq!(reward, 65);
                format!("reward={reward}")
            }
            "C017-P-B276FF382F029728" => {
                let vi = accumulate_vi(&BigInt::from(7), 99, 3);
                assert_eq!(vi, BigInt::from(33) * BigInt::from(VI_SCALE) + 7);
                format!("vi={vi}")
            }
            "C017-P-E592EC83261757D4" => {
                let vi = accumulate_vi(&BigInt::from(11), 0, 3);
                assert_eq!(vi, BigInt::from(11));
                format!("vi={vi}")
            }
            "C017-P-89159280DEAA79A5" => {
                let vi = accumulate_vi(&BigInt::from(0), 100, 4);
                assert_eq!(vi, BigInt::from(25) * BigInt::from(VI_SCALE));
                format!("vi={vi}")
            }
            "C017-P-4F3BB21AA968AD23" => {
                let distribution = standby_distribution(&[(vec![1], 1), (vec![2], 2)], 90);
                assert_eq!(distribution.iter().map(|x| x.1).collect::<Vec<_>>(), vec![30, 60]);
                "distribution=30:60".to_owned()
            }
            "C017-P-EDAE80DBFFED05F8" => {
                let distribution = standby_distribution(&[(vec![1], 0), (vec![2], 0)], 7);
                assert!(distribution.is_empty());
                "distribution=empty".to_owned()
            }
            "C017-P-C1C10AE73015A5F9" => with_state(|state| {
                let producer = vec![0x41; 21]; save_account(state, &producer, 0, vec![]);
                save_dynamic(state, "ALLOW_TRANSACTION_FEE_POOL", 1); save_dynamic(state, "TRANSACTION_FEE_POOL", 101);
                save_dynamic(state, "CHANGE_DELEGATION", 0);
                let paid = pay_fee_pool_reward(state, &producer, 10).unwrap().unwrap();
                assert_eq!((paid.transaction_fee_reward, paid.pool_after, account(state, &producer).allowance), (10, 91, 10));
                format!("fee={},pool={}", paid.transaction_fee_reward, paid.pool_after)
            }),
            "C017-P-71571190B082ED81" => {
                let (_, reward, allowance) = configured_payment(80, 25, pay_block_reward);
                assert_eq!((allowance, reward), (20, 60));
                format!("allowance={allowance},reward={reward}")
            }
            "C017-T-0676CF68216D8BEA" => with_state(|state| {
                let voter = vec![0x41; 21]; let witness = vec![0x42; 21];
                query_fixture(state, &voter, &witness, 1, 3);
                state.store_put(StoreKind::Delegation, &delegation_key(0, &witness, "vi"), &BigInt::from(0).to_signed_bytes_be()).unwrap();
                state.store_put(StoreKind::Delegation, &delegation_key(1, &witness, "vi"), &(BigInt::from(2) * BigInt::from(VI_SCALE)).to_signed_bytes_be()).unwrap();
                let reward = query_reward(state, &voter).unwrap();
                assert_eq!(reward, 14);
                format!("query={reward}")
            }),
            unknown => panic!("unimplemented retained reward case {unknown}"),
        };
        assert!(!case.operation.is_empty() && case.parameters.is_object());
        assert_eq!(result, case.expected, "{}", case.case_id);
        println!("{}={result}", case.case_id);
        executed.push((case.case_id, result));
    }
    assert_eq!(executed.len(), retained.len());
}
