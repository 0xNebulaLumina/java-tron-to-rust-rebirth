use std::{collections::BTreeSet, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use prost::Message;
use serde::Deserialize;
use tron_consensus::{solidity_position, update_solidity, ConsensusRead, DposSlot, FixedClock, SlotContext, StateFacade};
use tron_protocol::protocol::Witness;
use tron_state::{
    dynamic, evaluate_fork_pass, CheckpointIdentity, CheckpointLimits, CursorPoint, CursorSet,
    CursorView, DynamicProperties, ForkClock, ForkController, ForkPassInput, ForkSchedule,
    ForkVersion, JavaForkMath, StateLifecycle, StateStore, StoreKind,
};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Deserialize)]
struct Oracle {
    schema: String,
    retained_cases: Vec<Case>,
    excluded_owner_prefixes: Vec<String>,
    exclusions_executed: bool,
}

#[derive(Deserialize)]
struct Case {
    case_id: String,
    stable_id: String,
    java_source: String,
    java_line: usize,
    java_symbol: String,
    expected_result: String,
}

fn path(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("c017-solidity-fork-{name}-{}-{nonce}", std::process::id()))
}

fn state(name: &str) -> (PathBuf, StateStore) {
    let directory = path(name);
    let storage = StorageManager::new(OpenRequirements {
        identity: StorageIdentity { network: "c017-solidity-fork".into(), genesis: "00".into() },
        schema_version: 1,
        backend: "rustlog".into(),
        backend_format: "rustlog-v1".into(),
        supported_features: vec!["rustlog-v1".into()],
    });
    (directory.clone(), StateStore::new(storage.open_store(directory).unwrap()))
}

fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn put_long(store: &StateStore, name: &str, value: i64) {
    store.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
}
fn put_int(store: &StateStore, name: &str, value: i32) {
    store.store(StoreKind::DynamicProperties).put(dynamic::key(name).unwrap(), &value.to_be_bytes()).unwrap();
}

struct Schedule(Vec<ForkVersion>);
impl ForkSchedule for Schedule { fn versions(&self) -> &[ForkVersion] { &self.0 } }
struct Clock { number: i64, timestamp: i64 }
impl ForkClock for Clock {
    fn latest_block_number(&self) -> i64 { self.number }
    fn latest_block_timestamp(&self) -> i64 { self.timestamp }
}

#[test]
fn retained_solidity_fork_rows_execute_exact_typed_contracts() {
    let oracle: Oracle = serde_json::from_str(include_str!("../../../../docs/oracles/c017-cases-solidity-fork.v1.json")).unwrap();
    assert_eq!(oracle.schema, "c017-cases-solidity-fork.v1");
    assert_eq!(oracle.excluded_owner_prefixes, ["C018", "C019"]);
    assert!(!oracle.exclusions_executed);

    let exact: BTreeSet<_> = [
        "C017-P-B08564CDFC77C8B4", "C017-P-79CA953FC8080FEB",
        "C017-P-B4CB60E681F95590", "C017-P-0838EB81B529F8D4",
        "C017-P-B9B1A29827EC142B", "C017-P-621AAC2E627C7F21",
        "C017-P-CBE5FFAE67570F58", "C017-P-46BF7018AB0D3600",
    ].into_iter().collect();
    assert_eq!(oracle.retained_cases.iter().map(|case| case.case_id.as_str()).collect::<BTreeSet<_>>(), exact);

    let (directory, root) = state("cases");
    put_long(&root, "LATEST_BLOCK_HEADER_TIMESTAMP", 9_000);
    put_long(&root, "LATEST_BLOCK_HEADER_NUMBER", 40);
    put_long(&root, "LATEST_SOLIDIFIED_BLOCK_NUM", 7);
    put_long(&root, "NEXT_MAINTENANCE_TIME", 10_000);
    put_long(&root, "MAINTENANCE_TIME_INTERVAL", 9_000);
    put_int(&root, "STATE_FLAG", 1);
    let active = vec![address(1), address(2), address(3)];
    root.store(StoreKind::WitnessSchedule).put(tron_state::value::ACTIVE_WITNESSES_KEY, &active.concat()).unwrap();
    for (address, latest_block_num) in active.iter().cloned().zip([4, 20, 9]) {
        let witness = Witness { address: address.clone(), latest_block_num, ..Default::default() };
        root.store(StoreKind::Witness).put(&address, &witness.encode_to_vec()).unwrap();
    }

    let lifecycle = StateLifecycle::new(root.clone(), CheckpointLimits::default());
    let sessions = lifecycle.sessions();
    let solid = CursorPoint { block: 40, identity: CheckpointIdentity::new([40; 32]) };
    lifecycle.checkpoints().record(solid).unwrap();
    let mut head_session = sessions.build_session_enabled().unwrap();
    head_session.store(StoreKind::DynamicProperties).put(dynamic::key("LATEST_BLOCK_HEADER_TIMESTAMP").unwrap(), &12_000_i64.to_be_bytes()).unwrap();
    head_session.store(StoreKind::DynamicProperties).put(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").unwrap(), &44_i64.to_be_bytes()).unwrap();
    head_session.commit().unwrap();
    let head = CursorPoint { block: 44, identity: CheckpointIdentity::new([44; 32]) };
    lifecycle.checkpoints().record(head).unwrap();
    let cursors = CursorSet::new(&sessions, head, Some(solid), None, 0).unwrap();
    let mut working = sessions.build_session_enabled().unwrap();
    let facade = StateFacade::new(&working);
    let properties = DynamicProperties::new(root.store(StoreKind::DynamicProperties));

    let mut executed = Vec::new();
    for case in &oracle.retained_cases {
        assert_eq!(case.stable_id, case.case_id.replacen("C017-P-", "PROD-", 1));
        assert_eq!(case.java_source, "java-tron/consensus/src/main/java/org/tron/consensus/ConsensusDelegate.java");
        let result = match case.case_id.as_str() {
            "C017-P-B08564CDFC77C8B4" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (67, "getLatestBlockHeaderTimestamp"));
                let head_time = i64::from_be_bytes(cursors.head().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_TIMESTAMP").unwrap()).unwrap().try_into().unwrap());
                let solid_time = i64::from_be_bytes(cursors.solidity().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_TIMESTAMP").unwrap()).unwrap().try_into().unwrap());
                assert_eq!((head_time, solid_time), (12_000, 9_000));
                format!("head_timestamp={head_time};solidity_timestamp={solid_time}")
            }
            "C017-P-79CA953FC8080FEB" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (71, "getLatestBlockHeaderNumber"));
                let head_number = i64::from_be_bytes(cursors.head().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").unwrap()).unwrap().try_into().unwrap());
                let solid_number = i64::from_be_bytes(cursors.solidity().store(StoreKind::DynamicProperties).get(dynamic::key("LATEST_BLOCK_HEADER_NUMBER").unwrap()).unwrap().try_into().unwrap());
                assert_eq!((head_number, solid_number), (44, 40));
                format!("head_number={head_number};solidity_number={solid_number}")
            }
            "C017-P-B4CB60E681F95590" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (75, "lastHeadBlockIsMaintenance"));
                let flag = facade.dynamic_int("STATE_FLAG").unwrap();
                let version = ForkVersion { version: 17, hard_fork_time: 10_001, hard_fork_rate: 70 };
                properties.save_fork_stats(17, &[1, 1, 1]).unwrap();
                assert!(evaluate_fork_pass(ForkPassInput { target: version, old_cutoff: 16, latest_block_number: 44, energy_limit_height: 5, latest_block_timestamp: 19_000, maintenance_interval: 9_000, stats: Some(&[1, 1, 1]) }, &JavaForkMath).unwrap());
                format!("state_flag={flag};is_maintenance={}", flag == 1)
            }
            "C017-P-0838EB81B529F8D4" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (79, "getMaintenanceSkipSlots"));
                let slots = DposSlot::new(FixedClock(12_345), SlotContext { genesis_time: 0, head_number: 44, head_time: 9_000, head_is_maintenance: true, maintenance_skip_slots: 2 });
                assert_eq!(slots.time(1).unwrap(), 18_000);
                "maintenance_skip_slots=2".to_owned()
            }
            "C017-P-B9B1A29827EC142B" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (115, "updateNextMaintenanceTime"));
                let next = properties.update_next_maintenance_time(10_000).unwrap();
                assert_eq!(next, 19_000);
                let schedule = Schedule(vec![ForkVersion { version: 17, hard_fork_time: 20_000, hard_fork_rate: 70 }]);
                let clock = Clock { number: 44, timestamp: 19_000 };
                properties.save_fork_stats(17, &[1, 0, 0]).unwrap();
                let controller = ForkController::new(properties.clone(), &schedule, &clock, &JavaForkMath, 5);
                controller.reset(&active).unwrap();
                assert_eq!(properties.fork_stats(17).unwrap(), vec![0; 3]);
                "next_maintenance_time:10000->19000".to_owned()
            }
            "C017-P-621AAC2E627C7F21" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (119, "getNextMaintenanceTime"));
                let next = properties.get_long("NEXT_MAINTENANCE_TIME").unwrap();
                assert_eq!(next, 19_000);
                format!("next_maintenance_time={next}")
            }
            "C017-P-CBE5FFAE67570F58" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (123, "getLatestSolidifiedBlockNum"));
                let latest = facade.dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap();
                assert_eq!(latest, 7);
                format!("latest_solidified={latest}")
            }
            "C017-P-46BF7018AB0D3600" => {
                assert_eq!((case.java_line, case.java_symbol.as_str()), (127, "saveLatestSolidifiedBlockNum"));
                let update = update_solidity(&facade).unwrap();
                assert_eq!(solidity_position(3), 0);
                assert_eq!((update.position, update.previous, update.candidate, update.applied), (0, 7, 4, 7));
                assert_eq!(facade.dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM").unwrap(), 7);
                "latest_blocks=[4,9,20];position=0;previous=7;candidate=4;applied=7".to_owned()
            }
            other => panic!("unbound retained solidity/fork case {other}"),
        };
        assert_eq!(result, case.expected_result);
        println!("{}={result}", case.case_id);
        executed.push(case.case_id.as_str());
    }
    let executed = executed.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(executed, exact);
    println!("executed_ids={}", executed.into_iter().collect::<Vec<_>>().join(","));

    working.revoke().unwrap();
    drop(cursors);
    drop(lifecycle);
    fs::remove_dir_all(directory).unwrap();
}
