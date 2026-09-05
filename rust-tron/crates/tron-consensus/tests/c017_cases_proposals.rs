use std::{collections::{BTreeMap, BTreeSet}, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use prost::Message;
use serde::Deserialize;
use tron_consensus::{approval_threshold, has_most_approvals, process_expired_proposals, ConsensusRead, ParameterRule, StateError, StateFacade};
use tron_protocol::protocol::{proposal::State, Proposal};
use tron_state::{dynamic, value, SessionManager, StateStore, StoreKind};
use tron_storage::{OpenRequirements, StorageIdentity, StorageManager};

#[derive(Deserialize)]
struct Manifest { cases: Vec<Case> }
#[derive(Deserialize)]
struct Case { case_id: String, case_kind: String, evidence: String, parameters: Parameters, scenario: String, proposal_id: i64, expected_result: String }
#[derive(Deserialize)]
struct Parameters { java_source: String, java_line: usize, java_symbol: String, owning_item: String, acceptance_gate: String }

fn manifest() -> Manifest { serde_json::from_str(include_str!("../../../../docs/oracles/c017-cases-proposals.v1.json")).unwrap() }
fn path(id: i64) -> PathBuf { std::env::temp_dir().join(format!("c017-proposal-{}-{id}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())) }
fn manager() -> StorageManager { StorageManager::new(OpenRequirements { identity: StorageIdentity { network: "c017-proposals".into(), genesis: "00".into() }, schema_version: 1, backend: "rustlog".into(), backend_format: "rustlog-v1".into(), supported_features: vec!["rustlog-v1".into()] }) }
fn address(byte: u8) -> Vec<u8> { [vec![0x41], vec![byte; 20]].concat() }
fn proposal(id: i64, expiration_time: i64, state: State, approvals: &[Vec<u8>], parameters: &[(i64, i64)]) -> Proposal { Proposal { proposal_id: id, expiration_time, state: state as i32, approvals: approvals.to_vec(), parameters: parameters.iter().copied().collect(), ..Default::default() } }
fn put_proposal(facade: &StateFacade<'_>, proposal: &Proposal) { facade.store_put(StoreKind::Proposal, &proposal.proposal_id.to_be_bytes(), &proposal.encode_to_vec()).unwrap(); }
fn rules() -> BTreeMap<i64, ParameterRule> { BTreeMap::from([
    (1, ParameterRule { dynamic: "ENERGY_FEE", depends_on: None, one_shot: false }),
    (2, ParameterRule { dynamic: "ALLOW_CREATION_OF_CONTRACTS", depends_on: None, one_shot: true }),
    (3, ParameterRule { dynamic: "CONSENSUS_LOGIC_OPTIMIZATION", depends_on: Some((2, 1)), one_shot: false }),
]) }

fn execute(case: &Case) -> String {
    assert!(case.case_kind.starts_with("java-symbol:"));
    assert!(!case.evidence.is_empty());
    assert!(case.parameters.java_source.contains("ProposalController") || case.parameters.java_source.contains("ProposalService"));
    assert_eq!(case.parameters.owning_item == "C017.05" || case.parameters.owning_item == "C017.07", true);
    assert_eq!(case.parameters.acceptance_gate, "C017.V");
    assert!(case.parameters.java_line > 0);
    assert!(!case.parameters.java_symbol.is_empty());
    assert!(case.proposal_id > 0, "{} used the forbidden zero-proposal shortcut", case.case_id);

    let directory = path(case.proposal_id);
    let root = StateStore::new(manager().open_store(&directory).unwrap());
    let sessions = SessionManager::new(root.clone());
    let session = sessions.build_session().unwrap();
    let facade = StateFacade::new(&session);
    let active: Vec<_> = (0..10).map(address).collect();
    facade.save_active_witnesses(&active).unwrap();
    facade.save_dynamic_long("LATEST_PROPOSAL_NUM", case.proposal_id).unwrap();
    facade.save_dynamic_long("NEXT_MAINTENANCE_TIME", 1_000).unwrap();
    let at = active[..approval_threshold(active.len())].to_vec();
    let below = active[..approval_threshold(active.len()) - 1].to_vec();

    match case.scenario.as_str() {
        "threshold_at" => { let p = proposal(case.proposal_id, 1_000, State::Pending, &at, &[]); assert!(has_most_approvals(&p, &active)); assert_eq!(approval_threshold(active.len()), 7); put_proposal(&facade, &p); assert_eq!(process_expired_proposals(&facade, &rules()).unwrap().history[0].active_approvals, 7); }
        "threshold_below" => { let p = proposal(case.proposal_id, 1_000, State::Pending, &below, &[]); assert!(!has_most_approvals(&p, &active)); put_proposal(&facade, &p); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!((scan.history[0].approved, scan.history[0].active_approvals), (false, 6)); }
        "expired_apply" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(1, 420)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.history[0].writes, vec![("ENERGY_FEE", 420)]); assert_eq!(facade.dynamic_long("ENERGY_FEE").unwrap(), 420); }
        "expired_disapprove" => { put_proposal(&facade, &proposal(case.proposal_id, 1_000, State::Pending, &below, &[(1, 9)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert!(!scan.history[0].approved); assert!(facade.dynamic_long("ENERGY_FEE").is_err()); }
        "future_skip" => { put_proposal(&facade, &proposal(case.proposal_id, 1_001, State::Pending, &at, &[(1, 8)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.examined, vec![case.proposal_id]); assert!(scan.history.is_empty()); }
        "canceled_skip" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Canceled, &at, &[(1, 8)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.examined, vec![case.proposal_id]); assert!(scan.history.is_empty()); }
        "processed_break" => { put_proposal(&facade, &proposal(case.proposal_id - 1, 999, State::Pending, &at, &[(1, 8)])); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Approved, &at, &[])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.examined, vec![case.proposal_id]); assert!(scan.history.is_empty()); }
        "deleted_gap" => { let p = proposal(case.proposal_id, 999, State::Pending, &at, &[]); put_proposal(&facade, &p); facade.store_delete(StoreKind::Proposal, &case.proposal_id.to_be_bytes()).unwrap(); put_proposal(&facade, &proposal(case.proposal_id - 1, 999, State::Pending, &below, &[])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.examined, vec![case.proposal_id - 1]); assert_eq!(scan.history[0].id, case.proposal_id - 1); }
        "dependency_apply" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(2, 1), (3, 77)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.history[0].writes, vec![("ALLOW_CREATION_OF_CONTRACTS", 1), ("CONSENSUS_LOGIC_OPTIMIZATION", 77)]); }
        "dependency_skip" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(2, 0), (3, 77)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.history[0].writes, vec![("ALLOW_CREATION_OF_CONTRACTS", 0)]); assert!(facade.dynamic_long("CONSENSUS_LOGIC_OPTIMIZATION").is_err()); }
        "oneshot_skip" => { facade.save_dynamic_long("ALLOW_CREATION_OF_CONTRACTS", 1).unwrap(); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(2, 9)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert!(scan.history[0].writes.is_empty()); assert_eq!(facade.dynamic_long("ALLOW_CREATION_OF_CONTRACTS").unwrap(), 1); }
        "unknown_parameter" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(999, 4)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert!(scan.history[0].approved); assert!(scan.history[0].writes.is_empty()); }
        "invalid_protobuf" => { facade.store_put(StoreKind::Proposal, &case.proposal_id.to_be_bytes(), &[0xff]).unwrap(); let error = process_expired_proposals(&facade, &rules()).unwrap_err(); assert!(matches!(error, StateError::InvalidProtobuf { store: StoreKind::Proposal, .. })); }
        "missing_maintenance" => { facade.store_delete(StoreKind::DynamicProperties, dynamic::key("NEXT_MAINTENANCE_TIME").unwrap()).unwrap(); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[])); assert!(matches!(process_expired_proposals(&facade, &rules()), Err(StateError::MissingDynamic("NEXT_MAINTENANCE_TIME")))); }
        "invalid_schedule" => { facade.store_put(StoreKind::WitnessSchedule, value::ACTIVE_WITNESSES_KEY, &[1, 2]).unwrap(); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[])); assert!(matches!(process_expired_proposals(&facade, &rules()), Err(StateError::InvalidSchedule(_)))); }
        "multiple_history" => { put_proposal(&facade, &proposal(case.proposal_id - 1, 999, State::Pending, &below, &[])); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.history.iter().map(|h| (h.id, h.approved)).collect::<Vec<_>>(), vec![(case.proposal_id, true), (case.proposal_id - 1, false)]); }
        "inactive_approval" => { let mut approvals = at[..6].to_vec(); approvals.push(address(99)); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &approvals, &[])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!((scan.history[0].active_approvals, scan.history[0].approved), (6, false)); }
        "stored_dependency" => { facade.save_dynamic_long("ALLOW_CREATION_OF_CONTRACTS", 1).unwrap(); put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(3, 55)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.history[0].writes, vec![("CONSENSUS_LOGIC_OPTIMIZATION", 55)]); }
        "state_persisted" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[])); process_expired_proposals(&facade, &rules()).unwrap(); let stored = Proposal::decode(facade.store_get(StoreKind::Proposal, &case.proposal_id.to_be_bytes()).unwrap().as_slice()).unwrap(); assert_eq!((stored.proposal_id, stored.state), (case.proposal_id, State::Approved as i32)); }
        "descending_scan" => { put_proposal(&facade, &proposal(case.proposal_id - 2, 999, State::Pending, &at, &[])); put_proposal(&facade, &proposal(case.proposal_id, 1_001, State::Pending, &at, &[])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); assert_eq!(scan.examined, vec![case.proposal_id, case.proposal_id - 2]); assert_eq!(scan.history[0].id, case.proposal_id - 2); }
        "history_writes" => { put_proposal(&facade, &proposal(case.proposal_id, 999, State::Pending, &at, &[(1, 17)])); let scan = process_expired_proposals(&facade, &rules()).unwrap(); let h = &scan.history[0]; assert_eq!((h.id, h.approved, h.active_approvals, h.active_witnesses), (case.proposal_id, true, 7, 10)); assert_eq!(h.writes, vec![("ENERGY_FEE", 17)]); }
        other => panic!("unimplemented proposal scenario {other}"),
    }

    let result = case.scenario.clone();
    drop(facade); drop(session); drop(sessions); drop(root); fs::remove_dir_all(directory).unwrap();
    result
}

#[test]
fn retained_proposal_rows_execute_real_case_table() {
    let manifest = manifest();
    let expected: BTreeSet<_> = [
        "C017-P-749E1A8690D84356", "C017-P-8981DBFD4016CFA3", "C017-P-31C3C20AB7D8655D", "C017-P-E5999C27CF3B93C9", "C017-P-2F9184A98E3191E2", "C017-P-AD6A71BF066B1CF6", "C017-P-B844E270C6ACD2A7", "C017-P-2905B4660F3B19B3", "C017-P-4B26A28BAE9F965A", "C017-P-89389712C6C86999", "C017-P-BCC285AEAD528EDA", "C017-P-CB5949C30676543E", "C017-T-D8452549066F4016", "C017-T-AC1C6B78AF77FF63", "C017-T-5B47F4B48C756788", "C017-T-D7BA4A98A870757F", "C017-T-E4F6DD01435D0BD5", "C017-T-FBE933D938E646CD", "C017-T-8B1D7BEE7C90ECFA", "C017-T-E145ACF825B6C190", "C017-T-82B1D3036D5B9BB3",
    ].into_iter().map(str::to_owned).collect();
    let actual: BTreeSet<_> = manifest.cases.iter().map(|case| case.case_id.clone()).collect();
    assert_eq!(actual, expected);
    assert_eq!(manifest.cases.len(), expected.len(), "duplicate proposal case IDs");
    let executed: BTreeMap<_, _> = manifest.cases.iter().map(|case| { let result=execute(case); assert_eq!(result,case.expected_result,"{}",case.case_id); println!("{}={result}",case.case_id); (case.case_id.clone(), result) }).collect();
    assert_eq!(executed.keys().cloned().collect::<BTreeSet<_>>(), expected);
}
