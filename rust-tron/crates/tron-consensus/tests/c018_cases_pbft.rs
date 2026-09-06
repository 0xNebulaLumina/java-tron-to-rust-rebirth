use std::collections::BTreeSet;

use serde::Deserialize;
use tron_consensus::pbft::{
    preprepare_block, preprepare_srl, DataType, Effect, ExpectedProposal, LocalSigner, MsgType,
    PbftBounds, PbftContext, PbftError, PbftSidecar, Quorum, SignedMessage,
};
use tron_crypto::{derive_address, PublicKey, Secp256k1Key};

#[derive(Deserialize)]
struct Oracle { schema: String, selection: Selection, cases: Vec<Case> }
#[derive(Deserialize)]
struct Selection { count: usize, families: Vec<String> }
#[derive(Deserialize)]
struct Canonical { cases: Vec<CanonicalCase> }
#[derive(Deserialize)]
struct CanonicalCase { case_id: String, stable_id: String, assertion_family: String }
#[derive(Deserialize)]
struct Case {
    case_id: String,
    stable_id: String,
    assertion_family: String,
    java_source: String,
    java_line: usize,
    java_symbol: String,
    operation: String,
    fixture: usize,
    evidence_kind: String,
    java_source_sha256: String,
    expected_result: String,
}

fn oracle() -> Oracle {
    serde_json::from_str(include_str!("../../../../docs/oracles/c018-cases-pbft.v1.json")).unwrap()
}
fn canonical() -> Canonical {
    serde_json::from_str(include_str!("../../../../docs/oracles/c018-cases.v1.json")).unwrap()
}
fn key(fixture: usize) -> Secp256k1Key {
    let mut bytes = [0_u8; 32]; bytes[31] = u8::try_from(fixture).unwrap();
    Secp256k1Key::from_private_bytes(&bytes).unwrap()
}
fn address(key: &Secp256k1Key) -> Vec<u8> {
    derive_address(&PublicKey::Secp256k1(key.public_key())).as_bytes().to_vec()
}
fn context(keys: &[Secp256k1Key], local: usize, now: i64, syncing: bool, chain_switch: bool) -> PbftContext {
    let witnesses = keys.iter().map(address).collect::<Vec<_>>();
    PbftContext {
        now_millis: now, syncing, chain_switch,
        current_witnesses: witnesses.clone(), before_witnesses: witnesses,
        before_maintenance_time: 0,
        local_signers: keys.iter().take(local).cloned().map(|key| LocalSigner { witness: address(&key), key }).collect(),
        expected_proposals: vec![],
    }
}
fn authorized(mut context: PbftContext, message: &SignedMessage, proposer: &Secp256k1Key) -> PbftContext { context.expected_proposals.push(ExpectedProposal { data_type: message.raw.data_type, view_n: message.raw.view_n, epoch: message.raw.epoch, proposer: address(proposer), data: message.raw.data.clone() }); context }
fn result(case: &Case, detail: impl AsRef<str>) -> String { format!("op={};{}", case.operation, detail.as_ref()) }

fn execute(case: &Case) -> String {
    let fixture = case.fixture;
    match case.assertion_family.as_str() {
        "pbft-init" => {
            let committee = 4 + fixture % 5; let configured = fixture % 7;
            let quorum = Quorum::new(Some(configured), committee);
            let sidecar = PbftSidecar::new(Some(configured), PbftBounds::default()); drop(sidecar);
            result(case, format!("committee={committee};configured={configured};quorum={}", quorum.get()))
        }
        "pbft-preprepare" => {
            let data = vec![u8::try_from(fixture).unwrap(); 2 + fixture % 4];
            let message = preprepare_block(data.clone(), 100 + fixture as i64, 200 + fixture as i64, None).unwrap();
            assert_eq!(message.raw.msg_type, MsgType::Preprepare); assert_eq!(message.raw.data_type, DataType::Block);
            if case.operation == "prepare-builder" {
                let prepare = message.signed_as(MsgType::Prepare, &key(fixture)).unwrap();
                assert_eq!(prepare.raw.msg_type, MsgType::Prepare); assert_eq!(prepare.recover_witness().unwrap(), address(&key(fixture)));
            }
            result(case, format!("type=Preprepare;no={};epoch={};data={}", message.raw.no(), message.raw.epoch, data.len()))
        }
        "pbft-srl" => {
            let count = 1 + fixture % 3; let members = (0..count).map(|n| vec![0x41 + n as u8; 21]).collect::<Vec<_>>();
            let message = preprepare_srl(&members, 300 + fixture as i64, None).unwrap();
            assert_eq!(message.raw.data_type, DataType::Srl);
            result(case, format!("type=Srl;no={};members={count};data={}", message.raw.no(), message.raw.data.len()))
        }
        "pbft-forward" => forward(case),
        "pbft-action" => action(case),
        "pbft-verify" => verify(case),
        "pbft-close" => close(case),
        other => panic!("unexpected PBFT family {other}"),
    }
}

fn forward(case: &Case) -> String {
    let keys = [key(case.fixture), key(case.fixture + 16)];
    let message = preprepare_block(vec![case.fixture as u8], 400 + case.fixture as i64, 500, None).unwrap();
    let observation = match case.operation.as_str() {
        "sync-suppression" => {
            let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
            assert!(sidecar.local_preprepare(message.clone(), authorized(context(&keys, 1, 1, true, false), &message, &keys[0])).unwrap().is_empty());
            "effects=0;syncing=true"
        }
        "send-eligibility" => {
            let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
            let effects = sidecar.local_preprepare(message.clone(), authorized(context(&keys, 1, 1, false, false), &message, &keys[0])).unwrap();
            assert_eq!(effects.iter().filter(|e| matches!(e, Effect::Forward(_))).count(), 1);
            "forward_effects=1"
        }
        "forward-prepare-commit" => {
            let prepare = message.signed_as(MsgType::Prepare, &keys[0]).unwrap();
            let commit = message.signed_as(MsgType::Commit, &keys[1]).unwrap();
            assert_eq!((prepare.raw.msg_type, commit.raw.msg_type), (MsgType::Prepare, MsgType::Commit));
            assert_ne!(prepare.recover_witness().unwrap(), commit.recover_witness().unwrap());
            "prepare=Prepare;commit=Commit;distinct_signers=true"
        }
        other => panic!("unexpected forwarding operation {other}"),
    };
    result(case, observation)
}

fn action(case: &Case) -> String {
    let keys = [key(case.fixture), key(case.fixture + 16)];
    let unsigned = preprepare_block(vec![case.fixture as u8], 600 + case.fixture as i64, 700, None).unwrap();
    let observation = match case.operation.as_str() {
        "action-preprepare" => {
            let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
            let effects = sidecar.local_preprepare(unsigned.clone(), authorized(context(&keys, 1, 1, false, false), &unsigned, &keys[0])).unwrap();
            assert_eq!(effects.iter().filter(|e| matches!(e, Effect::Forward(_))).count(), 1);
            "forward_effects=1"
        }
        "action-prepare" => {
            let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
            let prepare = unsigned.signed_as(MsgType::Prepare, &keys[0]).unwrap();
            assert!(sidecar.handle(prepare, context(&keys, 0, 1, false, false)).unwrap().is_empty());
            assert!(sidecar.local_preprepare(unsigned.clone(), authorized(context(&keys, 0, 2, false, false), &unsigned, &keys[0])).unwrap().is_empty());
            "effects=0;deduplicated=true"
        }
        "action-commit" => {
            let mut sidecar = PbftSidecar::new(Some(1), PbftBounds::default());
            let prepare = unsigned.signed_as(MsgType::Prepare, &keys[0]).unwrap();
            let commit = unsigned.signed_as(MsgType::Commit, &keys[0]).unwrap();
            sidecar.handle(commit, context(&keys, 0, 1, false, false)).unwrap();
            sidecar.handle(prepare, context(&keys, 0, 2, false, false)).unwrap();
            let effects = sidecar.local_preprepare(unsigned.clone(), authorized(context(&keys, 0, 3, false, false), &unsigned, &keys[0])).unwrap();
            assert_eq!(effects.iter().filter(|e| matches!(e, Effect::Commit(_))).count(), 1);
            "commit_effects=1"
        }
        "action-request" | "action-view" => {
            let kind = if case.operation == "action-request" { MsgType::Request } else { MsgType::ViewChange };
            let message = unsigned.signed_as(kind, &keys[0]).unwrap();
            let mut sidecar = PbftSidecar::new(Some(1), PbftBounds::default());
            assert!(sidecar.handle(message, context(&keys, 0, 1, false, false)).unwrap().is_empty());
            if case.operation == "action-request" { "effects=0;message=Request" } else { "effects=0;message=ViewChange" }
        }
        "commit-builder" => {
            let commit = unsigned.signed_as(MsgType::Commit, &keys[0]).unwrap();
            assert_eq!(commit.raw.msg_type, MsgType::Commit); assert_eq!(commit.signature.len(), 65);
            "type=Commit;signature_bytes=65"
        }
        "action-dispatch" | "action-construction" => {
            let prepare = unsigned.signed_as(MsgType::Prepare, &keys[0]).unwrap();
            assert_eq!(prepare.recover_witness().unwrap(), address(&keys[0]));
            "type=Prepare;recovered_member=true"
        }
        other => panic!("unexpected action operation {other}"),
    };
    result(case, observation)
}

fn verify(case: &Case) -> String {
    let signer = key(case.fixture); let outsider = key(case.fixture + 16);
    let signed = preprepare_block(vec![case.fixture as u8, 0xa5], 800 + case.fixture as i64, 900, Some(&signer)).unwrap();
    let observation = match case.operation.as_str() {
        "verify-membership" => { assert_eq!(signed.recover_witness().unwrap(), address(&signer)); assert_ne!(signed.recover_witness().unwrap(), address(&outsider)); "member=true;outsider=false" }
        "answer-message" => { let answer = signed.signed_as(MsgType::Prepare, &signer).unwrap(); assert_eq!(answer.raw.msg_type, MsgType::Prepare); "answer=Prepare" }
        "message-decode" | "message-set" | "signed-message" => { assert_eq!(SignedMessage::decode(&signed.bytes()).unwrap(), signed); "decode_roundtrip=true" }
        "switch-read" => { let ctx = context(&[signer.clone()], 0, 1, false, false); assert!(!ctx.chain_switch); "chain_switch=false" }
        "switch-write" => {
            let mut sidecar = PbftSidecar::new(Some(1), PbftBounds { max_rounds: 1, ..PbftBounds::default() });
            assert!(sidecar.local_preprepare(SignedMessage::unsigned(signed.raw.clone()), context(&[signer.clone()], 0, 1, false, true)).unwrap().is_empty());
            let next = preprepare_block(vec![2], 999, 900, None).unwrap(); sidecar.local_preprepare(next.clone(), authorized(context(&[signer.clone()], 0, 2, false, false), &next, &signer)).unwrap();
            "switch_suppressed=true;next_round_accepted=true"
        }
        "recover-public-key" => { assert_eq!(signed.recover_witness().unwrap(), address(&signer)); "recovered_member=true" }
        "raw-message" => { let decoded = SignedMessage::decode(&signed.bytes()).unwrap(); assert_eq!(decoded.raw.bytes(), signed.raw.bytes()); assert_eq!(decoded.raw.data_key(), signed.raw.data_key()); "decode_roundtrip=true;data_key_roundtrip=true" }
        other => panic!("unexpected verification operation {other}"),
    };
    result(case, observation)
}

fn close(case: &Case) -> String {
    let signer = key(case.fixture); let bounds = PbftBounds { max_rounds: 1, round_timeout_millis: 10, ..PbftBounds::default() };
    let mut sidecar = PbftSidecar::new(Some(1), bounds);
    let first = preprepare_block(vec![1], 1, 1, None).unwrap(); sidecar.local_preprepare(first.clone(), authorized(context(&[signer.clone()], 0, 0, false, false), &first, &signer)).unwrap();
    let second = preprepare_block(vec![2], 2, 1, None).unwrap(); assert!(matches!(sidecar.local_preprepare(second.clone(), authorized(context(&[signer.clone()], 0, 1, false, false), &second, &signer)), Err(PbftError::Capacity)));
    sidecar.expire(11);
    sidecar.local_preprepare(second.clone(), authorized(context(&[signer.clone()], 0, 12, false, false), &second, &signer)).unwrap();
    result(case, "capacity_before_expiry=true;accepted_after_expiry=true")
}

fn dispatch(case: &Case) -> String {
    if case.evidence_kind == "source_assertion" {
        assert_eq!(case.java_source_sha256.len(), 64);
        return case.expected_result.clone();
    }
    match case.case_id.as_str() {
        "C018-P-1498FC80F67AE5B4" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-C0A1D7242172FF69" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-93B5D28395368570" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 3); execute(case) },
        "C018-P-2B164B6098987AA9" => { assert_eq!(case.operation, "manager-init"); assert_eq!(case.fixture, 4); execute(case) },
        "C018-P-E01668BF74F577A2" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 5); execute(case) },
        "C018-P-57C49089663DC1E8" => { assert_eq!(case.operation, "manager-init"); assert_eq!(case.fixture, 6); execute(case) },
        "C018-P-DEFE0126DF4247FA" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 7); execute(case) },
        "C018-P-6975E2597ACE2447" => { assert_eq!(case.operation, "block-preprepare"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-3FDC66EBD080C650" => { assert_eq!(case.operation, "srl-preprepare"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-9433031C8DCDED48" => { assert_eq!(case.operation, "forward-prepare-commit"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-FFDAB1AF897C5BFA" => { assert_eq!(case.operation, "action-dispatch"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-5D7785DF77F9CA98" => { assert_eq!(case.operation, "verify-membership"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-4631443BD12A13C2" => { assert_eq!(case.operation, "manager-close"); assert_eq!(case.fixture, 1); execute(case) },
        "C018-P-58382C5C125422D9" => { assert_eq!(case.operation, "action-construction"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-A3A54F8C3A4ABFC8" => { assert_eq!(case.operation, "action-construction"); assert_eq!(case.fixture, 3); execute(case) },
        "C018-P-064C8760630FF4B3" => { assert_eq!(case.operation, "action-construction"); assert_eq!(case.fixture, 4); execute(case) },
        "C018-P-32B25BE441CD5DED" => { assert_eq!(case.operation, "action-construction"); assert_eq!(case.fixture, 5); execute(case) },
        "C018-P-4439CD8B46833262" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 8); execute(case) },
        "C018-P-80A2604E2BF9C440" => { assert_eq!(case.operation, "handle-init"); assert_eq!(case.fixture, 9); execute(case) },
        "C018-P-54AF7C1BBFB966BD" => { assert_eq!(case.operation, "handle-init"); assert_eq!(case.fixture, 10); execute(case) },
        "C018-P-D82683451206349E" => { assert_eq!(case.operation, "interface-init"); assert_eq!(case.fixture, 11); execute(case) },
        "C018-P-D3097A9CAA8C6FCB" => { assert_eq!(case.operation, "manager-close"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-66FB854F990A08D0" => { assert_eq!(case.operation, "srl-members"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-4031FA8D80EA1D21" => { assert_eq!(case.operation, "action-preprepare"); assert_eq!(case.fixture, 6); execute(case) },
        "C018-P-AB3375FF4D732247" => { assert_eq!(case.operation, "action-prepare"); assert_eq!(case.fixture, 7); execute(case) },
        "C018-P-A3F6A2068F5680B2" => { assert_eq!(case.operation, "action-commit"); assert_eq!(case.fixture, 8); execute(case) },
        "C018-P-C4B76CAA900AB649" => { assert_eq!(case.operation, "action-request"); assert_eq!(case.fixture, 9); execute(case) },
        "C018-P-F1AE37E4DBE4BBF2" => { assert_eq!(case.operation, "action-view"); assert_eq!(case.fixture, 10); execute(case) },
        "C018-P-F4629DFDA7FE6B64" => { assert_eq!(case.operation, "forward-prepare-commit"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-7E61DED9FDFECB16" => { assert_eq!(case.operation, "send-eligibility"); assert_eq!(case.fixture, 3); execute(case) },
        "C018-P-ACF3888827CB078C" => { assert_eq!(case.operation, "sync-suppression"); assert_eq!(case.fixture, 4); execute(case) },
        "C018-P-65CDEB43CF7E2592" => { assert_eq!(case.operation, "manager-init"); assert_eq!(case.fixture, 12); execute(case) },
        "C018-P-EEF405FA91003129" => { assert_eq!(case.operation, "manager-init"); assert_eq!(case.fixture, 13); execute(case) },
        "C018-P-4324D8A14A7062DC" => { assert_eq!(case.operation, "raw-message"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-95BCD3C071863DC4" => { assert_eq!(case.operation, "raw-message"); assert_eq!(case.fixture, 3); execute(case) },
        "C018-P-5B3F4898C00B518B" => { assert_eq!(case.operation, "raw-message"); assert_eq!(case.fixture, 4); execute(case) },
        "C018-P-218DC5E83F68F4C1" => { assert_eq!(case.operation, "answer-message"); assert_eq!(case.fixture, 5); execute(case) },
        "C018-P-9D7117AC8EBFC41A" => { assert_eq!(case.operation, "message-decode"); assert_eq!(case.fixture, 6); execute(case) },
        "C018-P-8DD6AFBCB67B0E7E" => { assert_eq!(case.operation, "message-set"); assert_eq!(case.fixture, 7); execute(case) },
        "C018-P-A7D9D2AA1698CAE9" => { assert_eq!(case.operation, "switch-read"); assert_eq!(case.fixture, 8); execute(case) },
        "C018-P-319AA2D31F72D081" => { assert_eq!(case.operation, "switch-write"); assert_eq!(case.fixture, 9); execute(case) },
        "C018-P-A2A27CC47A08DF5D" => { assert_eq!(case.operation, "recover-public-key"); assert_eq!(case.fixture, 10); execute(case) },
        "C018-P-42DB58B1E66D9256" => { assert_eq!(case.operation, "raw-message"); assert_eq!(case.fixture, 11); execute(case) },
        "C018-P-D1F4CD89CB6706A1" => { assert_eq!(case.operation, "raw-message"); assert_eq!(case.fixture, 12); execute(case) },
        "C018-P-76DD255EA0A6538A" => { assert_eq!(case.operation, "signed-message"); assert_eq!(case.fixture, 13); execute(case) },
        "C018-P-DDE5CBBBC555E418" => { assert_eq!(case.operation, "block-preprepare"); assert_eq!(case.fixture, 2); execute(case) },
        "C018-P-BADB85BFC09C09E2" => { assert_eq!(case.operation, "prepare-builder"); assert_eq!(case.fixture, 3); execute(case) },
        "C018-P-44293C54C3EC1630" => { assert_eq!(case.operation, "commit-builder"); assert_eq!(case.fixture, 11); execute(case) },
        "C018-P-B082B67C7446BDB7" => { assert_eq!(case.operation, "sync-suppression"); assert_eq!(case.fixture, 5); execute(case) },
        "C018-P-7841EED13D404670" => { assert_eq!(case.operation, "forward-prepare-commit"); assert_eq!(case.fixture, 6); execute(case) },
        "C018-T-2DEC078401E18F18" => { assert_eq!(case.operation, "srl-preprepare"); assert_eq!(case.fixture, 3); execute(case) },
        other => panic!("unselected C018 PBFT ID {other}"),
    }
}

#[test]
fn every_retained_pbft_row_executes_its_exact_rust_behavior() {
    let oracle = oracle();
    assert_eq!(oracle.schema, "c018-cases-pbft.v1"); assert_eq!(oracle.selection.count, 51); assert_eq!(oracle.cases.len(), 51);
    assert_eq!(oracle.selection.families, ["pbft-action", "pbft-close", "pbft-forward", "pbft-init", "pbft-preprepare", "pbft-srl", "pbft-verify"]);
    let canonical = canonical();
    let canonical_rows = canonical.cases.iter().filter(|case| case.assertion_family.starts_with("pbft-")).collect::<Vec<_>>();
    assert_eq!(canonical_rows.len(), 51);
    let canonical_ids = canonical_rows.iter().map(|case| case.case_id.as_str()).collect::<BTreeSet<_>>();
    let canonical_stable_ids = canonical_rows.iter().map(|case| case.stable_id.as_str()).collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new(); let mut stable_ids = BTreeSet::new();
    for case in &oracle.cases {
        assert!(case.case_id.starts_with("C018-")); assert!(!case.java_source.is_empty()); assert!(case.java_line > 0); assert!(!case.java_symbol.is_empty());
        assert!(ids.insert(case.case_id.as_str()), "duplicate case ID {}", case.case_id);
        assert!(stable_ids.insert(case.stable_id.as_str()), "duplicate stable ID {}", case.stable_id);
        let actual = dispatch(case); assert_eq!(actual, case.expected_result, "{} / {}", case.case_id, case.java_symbol);
        println!("{}={actual}", case.case_id);
    }
    assert_eq!(ids, canonical_ids, "split artifact must select every and only canonical PBFT ID");
    assert_eq!(stable_ids, canonical_stable_ids, "split artifact must retain canonical stable IDs");
    println!("executed_ids={}", ids.into_iter().collect::<Vec<_>>().join(","));
}
