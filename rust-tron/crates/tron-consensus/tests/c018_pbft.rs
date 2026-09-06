use std::{collections::BTreeMap, sync::{Arc, Barrier, Mutex}, thread};

use prost::Message;
use tron_consensus::pbft::*;
use tron_crypto::{derive_address, Secp256k1Key};
use tron_protocol::protocol::PbftCommitResult;
use tron_state::StoreKind;

fn key(n: u8) -> Secp256k1Key { let mut bytes = [0u8; 32]; bytes[31] = n; Secp256k1Key::from_private_bytes(&bytes).unwrap() }
fn address(key: &Secp256k1Key) -> Vec<u8> { derive_address(&tron_crypto::PublicKey::Secp256k1(key.public_key())).as_bytes().to_vec() }
fn context(keys: &[Secp256k1Key], now: i64) -> PbftContext { let witnesses: Vec<_> = keys.iter().map(address).collect(); PbftContext { now_millis: now, syncing: false, chain_switch: false, current_witnesses: witnesses.clone(), before_witnesses: witnesses.clone(), before_maintenance_time: 0, local_signers: keys.iter().cloned().map(|key| LocalSigner { witness: address(&key), key }).collect(), expected_proposals: vec![] } }
fn passive_context(keys: &[Secp256k1Key], now: i64) -> PbftContext { PbftContext { local_signers: vec![], ..context(keys, now) } }
fn proposal_context(keys: &[Secp256k1Key], now: i64, message: &SignedMessage) -> PbftContext { let mut context = passive_context(keys, now); context.expected_proposals.push(ExpectedProposal { data_type: message.raw.data_type, view_n: message.raw.view_n, epoch: message.raw.epoch, proposer: address(&keys[0]), data: message.raw.data.clone() }); context }
fn authority_context(keys: &[Secp256k1Key], now: i64, message: &SignedMessage, proposer: usize, local: bool) -> PbftContext { let mut context = if local { context(keys, now) } else { passive_context(keys, now) }; context.expected_proposals.push(ExpectedProposal { data_type: message.raw.data_type, view_n: message.raw.view_n, epoch: message.raw.epoch, proposer: address(&keys[proposer]), data: message.raw.data.clone() }); context }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

#[test]
fn pinned_java_raw_message_and_signature_vectors_are_exact() {
    let key = key(1);
    let unsigned = preprepare_block(b"block-id".to_vec(), 7, 42, None).unwrap();
    assert_eq!(hex(&unsigned.raw.bytes()), "08021807202a2a08626c6f636b2d6964");
    assert_eq!(hex(&unsigned.bytes()), "0a1008021807202a2a08626c6f636b2d6964");
    let signed = preprepare_block(b"block-id".to_vec(), 7, 42, Some(&key)).unwrap();
    assert_eq!(hex(&signed.bytes()), "0a1008021807202a2a08626c6f636b2d696412419c55482de9d85dd9d562839b664f032fcf1b96ab3b8f4e5d263da340ce8edd5153002427fe312fc4a8d25529e8cda2a910ad12badb106e55ecc58b056f3e657500");
    assert_eq!(signed.recover_witness().unwrap(), address(&key));
    assert_eq!(SignedMessage::decode(&signed.bytes()).unwrap(), signed);
    let srl = preprepare_srl(&[vec![0x41; 21], vec![0x42; 21]], 99, None).unwrap();
    assert_eq!(hex(&srl.raw.bytes()), "08021001186320632a2e0a154141414141414141414141414141414141414141410a15424242424242424242424242424242424242424242");
    assert_eq!(srl.raw.no(), "99_1");
}

#[test]
fn quorum_defaults_clamps_and_has_exact_boundaries() {
    assert_eq!(Quorum::new(None, 27).get(), 19); assert_eq!(Quorum::new(None, 7).get(), 7);
    assert_eq!(Quorum::new(Some(0), 27).get(), 1); assert_eq!(Quorum::new(Some(99), 27).get(), 27);
    let quorum = Quorum::new(Some(19), 27); assert!(!quorum.reached(18)); assert!(quorum.reached(19)); assert!(quorum.reached(20));
}

#[test]
fn network_requires_authenticated_witness_even_for_preprepare() {
    let keys = [key(1), key(2), key(3)]; let mut sidecar = PbftSidecar::new(Some(3), PbftBounds::default());
    let unsigned = preprepare_block(vec![1], 9, 9, None).unwrap();
    assert!(matches!(sidecar.handle(unsigned.clone(), context(&keys, 1)), Err(PbftError::MissingSignature)));
    assert!(sidecar.local_preprepare(unsigned.clone(), proposal_context(&keys, 2, &unsigned)).unwrap().is_empty());
    let outsider = key(9); let outsider_message = preprepare_block(vec![1], 10, 10, Some(&outsider)).unwrap();
    assert!(matches!(sidecar.handle(outsider_message, context(&keys, 3)), Err(PbftError::NonWitness)));
    let mut malformed = preprepare_block(vec![2], 11, 11, Some(&keys[0])).unwrap(); malformed.signature = vec![0xff; 64];
    assert!(matches!(sidecar.handle(malformed, context(&keys, 4)), Err(PbftError::Crypto(_))));
    let prepare = preprepare_block(vec![3], 12, 12, None).unwrap().signed_as(MsgType::Prepare, &keys[0]).unwrap();
    assert!(matches!(sidecar.local_preprepare(prepare, context(&keys, 5)), Err(PbftError::LocalPreprepareOnly)));
}

#[test]
fn three_phase_quorum_commits_only_at_exact_boundary() {
    let keys = [key(1), key(2), key(3)]; let mut sidecar = PbftSidecar::new(Some(3), PbftBounds::default());
    let preprepare = preprepare_block(vec![0xab; 32], 123, 5, Some(&keys[0])).unwrap();
    assert!(sidecar.handle(preprepare.clone(), proposal_context(&keys, 1_000, &preprepare)).unwrap().is_empty());
    for key in &keys[..2] { let prepare = preprepare.signed_as(MsgType::Prepare, key).unwrap(); assert!(sidecar.handle(prepare, passive_context(&keys, 1_001)).unwrap().is_empty()); }
    let third_prepare = preprepare.signed_as(MsgType::Prepare, &keys[2]).unwrap(); assert!(sidecar.handle(third_prepare, passive_context(&keys, 1_002)).unwrap().is_empty());
    for key in &keys[..2] { let commit = preprepare.signed_as(MsgType::Commit, key).unwrap(); assert!(sidecar.handle(commit, passive_context(&keys, 1_003)).unwrap().is_empty()); }
    let effects = sidecar.handle(preprepare.signed_as(MsgType::Commit, &keys[2]).unwrap(), passive_context(&keys, 1_004)).unwrap();
    let commits: Vec<_> = effects.iter().filter_map(|effect| if let Effect::Commit(commit) = effect { Some(commit) } else { None }).collect();
    assert_eq!(commits.len(), 1); assert_eq!((commits[0].number, commits[0].signatures.len()), (123, 3));
}

#[test]
fn wrong_leader_and_wrong_authoritative_value_are_rejected_before_prepare() {
    let keys = [key(1), key(2), key(3)];
    let proposal = preprepare_block(vec![0xaa; 32], 44, 7, Some(&keys[1])).unwrap();
    let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
    assert!(matches!(sidecar.handle(proposal.clone(), authority_context(&keys, 1, &proposal, 0, true)), Err(PbftError::WrongProposer)));
    let signed_by_leader = preprepare_block(vec![0xbb; 32], 44, 7, Some(&keys[0])).unwrap();
    let mut wrong_value_context = authority_context(&keys, 2, &signed_by_leader, 0, true);
    wrong_value_context.expected_proposals[0].data = vec![0xcc; 32];
    assert!(matches!(sidecar.handle(signed_by_leader, wrong_value_context), Err(PbftError::ProposalMismatch)));
}

#[test]
fn prepare_and_commit_must_bind_to_the_same_proposal_and_cached_votes_cannot_cross() {
    let keys = [key(1), key(2)];
    let proposal_a = preprepare_block(vec![0xa1], 55, 8, Some(&keys[0])).unwrap();
    let proposal_b = preprepare_block(vec![0xb2], 55, 8, Some(&keys[0])).unwrap();
    let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
    sidecar.handle(proposal_a.clone(), authority_context(&keys, 1, &proposal_a, 0, false)).unwrap();
    sidecar.handle(proposal_a.signed_as(MsgType::Prepare, &keys[0]).unwrap(), passive_context(&keys, 2)).unwrap();
    assert!(matches!(sidecar.handle(proposal_b.signed_as(MsgType::Commit, &keys[0]).unwrap(), passive_context(&keys, 3)), Err(PbftError::ProposalMismatch)));

    let mut cached = PbftSidecar::new(Some(1), PbftBounds::default());
    cached.handle(proposal_b.signed_as(MsgType::Prepare, &keys[0]).unwrap(), passive_context(&keys, 4)).unwrap();
    cached.handle(proposal_a.clone(), authority_context(&keys, 5, &proposal_a, 0, false)).unwrap();
    assert!(matches!(cached.handle(proposal_b.signed_as(MsgType::Prepare, &keys[1]).unwrap(), passive_context(&keys, 6)), Err(PbftError::ProposalMismatch)));
}

#[test]
fn authoritative_block_and_srl_rounds_commit_valid_identity() {
    let keys = [key(1), key(2)];
    for proposal in [preprepare_block(vec![0x42; 32], 77, 9, Some(&keys[0])).unwrap(), preprepare_srl(&[vec![0x41; 21], vec![0x42; 21]], 88, Some(&keys[0])).unwrap()] {
        let mut sidecar = PbftSidecar::new(Some(2), PbftBounds::default());
        sidecar.handle(proposal.clone(), authority_context(&keys, 1, &proposal, 0, false)).unwrap();
        for key in &keys { sidecar.handle(proposal.signed_as(MsgType::Prepare, key).unwrap(), passive_context(&keys, 2)).unwrap(); }
        assert!(sidecar.handle(proposal.signed_as(MsgType::Commit, &keys[0]).unwrap(), passive_context(&keys, 3)).unwrap().is_empty());
        let effects = sidecar.handle(proposal.signed_as(MsgType::Commit, &keys[1]).unwrap(), passive_context(&keys, 4)).unwrap();
        let commit = effects.into_iter().find_map(|effect| if let Effect::Commit(commit) = effect { Some(commit) } else { None }).unwrap();
        assert_eq!((commit.data_type, commit.number, commit.epoch), (proposal.raw.data_type, proposal.raw.view_n, proposal.raw.epoch));
    }
}

#[test]
fn raw_encoded_round_vote_and_aggregate_bounds_reject_before_retention() {
    let keys = [key(1), key(2)];
    let tight = PbftBounds { max_raw_data_bytes: 8, max_encoded_message_bytes: 90, max_round_bytes: 150, max_retained_bytes: 150, max_rounds: 1, max_votes: 1, ..PbftBounds::default() };
    let mut sidecar = PbftSidecar::new(Some(2), tight);
    assert!(matches!(sidecar.handle(preprepare_block(vec![0; 9], 1, 1, Some(&keys[0])).unwrap(), passive_context(&keys, 0)), Err(PbftError::Capacity)));
    let first = preprepare_block(vec![1; 8], 1, 1, Some(&keys[0])).unwrap(); sidecar.handle(first.clone(), proposal_context(&keys, 1, &first)).unwrap();
    let blocked = preprepare_block(vec![2], 2, 2, Some(&keys[0])).unwrap(); assert!(matches!(sidecar.handle(blocked.clone(), proposal_context(&keys, 2, &blocked)), Err(PbftError::Capacity)));
    sidecar.expire(ROUND_TIMEOUT_MILLIS + 2);
    let next = preprepare_block(vec![2], 2, 2, Some(&keys[0])).unwrap(); sidecar.handle(next.clone(), proposal_context(&keys, ROUND_TIMEOUT_MILLIS + 3, &next)).unwrap();
    let prepare1 = preprepare_block(vec![7], 3, 3, None).unwrap().signed_as(MsgType::Prepare, &keys[0]).unwrap();
    let prepare2 = preprepare_block(vec![7], 4, 4, None).unwrap().signed_as(MsgType::Prepare, &keys[1]).unwrap();
    let mut flood = PbftSidecar::new(Some(2), PbftBounds { max_votes: 1, ..PbftBounds::default() });
    flood.handle(prepare1, passive_context(&keys, 0)).unwrap();
    assert!(matches!(flood.handle(prepare2, passive_context(&keys, 0)), Err(PbftError::Capacity)));
}

#[derive(Default)]
struct Memory { rows: Mutex<BTreeMap<(StoreKind, Vec<u8>), Vec<u8>>>, fail: Mutex<bool> }
impl Memory { fn get(&self, store: StoreKind, key: &[u8]) -> Option<Vec<u8>> { self.rows.lock().unwrap().get(&(store, key.to_vec())).cloned() } fn fail_next(&self) { *self.fail.lock().unwrap() = true; } }
impl PbftPersistence for Memory {
    type Error = &'static str;
    fn persist_atomic(&self, key: &[u8], value: &[u8], candidate: Option<i64>) -> Result<Option<i64>, Self::Error> {
        let mut rows = self.rows.lock().unwrap(); let mut transaction = rows.clone();
        let previous = transaction.get(&(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec())).and_then(|bytes| bytes.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(0);
        let advanced = candidate.filter(|number| *number > previous); transaction.insert((StoreKind::Pbft, key.to_vec()), value.to_vec());
        if let Some(number) = advanced { transaction.insert((StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY.to_vec()), number.to_be_bytes().to_vec()); }
        if std::mem::take(&mut *self.fail.lock().unwrap()) { return Err("injected transaction failure"); } *rows = transaction; Ok(advanced)
    }
}
fn block(number: i64) -> CommitData { CommitData { raw: vec![number as u8], data_type: DataType::Block, number, epoch: 5, signatures: vec![vec![3], vec![4]] } }

#[test]
fn commit_and_cursor_are_atomic_monotonic_and_failure_has_no_partial_write() {
    let store = Memory::default(); let saved = persist_commit(&store, &block(41)).unwrap();
    assert_eq!(saved.key, b"BLOCK41"); assert_eq!(saved.latest_pbft_block, Some(41));
    let decoded = PbftCommitResult::decode(saved.value.as_slice()).unwrap(); assert_eq!(decoded.signature, vec![vec![3], vec![4]]);
    assert_eq!(store.get(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY), Some(41i64.to_be_bytes().to_vec()));
    store.fail_next(); assert_eq!(persist_commit(&store, &block(44)).unwrap_err(), "injected transaction failure");
    assert_eq!(store.get(StoreKind::Pbft, b"BLOCK44"), None); assert_eq!(store.get(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY), Some(41i64.to_be_bytes().to_vec()));
}

#[test]
fn concurrent_block_42_and_43_commits_leave_cursor_at_43() {
    let store = Arc::new(Memory::default()); let barrier = Arc::new(Barrier::new(3)); let mut joins = Vec::new();
    for number in [42, 43] { let store = Arc::clone(&store); let barrier = Arc::clone(&barrier); joins.push(thread::spawn(move || { barrier.wait(); persist_commit(&*store, &block(number)).unwrap() })); }
    barrier.wait(); for join in joins { join.join().unwrap(); }
    assert!(store.get(StoreKind::Pbft, b"BLOCK42").is_some()); assert!(store.get(StoreKind::Pbft, b"BLOCK43").is_some());
    assert_eq!(store.get(StoreKind::Common, LATEST_PBFT_BLOCK_NUM_KEY), Some(43i64.to_be_bytes().to_vec()));
}
