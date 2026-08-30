use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
};

use bellman::groth16::Proof;
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use group::GroupEncoding;
use redjubjub::{Binding, SpendAuth};
use sapling_crypto::{
    bundle::GrothProofBytes,
    circuit::ValueCommitmentOpening,
    keys::SpendValidatingKey,
    note::ExtractedNoteCommitment,
    prover::{OutputProver, SpendProver},
    value::{CommitmentSum, NoteValue, TrapdoorSum, ValueCommitTrapdoor, ValueCommitment},
    SaplingVerificationContext,
    Diversifier, MerklePath, PaymentAddress, ProofGenerationKey, Rseed,
};

use crate::{JavaMerklePath, Result, ShieldedError, TronParameters};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendProof {
    pub value_commitment: [u8; 32],
    pub randomized_key: [u8; 32],
    pub zkproof: GrothProofBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputProof {
    pub value_commitment: [u8; 32],
    pub zkproof: GrothProofBytes,
}

pub struct ProvingContext {
    parameters: Arc<TronParameters>,
    commitments: CommitmentSum,
    trapdoors: TrapdoorSum,
}

impl ProvingContext {
    pub fn new(parameters: Arc<TronParameters>) -> Self {
        Self {
            parameters,
            commitments: CommitmentSum::zero(),
            trapdoors: TrapdoorSum::zero(),
        }
    }

    pub fn parameters(&self) -> &Arc<TronParameters> {
        &self.parameters
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spend_proof(
        &mut self,
        ak: [u8; 32],
        nsk: [u8; 32],
        diversifier: [u8; 11],
        rcm: [u8; 32],
        alpha: [u8; 32],
        value: u64,
        anchor: [u8; 32],
        voucher_path: &[u8],
    ) -> Result<SpendProof> {
        let rk = redjubjub::VerificationKey::<SpendAuth>::try_from(ak)
            .map_err(|_| ShieldedError::InvalidEncoding("spend validating key"))?;
        let ak = SpendValidatingKey::temporary_zcash_from_bytes(&ak)
            .ok_or(ShieldedError::InvalidEncoding("spend validating key"))?;
        let nsk = scalar(nsk, "proof generation key")?;
        let rcm = scalar(rcm, "note commitment trapdoor")?;
        let alpha = scalar(alpha, "spend randomizer")?;
        let anchor = Option::<Scalar>::from(Scalar::from_repr(anchor))
            .ok_or(ShieldedError::InvalidEncoding("anchor"))?;
        let path = merkle_path(voucher_path)?;
        let rcv = ValueCommitTrapdoor::random(&mut rand_core::OsRng);
        let circuit = <sapling_crypto::circuit::SpendParameters as SpendProver>::prepare_circuit(
            ProofGenerationKey { ak, nsk },
            Diversifier(diversifier),
            Rseed::BeforeZip212(rcm),
            NoteValue::from_raw(value),
            alpha,
            rcv.clone(),
            anchor,
            path,
        )
        .ok_or(ShieldedError::InvalidEncoding("diversifier"))?;
        let proof = self.parameters.spend.create_proof(circuit, &mut rand_core::OsRng);
        let zkproof = <sapling_crypto::circuit::SpendParameters as SpendProver>::encode_proof(proof);
        let value_commitment = ValueCommitment::derive(NoteValue::from_raw(value), rcv.clone());
        let randomized_key: [u8; 32] = rk.randomize(&alpha).into();

        self.trapdoors += &rcv;
        self.commitments += &value_commitment;
        Ok(SpendProof {
            value_commitment: value_commitment.to_bytes(),
            randomized_key,
            zkproof,
        })
    }

    pub fn output_proof(
        &mut self,
        esk: [u8; 32],
        diversifier: [u8; 11],
        pk_d: [u8; 32],
        rcm: [u8; 32],
        value: u64,
    ) -> Result<OutputProof> {
        let recipient = payment_address(diversifier, pk_d)?;
        let esk = scalar(esk, "ephemeral secret key")?;
        let rcm = scalar(rcm, "note commitment trapdoor")?;
        let rcv = ValueCommitTrapdoor::random(&mut rand_core::OsRng);
        let circuit = sapling_crypto::circuit::Output {
            value_commitment_opening: Some(ValueCommitmentOpening {
                value: NoteValue::from_raw(value),
                randomness: rcv.inner(),
            }),
            payment_address: Some(recipient),
            commitment_randomness: Some(rcm),
            esk: Some(esk),
        };
        let proof = self.parameters.output.create_proof(circuit, &mut rand_core::OsRng);
        let zkproof = <sapling_crypto::circuit::OutputParameters as OutputProver>::encode_proof(proof);
        let value_commitment = ValueCommitment::derive(NoteValue::from_raw(value), rcv.clone());

        self.trapdoors -= &rcv;
        self.commitments -= &value_commitment;
        Ok(OutputProof {
            value_commitment: value_commitment.to_bytes(),
            zkproof,
        })
    }

    pub fn binding_sig(&self, value_balance: i64, sighash: [u8; 32]) -> Result<[u8; 64]> {
        let bsk = self.trapdoors.into_bsk();
        let expected_bvk = self.commitments.into_bvk(value_balance);
        if redjubjub::VerificationKey::from(&bsk) != expected_bvk {
            return Err(ShieldedError::InvalidParameter(
                "value balance is inconsistent with proving context".into(),
            ));
        }
        Ok(bsk.sign(rand_core::OsRng, &sighash).into())
    }
}

pub struct VerificationContext {
    parameters: Arc<TronParameters>,
    inner: SaplingVerificationContext,
    spend_count: u64,
    output_count: u64,
    preverification_count: u64,
}

impl VerificationContext {
    pub fn new(parameters: Arc<TronParameters>) -> Self {
        Self {
            parameters,
            inner: SaplingVerificationContext::new(),
            spend_count: 0,
            output_count: 0,
            preverification_count: 0,
        }
    }

    pub fn spend_count(&self) -> u64 {
        self.spend_count
    }

    pub fn output_count(&self) -> u64 {
        self.output_count
    }

    pub fn preverification_count(&self) -> u64 {
        self.preverification_count
    }

    #[allow(clippy::too_many_arguments)]
    pub fn check_spend(
        &mut self,
        cv: [u8; 32],
        anchor: [u8; 32],
        nullifier: [u8; 32],
        rk: [u8; 32],
        zkproof: &[u8],
        spend_auth_sig: [u8; 64],
        sighash: [u8; 32],
    ) -> Result<bool> {
        let cv = value_commitment(cv)?;
        let anchor = Option::<Scalar>::from(Scalar::from_repr(anchor))
            .ok_or(ShieldedError::InvalidEncoding("anchor"))?;
        let rk = redjubjub::VerificationKey::<SpendAuth>::try_from(rk)
            .map_err(|_| ShieldedError::InvalidEncoding("randomized spend key"))?;
        let signature = redjubjub::Signature::<SpendAuth>::from(spend_auth_sig);
        let verifying_key = self.parameters.spend.prepared_verifying_key();

        let mut preverification = SaplingVerificationContext::new();
        if !preverification.check_spend(
            &cv,
            anchor,
            &nullifier,
            rk,
            &sighash,
            signature,
            parse_proof(zkproof)?,
            &verifying_key,
        ) {
            return Ok(false);
        }

        let next_spend_count = self.spend_count.checked_add(1)
            .ok_or_else(|| ShieldedError::InvalidParameter("shielded spend counter overflow".into()))?;
        let next_preverification_count = self.preverification_count.checked_add(1)
            .ok_or_else(|| ShieldedError::InvalidParameter("shielded preverification counter overflow".into()))?;
        if !self.inner.check_spend(
            &cv,
            anchor,
            &nullifier,
            rk,
            &sighash,
            signature,
            parse_proof(zkproof)?,
            &verifying_key,
        ) {
            return Err(ShieldedError::VerificationStateCorrupt);
        }
        self.spend_count = next_spend_count;
        self.preverification_count = next_preverification_count;
        Ok(true)
    }

    pub fn check_output(
        &mut self,
        cv: [u8; 32],
        cmu: [u8; 32],
        ephemeral_key: [u8; 32],
        zkproof: &[u8],
    ) -> Result<bool> {
        let cv = value_commitment(cv)?;
        let cmu = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmu))
            .ok_or(ShieldedError::InvalidEncoding("note commitment"))?;
        let ephemeral_key = Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&ephemeral_key))
            .ok_or(ShieldedError::InvalidEncoding("ephemeral key"))?;
        let verifying_key = self.parameters.output.prepared_verifying_key();

        let mut preverification = SaplingVerificationContext::new();
        if !preverification.check_output(
            &cv,
            cmu,
            ephemeral_key,
            parse_proof(zkproof)?,
            &verifying_key,
        ) {
            return Ok(false);
        }

        let next_output_count = self.output_count.checked_add(1)
            .ok_or_else(|| ShieldedError::InvalidParameter("shielded output counter overflow".into()))?;
        let next_preverification_count = self.preverification_count.checked_add(1)
            .ok_or_else(|| ShieldedError::InvalidParameter("shielded preverification counter overflow".into()))?;
        if !self.inner.check_output(
            &cv,
            cmu,
            ephemeral_key,
            parse_proof(zkproof)?,
            &verifying_key,
        ) {
            return Err(ShieldedError::VerificationStateCorrupt);
        }
        self.output_count = next_output_count;
        self.preverification_count = next_preverification_count;
        Ok(true)
    }

    pub fn final_check(
        &self,
        value_balance: i64,
        binding_sig: [u8; 64],
        sighash: [u8; 32],
    ) -> bool {
        self.inner.final_check(
            value_balance,
            &sighash,
            redjubjub::Signature::<Binding>::from(binding_sig),
        )
    }
}

enum Context {
    Proving(ProvingContext),
    Verification(VerificationContext),
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ContextKind {
    Proving,
    Verification,
}

struct ContextEntry {
    kind: ContextKind,
    context: Mutex<Context>,
    admission: Mutex<AdmissionState>,
    quiesced: Condvar,
}

#[derive(Default)]
struct AdmissionState {
    retired: bool,
    active: usize,
}

struct ContextTableState {
    reserved_slots: usize,
    contexts: HashMap<u64, Arc<ContextEntry>>,
}

struct ReservedSlotGuard<'a> {
    table: &'a ContextTable,
}

impl Drop for ReservedSlotGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.table.state.lock().expect("context table mutex poisoned");
        state.reserved_slots = state
            .reserved_slots
            .checked_sub(1)
            .expect("context reserved slot underflow");
    }
}

struct AdmissionGuard {
    entry: Arc<ContextEntry>,
}

impl ContextEntry {
    fn new(kind: ContextKind, context: Context) -> Self {
        Self {
            kind,
            context: Mutex::new(context),
            admission: Mutex::new(AdmissionState::default()),
            quiesced: Condvar::new(),
        }
    }

    fn admit(self: &Arc<Self>) -> Result<AdmissionGuard> {
        let mut admission = self.admission.lock().expect("context admission mutex poisoned");
        if admission.retired {
            return Err(ShieldedError::InvalidHandle);
        }
        admission.active = admission.active.checked_add(1).expect("context activity overflow");
        drop(admission);
        Ok(AdmissionGuard { entry: Arc::clone(self) })
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut admission = self.entry.admission.lock().expect("context admission mutex poisoned");
        admission.active = admission.active.checked_sub(1).expect("context activity underflow");
        if admission.active == 0 {
            self.entry.quiesced.notify_all();
        }
    }
}

pub const DEFAULT_MAX_CONTEXTS: usize = 64;

pub struct ContextTable {
    next: AtomicU64,
    max_contexts: usize,
    state: Mutex<ContextTableState>,
}
impl Default for ContextTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextTable {
    pub fn new() -> Self {
        Self::with_max_contexts(DEFAULT_MAX_CONTEXTS).expect("default context bound is nonzero")
    }

    pub fn with_max_contexts(max_contexts: usize) -> Result<Self> {
        if max_contexts == 0 {
            return Err(ShieldedError::InvalidParameter("max contexts must be positive".into()));
        }
        Ok(Self {
            next: AtomicU64::new(1),
            max_contexts,
            state: Mutex::new(ContextTableState {
                reserved_slots: 0,
                contexts: HashMap::new(),
            }),
        })
    }
    fn insert(&self, kind: ContextKind, context: Context) -> Result<u64> {
        let mut state = self.state.lock().expect("context table mutex poisoned");
        if state.reserved_slots >= self.max_contexts {
            return Err(ShieldedError::ContextLimit { max: self.max_contexts });
        }
        let handle = self.next.fetch_add(1, Ordering::Relaxed);
        state.reserved_slots += 1;
        state.contexts.insert(handle, Arc::new(ContextEntry::new(kind, context)));
        Ok(handle)
    }

    pub fn init_proving(&self, parameters: Arc<TronParameters>) -> Result<u64> {
        self.insert(ContextKind::Proving, Context::Proving(ProvingContext::new(parameters)))
    }
    pub fn init_verification(&self, parameters: Arc<TronParameters>) -> Result<u64> {
        self.insert(
            ContextKind::Verification,
            Context::Verification(VerificationContext::new(parameters)),
        )
    }

    pub fn with_proving<T>(
        &self,
        handle: u64,
        f: impl FnOnce(&mut ProvingContext) -> Result<T>,
    ) -> Result<T> {
        let entry = self.get_matching(handle, ContextKind::Proving)?;
        let _admission = entry.admit()?;
        let mut context = entry.context.lock().expect("shielded context mutex poisoned");
        match &mut *context {
            Context::Proving(context) => f(context),
            Context::Verification(_) => unreachable!("context kind changed after insertion"),
        }
    }

    pub fn with_verification<T>(
        &self,
        handle: u64,
        f: impl FnOnce(&mut VerificationContext) -> Result<T>,
    ) -> Result<T> {
        let entry = self.get_matching(handle, ContextKind::Verification)?;
        let _admission = entry.admit()?;
        let mut context = entry.context.lock().expect("shielded context mutex poisoned");
        match &mut *context {
            Context::Verification(context) => f(context),
            Context::Proving(_) => unreachable!("context kind changed after insertion"),
        }
    }

    fn get_matching(&self, handle: u64, expected_kind: ContextKind) -> Result<Arc<ContextEntry>> {
        let state = self.state.lock().expect("context table mutex poisoned");
        let entry = state.contexts.get(&handle).ok_or(ShieldedError::InvalidHandle)?;
        if entry.kind != expected_kind {
            return Err(ShieldedError::InvalidHandle);
        }
        Ok(Arc::clone(entry))
    }

    pub fn free_proving(&self, handle: u64) -> Result<()> {
        self.free_matching(handle, ContextKind::Proving)
    }

    pub fn free_verification(&self, handle: u64) -> Result<()> {
        self.free_matching(handle, ContextKind::Verification)
    }

    fn free_matching(&self, handle: u64, expected_kind: ContextKind) -> Result<()> {
        let entry = {
            let mut state = self.state.lock().expect("context table mutex poisoned");
            let entry = Arc::clone(state.contexts.get(&handle).ok_or(ShieldedError::InvalidHandle)?);
            if entry.kind != expected_kind {
                return Err(ShieldedError::InvalidHandle);
            }
            let mut admission = entry.admission.lock().expect("context admission mutex poisoned");
            admission.retired = true;
            state.contexts.remove(&handle).expect("context entry disappeared while table was locked");
            drop(admission);
            entry
        };
        let reserved_slot = ReservedSlotGuard { table: self };

        let mut admission = entry.admission.lock().expect("context admission mutex poisoned");
        while admission.active != 0 {
            admission = entry.quiesced.wait(admission).expect("context admission mutex poisoned");
        }
        drop(admission);
        drop(reserved_slot);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("context table mutex poisoned")
            .contexts
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn scalar(bytes: [u8; 32], name: &'static str) -> Result<jubjub::Fr> {
    Option::<jubjub::Fr>::from(jubjub::Fr::from_repr(bytes))
        .ok_or(ShieldedError::InvalidEncoding(name))
}

fn payment_address(diversifier: [u8; 11], pk_d: [u8; 32]) -> Result<PaymentAddress> {
    let mut bytes = [0u8; 43];
    bytes[..11].copy_from_slice(&diversifier);
    bytes[11..].copy_from_slice(&pk_d);
    PaymentAddress::from_bytes(&bytes).ok_or(ShieldedError::InvalidEncoding("payment address"))
}

fn merkle_path(bytes: &[u8]) -> Result<MerklePath> {
    let path = JavaMerklePath::decode(bytes)?;
    let nodes = path
        .siblings
        .into_iter()
        .map(|bytes| {
            Option::<sapling_crypto::Node>::from(sapling_crypto::Node::from_bytes(bytes))
                .ok_or(ShieldedError::InvalidEncoding("Merkle node"))
        })
        .collect::<Result<Vec<_>>>()?;
    MerklePath::from_parts(nodes, path.position.into())
        .map_err(|_| ShieldedError::InvalidEncoding("Merkle path"))
}

fn value_commitment(bytes: [u8; 32]) -> Result<ValueCommitment> {
    Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(&bytes))
        .ok_or(ShieldedError::InvalidEncoding("value commitment"))
}

fn parse_proof(bytes: &[u8]) -> Result<Proof<Bls12>> {
    if bytes.len() != 192 {
        return Err(ShieldedError::InvalidParameter(
            "param length must be 192".into(),
        ));
    }
    Proof::read(bytes).map_err(|_| ShieldedError::InvalidEncoding("Groth16 proof"))
}
