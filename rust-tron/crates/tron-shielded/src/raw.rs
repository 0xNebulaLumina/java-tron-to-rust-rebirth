use std::sync::Arc;

use redjubjub::Binding;
use sapling_crypto::value::{CommitmentSum, ValueCommitment};

use crate::{
    BindingSigParams, CheckOutputNewParams, CheckOutputParams, CheckSpendNewParams,
    CheckSpendParams, ContextTable, FinalCheckNewParams, FinalCheckParams, OutputProofParams,
    Result, ShieldedError, SpendProofParams, TronParameters, Validate,
};

pub struct ShieldedRawAdapter {
    parameters: Arc<TronParameters>,
    contexts: ContextTable,
}

impl ShieldedRawAdapter {
    pub fn new(parameters: Arc<TronParameters>) -> Self {
        Self {
            parameters,
            contexts: ContextTable::new(),
        }
    }

    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }

    pub fn proving_ctx_init(&self) -> Result<u64> {
        self.contexts.init_proving(Arc::clone(&self.parameters))
    }

    pub fn verification_ctx_init(&self) -> Result<u64> {
        self.contexts.init_verification(Arc::clone(&self.parameters))
    }

    pub fn proving_ctx_free(&self, handle: u64) -> Result<()> {
        self.contexts.free_proving(handle)
    }

    pub fn verification_ctx_free(&self, handle: u64) -> Result<()> {
        self.contexts.free_verification(handle)
    }

    pub fn spend_proof(&self, params: &mut SpendProofParams) -> Result<()> {
        params.validate()?;
        let proof = self.contexts.with_proving(params.ctx, |context| {
            context.spend_proof(
                array(&params.ak),
                array(&params.nsk),
                array(&params.d),
                array(&params.r),
                array(&params.alpha),
                params.value as u64,
                array(&params.anchor),
                &params.voucher_path,
            )
        })?;
        params.cv.copy_from_slice(&proof.value_commitment);
        params.rk.copy_from_slice(&proof.randomized_key);
        params.zkproof.copy_from_slice(&proof.zkproof);
        Ok(())
    }

    pub fn output_proof(&self, params: &mut OutputProofParams) -> Result<()> {
        params.validate()?;
        let proof = self.contexts.with_proving(params.ctx, |context| {
            context.output_proof(
                array(&params.esk),
                array(&params.d),
                array(&params.pk_d),
                array(&params.r),
                params.value as u64,
            )
        })?;
        params.cv.copy_from_slice(&proof.value_commitment);
        params.zkproof.copy_from_slice(&proof.zkproof);
        Ok(())
    }

    pub fn binding_sig(&self, params: &mut BindingSigParams) -> Result<()> {
        params.validate()?;
        let signature = self.contexts.with_proving(params.ctx, |context| {
            context.binding_sig(params.value_balance, array(&params.sighash))
        })?;
        params.result.copy_from_slice(&signature);
        Ok(())
    }

    pub fn check_spend(&self, params: &CheckSpendParams) -> Result<bool> {
        params.validate()?;
        let handle = params.ctx.ok_or(ShieldedError::InvalidHandle)?;
        crypto_bool(self.contexts.with_verification(handle, |context| {
            context.check_spend(
                array(&params.cv),
                array(&params.anchor),
                array(&params.nullifier),
                array(&params.rk),
                &params.zkproof,
                array(&params.spend_auth_sig),
                array(&params.sighash_value),
            )
        }))
    }

    pub fn check_output(&self, params: &CheckOutputParams) -> Result<bool> {
        params.validate()?;
        let handle = params.ctx.ok_or(ShieldedError::InvalidHandle)?;
        crypto_bool(self.contexts.with_verification(handle, |context| {
            context.check_output(
                array(&params.cv),
                array(&params.cm),
                array(&params.ephemeral_key),
                &params.zkproof,
            )
        }))
    }

    pub fn final_check(&self, params: &FinalCheckParams) -> Result<bool> {
        params.validate()?;
        let handle = params.ctx.ok_or(ShieldedError::InvalidHandle)?;
        self.contexts.with_verification(handle, |context| {
            Ok(context.final_check(
                params.value_balance,
                array(&params.binding_sig),
                array(&params.sighash_value),
            ))
        })
    }

    pub fn check_spend_new(&self, params: &CheckSpendNewParams) -> Result<bool> {
        params.validate()?;
        let mut context = crate::VerificationContext::new(Arc::clone(&self.parameters));
        crypto_bool(context.check_spend(
            array(&params.cv),
            array(&params.anchor),
            array(&params.nullifier),
            array(&params.rk),
            &params.zkproof,
            array(&params.spend_auth_sig),
            array(&params.sighash_value),
        ))
    }

    pub fn check_output_new(&self, params: &CheckOutputNewParams) -> Result<bool> {
        params.validate()?;
        let mut context = crate::VerificationContext::new(Arc::clone(&self.parameters));
        crypto_bool(context.check_output(
            array(&params.cv),
            array(&params.cm),
            array(&params.ephemeral_key),
            &params.zkproof,
        ))
    }

    pub fn final_check_new(&self, params: &FinalCheckNewParams) -> Result<bool> {
        params.validate()?;
        let mut commitments = CommitmentSum::zero();
        for cv in params.spend_cv.chunks_exact(32) {
            let cv = match parse_cv(cv) {
                Some(cv) => cv,
                None => return Ok(false),
            };
            commitments += &cv;
        }
        for cv in params.output_cv.chunks_exact(32) {
            let cv = match parse_cv(cv) {
                Some(cv) => cv,
                None => return Ok(false),
            };
            commitments -= &cv;
        }
        let bvk = commitments.into_bvk(params.value_balance);
        let signature = redjubjub::Signature::<Binding>::from(array(&params.binding_sig));
        Ok(bvk.verify(&params.sighash_value, &signature).is_ok())
    }
}

fn array<const N: usize>(value: &[u8]) -> [u8; N] {
    value.try_into().expect("validated fixed-width parameter")
}

fn parse_cv(value: &[u8]) -> Option<ValueCommitment> {
    let bytes: [u8; 32] = value.try_into().ok()?;
    Option::from(ValueCommitment::from_bytes_not_small_order(&bytes))
}

fn crypto_bool(result: Result<bool>) -> Result<bool> {
    match result {
        Ok(value) => Ok(value),
        Err(ShieldedError::InvalidEncoding(_)) => Ok(false),
        Err(error) => Err(error),
    }
}
