use tron_protocol::protocol::{
    BytesMessage, DiversifierMessage, ExpandedSpendingKeyMessage,
    IncomingViewingKeyDiversifierMessage, IncomingViewingKeyMessage, PaymentAddressMessage,
    ShieldedAddressInfo, ViewingKeyMessage,
};
use tron_shielded::{
    ask_to_ak, check_diversifier, crh_ivk, generate_r, ivk_to_pkd, nsk_to_nk, spend_sig,
    zip32_xsk_master,
};

use crate::ApiError;

pub const SHIELDED_KEY_BYTES: usize = 32;
pub const DIVERSIFIER_BYTES: usize = 11;
pub const MAX_SHIELDED_SCAN_BLOCKS: i64 = 1_000;
pub const MAX_SHIELDED_SPENDS: usize = 1;
pub const MAX_SHIELDED_OUTPUTS: usize = 2;

pub struct ShieldedWallet;
impl ShieldedWallet {
    #[must_use]
    pub fn spending_key() -> BytesMessage {
        BytesMessage {
            value: generate_r().to_vec(),
        }
    }
    pub fn expanded_spending_key(seed: &[u8]) -> Result<ExpandedSpendingKeyMessage, ApiError> {
        if seed.len() != 32 {
            return Err(ApiError::InvalidArgument(
                "spending key must be 32 bytes".into(),
            ));
        }
        let xsk = zip32_xsk_master(seed);
        Ok(ExpandedSpendingKeyMessage {
            ask: xsk[41..73].to_vec(),
            nsk: xsk[73..105].to_vec(),
            ovk: xsk[105..137].to_vec(),
        })
    }
    pub fn ak_from_ask(ask: &[u8]) -> Result<BytesMessage, ApiError> {
        Ok(BytesMessage {
            value: ask_to_ak(array(ask, "ask")?).to_vec(),
        })
    }
    pub fn nk_from_nsk(nsk: &[u8]) -> Result<BytesMessage, ApiError> {
        Ok(BytesMessage {
            value: nsk_to_nk(array(nsk, "nsk")?).to_vec(),
        })
    }
    pub fn incoming_viewing_key(
        view: &ViewingKeyMessage,
    ) -> Result<IncomingViewingKeyMessage, ApiError> {
        Ok(IncomingViewingKeyMessage {
            ivk: crh_ivk(array(&view.ak, "ak")?, array(&view.nk, "nk")?).to_vec(),
        })
    }
    pub fn diversifier() -> DiversifierMessage {
        loop {
            let r = generate_r();
            let mut d = vec![0; 11];
            d.copy_from_slice(&r[..11]);
            if check_diversifier(d.clone().try_into().expect("fixed")) {
                return DiversifierMessage { d };
            }
        }
    }
    pub fn payment_address(
        input: &IncomingViewingKeyDiversifierMessage,
    ) -> Result<PaymentAddressMessage, ApiError> {
        let ivk = input
            .ivk
            .as_ref()
            .ok_or_else(|| ApiError::InvalidArgument("ivk is required".into()))?;
        let d = input
            .d
            .as_ref()
            .ok_or_else(|| ApiError::InvalidArgument("diversifier is required".into()))?;
        let d_array = array::<11>(&d.d, "diversifier")?;
        let pk_d = ivk_to_pkd(array(&ivk.ivk, "ivk")?, d_array)?.to_vec();
        let mut address = d.d.clone();
        address.extend_from_slice(&pk_d);
        Ok(PaymentAddressMessage {
            d: Some(d.clone()),
            pk_d,
            payment_address: hex(&address),
        })
    }
    pub fn new_address() -> Result<ShieldedAddressInfo, ApiError> {
        let sk = generate_r();
        let expanded = Self::expanded_spending_key(&sk)?;
        let ak = ask_to_ak(array(&expanded.ask, "ask")?);
        let nk = nsk_to_nk(array(&expanded.nsk, "nsk")?);
        let ivk = crh_ivk(ak, nk);
        let d = Self::diversifier().d;
        let pk_d = ivk_to_pkd(ivk, array(&d, "diversifier")?)?;
        let mut raw = d.clone();
        raw.extend_from_slice(&pk_d);
        Ok(ShieldedAddressInfo {
            sk: sk.to_vec(),
            ask: expanded.ask,
            nsk: expanded.nsk,
            ovk: expanded.ovk,
            ak: ak.to_vec(),
            nk: nk.to_vec(),
            ivk: ivk.to_vec(),
            d,
            pk_d: pk_d.to_vec(),
            payment_address: hex(&raw),
        })
    }
    pub fn create_spend_auth_sig(
        ask: &[u8],
        alpha: &[u8],
        sighash: &[u8],
    ) -> Result<BytesMessage, ApiError> {
        Ok(BytesMessage {
            value: spend_sig(
                array(ask, "ask")?,
                array(alpha, "alpha")?,
                array(sighash, "sighash")?,
            )
            .map_err(|e| ApiError::InvalidArgument(e.to_string()))?
            .to_vec(),
        })
    }
    pub fn validate_scan_range(start: i64, end: i64) -> Result<(), ApiError> {
        if start < 0 || end < start {
            return Err(ApiError::InvalidArgument(
                "invalid shielded scan range".into(),
            ));
        }
        if end - start > MAX_SHIELDED_SCAN_BLOCKS {
            return Err(ApiError::InvalidArgument(format!(
                "shielded scan range exceeds {MAX_SHIELDED_SCAN_BLOCKS} blocks"
            )));
        }
        Ok(())
    }
}
fn array<const N: usize>(value: &[u8], name: &str) -> Result<[u8; N], ApiError> {
    value
        .try_into()
        .map_err(|_| ApiError::InvalidArgument(format!("{name} must be {N} bytes")))
}
fn hex(value: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(value.len() * 2);
    for b in value {
        s.push(H[usize::from(b >> 4)] as char);
        s.push(H[usize::from(b & 15)] as char)
    }
    s
}
