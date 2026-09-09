use prost::Message;
use tron_crypto::selected_digest;
use tron_protocol::{
    google::protobuf::Any,
    protocol::{
        Transaction, TransactionExtention,
        transaction::{Contract, Raw, contract::ContractType},
    },
};
use tron_state::{CursorView, StoreKind, dynamic};

use crate::{
    ApiContext, ApiError, BlockingCancellation,
    error::{failure_return, success_return},
};

pub const DEFAULT_TRANSACTION_EXPIRATION_MILLIS: i64 = 60_000;
pub const MAX_CONTRACT_BYTES: usize = 500 * 1024;

#[derive(Clone)]
pub struct WalletMutation {
    context: ApiContext,
    expiration_millis: i64,
}
impl WalletMutation {
    #[must_use]
    pub fn new(context: ApiContext) -> Self {
        Self {
            context,
            expiration_millis: DEFAULT_TRANSACTION_EXPIRATION_MILLIS,
        }
    }
    pub fn with_expiration(mut self, millis: i64) -> Result<Self, ApiError> {
        if millis <= 0 {
            return Err(ApiError::InvalidArgument(
                "transaction expiration must be positive".into(),
            ));
        }
        self.expiration_millis = millis;
        Ok(self)
    }

    pub fn create<M: Message>(
        &self,
        kind: ContractType,
        protobuf_name: &str,
        message: &M,
    ) -> Result<TransactionExtention, ApiError> {
        self.create_extension(
            kind as i32,
            &format!("type.googleapis.com/{protobuf_name}"),
            message.encode_to_vec(),
        )
    }
    pub fn create_extension(
        &self,
        contract_type: i32,
        type_url: &str,
        payload: Vec<u8>,
    ) -> Result<TransactionExtention, ApiError> {
        if payload.len() > MAX_CONTRACT_BYTES {
            return Err(ApiError::InvalidArgument(
                "contract exceeds maximum transaction size".into(),
            ));
        }
        if type_url.is_empty() {
            return Err(ApiError::InvalidArgument(
                "contract type URL must not be empty".into(),
            ));
        }
        let head = self.context.head();
        let timestamp = read_i64(&head, "LATEST_BLOCK_HEADER_TIMESTAMP")?;
        let number = read_i64(&head, "LATEST_BLOCK_HEADER_NUMBER")?;
        let hash = read_bytes(&head, "LATEST_BLOCK_HEADER_HASH")?;
        let ref_hash = hash
            .get(8..16)
            .ok_or_else(|| {
                ApiError::FailedPrecondition(
                    "latest block hash must contain at least 16 bytes".into(),
                )
            })?
            .to_vec();
        let height = number.to_be_bytes();
        let transaction = Transaction {
            raw_data: Some(Raw {
                ref_block_bytes: height[6..].to_vec(),
                ref_block_num: 0,
                ref_block_hash: ref_hash,
                expiration: timestamp
                    .checked_add(self.expiration_millis)
                    .ok_or_else(|| ApiError::Internal("transaction expiration overflow".into()))?,
                contract: vec![Contract {
                    r#type: contract_type,
                    parameter: Some(Any {
                        type_url: type_url.to_owned(),
                        value: payload,
                    }),
                    ..Default::default()
                }],
                timestamp,
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(self.extension(transaction))
    }
    #[must_use]
    pub fn extension(&self, transaction: Transaction) -> TransactionExtention {
        let txid = transaction
            .raw_data
            .as_ref()
            .map(|raw| selected_digest(self.context.crypto_engine(), &raw.encode_to_vec()).to_vec())
            .unwrap_or_default();
        TransactionExtention {
            transaction: Some(transaction),
            txid,
            result: Some(success_return()),
            ..Default::default()
        }
    }
    pub fn create_common_transaction(&self, transaction: Transaction) -> TransactionExtention {
        if transaction
            .raw_data
            .as_ref()
            .is_none_or(|raw| raw.contract.len() != 1)
        {
            TransactionExtention {
                transaction: Some(transaction),
                result: Some(failure_return(
                    tron_protocol::protocol::r#return::ResponseCode::ContractValidateError,
                    b"transaction must contain exactly one contract".to_vec(),
                )),
                ..Default::default()
            }
        } else {
            self.extension(transaction)
        }
    }
    pub fn broadcast_raw(
        &self,
        raw_transaction: impl Into<Vec<u8>>,
        received_at: i64,
        smart: bool,
    ) -> tron_protocol::protocol::Return {
        self.broadcast_raw_cancellable(raw_transaction.into(), received_at, smart, None)
    }
    pub fn broadcast_raw_with_cancellation(
        &self,
        raw_transaction: Vec<u8>,
        received_at: i64,
        smart: bool,
        cancellation: &BlockingCancellation,
    ) -> tron_protocol::protocol::Return {
        self.broadcast_raw_cancellable(raw_transaction, received_at, smart, Some(cancellation))
    }
    fn broadcast_raw_cancellable(
        &self,
        raw_transaction: Vec<u8>,
        received_at: i64,
        smart: bool,
        cancellation: Option<&BlockingCancellation>,
    ) -> tron_protocol::protocol::Return {
        if cancellation.is_some_and(BlockingCancellation::is_cancelled) {
            return failure_return(
                tron_protocol::protocol::r#return::ResponseCode::OtherError,
                b"broadcast cancelled".to_vec(),
            );
        }
        let Some(provider) = self.context.execution() else {
            return failure_return(
                tron_protocol::protocol::r#return::ResponseCode::OtherError,
                b"transaction mutation is unavailable on this node".to_vec(),
            );
        };
        provider.broadcast_raw(raw_transaction, received_at, smart)
    }
}
fn read_i64(view: &tron_state::HeadCursor, name: &str) -> Result<i64, ApiError> {
    let value = read_bytes(view, name)?;
    value
        .as_slice()
        .try_into()
        .map(i64::from_be_bytes)
        .map_err(|_| ApiError::Internal(format!("invalid dynamic property {name}")))
}
fn read_bytes(view: &tron_state::HeadCursor, name: &str) -> Result<Vec<u8>, ApiError> {
    let key = dynamic::key(name)
        .ok_or_else(|| ApiError::Internal(format!("unknown dynamic property {name}")))?;
    view.store(StoreKind::DynamicProperties)
        .get(key)
        .ok_or_else(|| ApiError::FailedPrecondition(format!("missing dynamic property {name}")))
}

macro_rules! constructors { ($(($method:ident,$kind:ident,$ty:ty,$name:literal)),* $(,)?) => {$(
 impl WalletMutation { pub fn $method(&self,value:&$ty)->Result<TransactionExtention,ApiError>{self.create(ContractType::$kind,$name,value)} }
 )*}; }
constructors! {
(create_transaction,TransferContract,tron_protocol::protocol::TransferContract,"protocol.TransferContract"),(create_account,AccountCreateContract,tron_protocol::protocol::AccountCreateContract,"protocol.AccountCreateContract"),(update_account,AccountUpdateContract,tron_protocol::protocol::AccountUpdateContract,"protocol.AccountUpdateContract"),(set_account_id,SetAccountIdContract,tron_protocol::protocol::SetAccountIdContract,"protocol.SetAccountIdContract"),(vote_witness_account,VoteWitnessContract,tron_protocol::protocol::VoteWitnessContract,"protocol.VoteWitnessContract"),(create_asset_issue,AssetIssueContract,tron_protocol::protocol::AssetIssueContract,"protocol.AssetIssueContract"),(update_witness,WitnessUpdateContract,tron_protocol::protocol::WitnessUpdateContract,"protocol.WitnessUpdateContract"),(create_witness,WitnessCreateContract,tron_protocol::protocol::WitnessCreateContract,"protocol.WitnessCreateContract"),(transfer_asset,TransferAssetContract,tron_protocol::protocol::TransferAssetContract,"protocol.TransferAssetContract"),(participate_asset_issue,ParticipateAssetIssueContract,tron_protocol::protocol::ParticipateAssetIssueContract,"protocol.ParticipateAssetIssueContract"),(freeze_balance,FreezeBalanceContract,tron_protocol::protocol::FreezeBalanceContract,"protocol.FreezeBalanceContract"),(freeze_balance_v2,FreezeBalanceV2Contract,tron_protocol::protocol::FreezeBalanceV2Contract,"protocol.FreezeBalanceV2Contract"),(unfreeze_balance,UnfreezeBalanceContract,tron_protocol::protocol::UnfreezeBalanceContract,"protocol.UnfreezeBalanceContract"),(unfreeze_balance_v2,UnfreezeBalanceV2Contract,tron_protocol::protocol::UnfreezeBalanceV2Contract,"protocol.UnfreezeBalanceV2Contract"),(unfreeze_asset,UnfreezeAssetContract,tron_protocol::protocol::UnfreezeAssetContract,"protocol.UnfreezeAssetContract"),(withdraw_balance,WithdrawBalanceContract,tron_protocol::protocol::WithdrawBalanceContract,"protocol.WithdrawBalanceContract"),(withdraw_expire_unfreeze,WithdrawExpireUnfreezeContract,tron_protocol::protocol::WithdrawExpireUnfreezeContract,"protocol.WithdrawExpireUnfreezeContract"),(delegate_resource,DelegateResourceContract,tron_protocol::protocol::DelegateResourceContract,"protocol.DelegateResourceContract"),(un_delegate_resource,UnDelegateResourceContract,tron_protocol::protocol::UnDelegateResourceContract,"protocol.UnDelegateResourceContract"),(cancel_all_unfreeze_v2,CancelAllUnfreezeV2Contract,tron_protocol::protocol::CancelAllUnfreezeV2Contract,"protocol.CancelAllUnfreezeV2Contract"),(update_asset,UpdateAssetContract,tron_protocol::protocol::UpdateAssetContract,"protocol.UpdateAssetContract"),(proposal_create,ProposalCreateContract,tron_protocol::protocol::ProposalCreateContract,"protocol.ProposalCreateContract"),(proposal_approve,ProposalApproveContract,tron_protocol::protocol::ProposalApproveContract,"protocol.ProposalApproveContract"),(proposal_delete,ProposalDeleteContract,tron_protocol::protocol::ProposalDeleteContract,"protocol.ProposalDeleteContract"),(exchange_create,ExchangeCreateContract,tron_protocol::protocol::ExchangeCreateContract,"protocol.ExchangeCreateContract"),(exchange_inject,ExchangeInjectContract,tron_protocol::protocol::ExchangeInjectContract,"protocol.ExchangeInjectContract"),(exchange_withdraw,ExchangeWithdrawContract,tron_protocol::protocol::ExchangeWithdrawContract,"protocol.ExchangeWithdrawContract"),(exchange_transaction,ExchangeTransactionContract,tron_protocol::protocol::ExchangeTransactionContract,"protocol.ExchangeTransactionContract"),(market_sell_asset,MarketSellAssetContract,tron_protocol::protocol::MarketSellAssetContract,"protocol.MarketSellAssetContract"),(market_cancel_order,MarketCancelOrderContract,tron_protocol::protocol::MarketCancelOrderContract,"protocol.MarketCancelOrderContract"),(account_permission_update,AccountPermissionUpdateContract,tron_protocol::protocol::AccountPermissionUpdateContract,"protocol.AccountPermissionUpdateContract"),(update_setting,UpdateSettingContract,tron_protocol::protocol::UpdateSettingContract,"protocol.UpdateSettingContract"),(update_energy_limit,UpdateEnergyLimitContract,tron_protocol::protocol::UpdateEnergyLimitContract,"protocol.UpdateEnergyLimitContract"),(update_brokerage,UpdateBrokerageContract,tron_protocol::protocol::UpdateBrokerageContract,"protocol.UpdateBrokerageContract"),(clear_contract_abi,ClearAbiContract,tron_protocol::protocol::ClearAbiContract,"protocol.ClearABIContract")
}
