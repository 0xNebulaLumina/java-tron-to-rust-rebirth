use std::sync::{Arc, Mutex};

use crate::{ApiContext, ApiCursor, ApiError, WalletQuery};

/// Java WalletOnCursor-compatible scoped selector. The previous cursor is restored on every
/// return path and during unwinding, preventing a pooled RPC worker from leaking its view.
#[derive(Clone)]
pub struct CursorRouter {
    context: ApiContext,
    selected: Arc<Mutex<ApiCursor>>,
}
impl CursorRouter {
    #[must_use]
    pub fn new(context: ApiContext) -> Self {
        Self {
            context,
            selected: Arc::new(Mutex::new(ApiCursor::Head)),
        }
    }
    pub fn current(&self) -> Result<ApiCursor, ApiError> {
        self.selected
            .lock()
            .map(|v| *v)
            .map_err(|_| ApiError::Internal("cursor lock poisoned".into()))
    }
    pub fn with_cursor<T>(
        &self,
        cursor: ApiCursor,
        operation: impl FnOnce(&WalletQuery) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let previous = {
            let mut selected = self
                .selected
                .lock()
                .map_err(|_| ApiError::Internal("cursor lock poisoned".into()))?;
            let previous = *selected;
            *selected = cursor;
            previous
        };
        let reset = CursorReset {
            selected: Arc::clone(&self.selected),
            previous,
        };
        let result = operation(&WalletQuery::new(self.context.clone(), cursor));
        drop(reset);
        result
    }
    pub fn head<T>(
        &self,
        operation: impl FnOnce(&WalletQuery) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.with_cursor(ApiCursor::Head, operation)
    }
    pub fn solidity<T>(
        &self,
        operation: impl FnOnce(&WalletQuery) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.with_cursor(ApiCursor::Solidity, operation)
    }
    pub fn pbft<T>(
        &self,
        method: PbftMethod,
        operation: impl FnOnce(&WalletQuery) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        if !method.supported() {
            return Err(ApiError::Unavailable(format!(
                "{} is omitted from the PBFT service",
                method.name()
            )));
        }
        self.with_cursor(ApiCursor::Pbft, operation)
    }
}
struct CursorReset {
    selected: Arc<Mutex<ApiCursor>>,
    previous: ApiCursor,
}
impl Drop for CursorReset {
    fn drop(&mut self) {
        if let Ok(mut selected) = self.selected.lock() {
            *selected = self.previous
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PbftMethod {
    Account,
    AccountById,
    Witnesses,
    Assets,
    AssetByName,
    AssetById,
    PaginatedAssets,
    Exchange,
    Exchanges,
    NowBlock,
    BlockByNum,
    TransactionCount,
    Transaction,
    TransactionInfo,
    DelegatedResource,
    ResourceIndex,
    Constant,
    EstimateEnergy,
    Reward,
    Brokerage,
    ShieldedScan,
    Market,
    BurnTrx,
    GetBlock,
    BandwidthPrices,
    EnergyPrices,
    PaginatedWitnesses,
    TransactionInfoByBlock,
    MemoFee,
    ChainParameters,
    NodeInfo,
    Pending,
    WalletExtension,
    Monitor,
    Network,
}
impl PbftMethod {
    #[must_use]
    pub const fn supported(self) -> bool {
        !matches!(
            self,
            Self::PaginatedWitnesses
                | Self::TransactionInfoByBlock
                | Self::MemoFee
                | Self::ChainParameters
                | Self::NodeInfo
                | Self::Pending
                | Self::WalletExtension
                | Self::Monitor
                | Self::Network
        )
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Account => "GetAccount",
            Self::AccountById => "GetAccountById",
            Self::Witnesses => "ListWitnesses",
            Self::Assets => "GetAssetIssueList",
            Self::AssetByName => "GetAssetIssueByName",
            Self::AssetById => "GetAssetIssueById",
            Self::PaginatedAssets => "GetPaginatedAssetIssueList",
            Self::Exchange => "GetExchangeById",
            Self::Exchanges => "ListExchanges",
            Self::NowBlock => "GetNowBlock",
            Self::BlockByNum => "GetBlockByNum",
            Self::TransactionCount => "GetTransactionCountByBlockNum",
            Self::Transaction => "GetTransactionById",
            Self::TransactionInfo => "GetTransactionInfoById",
            Self::DelegatedResource => "GetDelegatedResource",
            Self::ResourceIndex => "GetDelegatedResourceAccountIndex",
            Self::Constant => "TriggerConstantContract",
            Self::EstimateEnergy => "EstimateEnergy",
            Self::Reward => "GetRewardInfo",
            Self::Brokerage => "GetBrokerageInfo",
            Self::ShieldedScan => "ShieldedScan",
            Self::Market => "MarketQueries",
            Self::BurnTrx => "GetBurnTrx",
            Self::GetBlock => "GetBlock",
            Self::BandwidthPrices => "GetBandwidthPrices",
            Self::EnergyPrices => "GetEnergyPrices",
            Self::PaginatedWitnesses => "GetPaginatedNowWitnessList",
            Self::TransactionInfoByBlock => "GetTransactionInfoByBlockNum",
            Self::MemoFee => "GetMemoFee",
            Self::ChainParameters => "GetChainParameters",
            Self::NodeInfo => "GetNodeInfo",
            Self::Pending => "PendingQueries",
            Self::WalletExtension => "WalletExtension",
            Self::Monitor => "Monitor",
            Self::Network => "Network",
        }
    }
}
