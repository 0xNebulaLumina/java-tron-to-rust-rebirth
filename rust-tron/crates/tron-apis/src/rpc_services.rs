//! Tonic adapters backed by the C022 domain API.

use crate::{ApiContext, ApiCursor, ApiError, BlockingExecutor, RpcDomainProvider, ShieldedWallet, WalletMutation, WalletQuery, interceptors::PreservedRawGrpcMessage};

#[derive(Clone)]
pub struct RpcApiServices {
    context: ApiContext,
    provider: RpcDomainProvider,
    blocking: BlockingExecutor,
    http_cursor: Option<ApiCursor>,
}

impl RpcApiServices {
    #[must_use]
    pub fn new(context: ApiContext) -> Self { Self::with_blocking_executor(context, BlockingExecutor::default()) }
    #[must_use]
    pub fn with_blocking_executor(context: ApiContext, blocking: BlockingExecutor) -> Self {
        let provider=RpcDomainProvider::new(context.clone());
        Self { provider, context, blocking, http_cursor: None }
    }
    #[must_use]
    pub fn with_provider(context: ApiContext, provider: RpcDomainProvider) -> Self { Self { provider, context, blocking: BlockingExecutor::default(), http_cursor: None } }
    #[must_use]
    pub fn with_provider_and_blocking(
        context: ApiContext,
        provider: RpcDomainProvider,
        blocking: BlockingExecutor,
    ) -> Self {
        Self { provider, context, blocking, http_cursor: None }
    }
    pub(crate) fn with_http_cursor(mut self, cursor: ApiCursor) -> Self { self.http_cursor = Some(cursor); self }
    fn query(&self, cursor: ApiCursor) -> WalletQuery { WalletQuery::new(self.context.clone(), self.http_cursor.unwrap_or(cursor)) }
    fn mutation(&self) -> WalletMutation { WalletMutation::new(self.context.clone()) }
    fn response<T>(value: Result<T, ApiError>) -> Result<tonic::Response<T>, tonic::Status> {
        value.map(tonic::Response::new).map_err(Into::into)
    }
    async fn blocking_response<T, F>(&self, work: F) -> Result<tonic::Response<T>, tonic::Status>
    where
        T: Send + 'static,
        F: FnOnce(crate::BlockingCancellation) -> Result<T, ApiError> + Send + 'static,
    {
        self.blocking.run(work).await.map(tonic::Response::new)
    }
    fn identifier(value: &[u8]) -> Result<i64, ApiError> {
        let bytes: [u8; 8] = value.try_into().map_err(|_| ApiError::InvalidArgument("identifier must be an eight-byte big-endian integer".into()))?;
        Ok(i64::from_be_bytes(bytes))
    }
    fn transaction(value: Result<super::TransactionExtention, ApiError>) -> Result<tonic::Response<super::Transaction>, tonic::Status> {
        let extension = value.map_err(tonic::Status::from)?;
        extension.transaction.map(tonic::Response::new).ok_or_else(|| tonic::Status::internal("domain mutation produced no transaction"))
    }
}

#[tonic::async_trait]
impl crate::wallet::wallet_server::Wallet for RpcApiServices {
    async fn get_account(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::Account>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.account(&input.address))
    }
    async fn get_account_by_id(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::Account>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.account_by_id(&input.account_id))
    }
    async fn get_account_balance(
        &self,
        request: tonic::Request<super::AccountBalanceRequest>,
    ) -> std::result::Result<tonic::Response<super::AccountBalanceResponse>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.account_balance(input, ApiCursor::Head))
    }
    async fn get_block_balance_trace(
        &self,
        request: tonic::Request<super::block_balance_trace::BlockIdentifier>,
    ) -> std::result::Result<tonic::Response<super::BlockBalanceTrace>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.block_balance_trace(input, ApiCursor::Head))
    }
    async fn create_transaction(
        &self,
        request: tonic::Request<super::TransferContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().create_transaction(&input))
    }
    async fn create_transaction2(
        &self,
        request: tonic::Request<super::TransferContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().create_transaction(&input))
    }
    async fn broadcast_transaction(
        &self,
        request: tonic::Request<super::Transaction>,
    ) -> std::result::Result<tonic::Response<super::Return>, tonic::Status> {
        let raw = request.extensions().get::<PreservedRawGrpcMessage>()
            .cloned()
            .ok_or_else(|| tonic::Status::internal("BroadcastTransaction requires preserved gRPC request bytes"))?;
        drop(request);
        let mutation = self.mutation();
        self.blocking_response(move |cancellation| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ApiError::Internal("system clock before Unix epoch".into()))?
                .as_millis() as i64;
            Ok(mutation.broadcast_raw_with_cancellation(raw.0.to_vec(), now, false, &cancellation))
        }).await
    }
    async fn update_account(
        &self,
        request: tonic::Request<super::AccountUpdateContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().update_account(&input))
    }
    async fn set_account_id(
        &self,
        request: tonic::Request<super::SetAccountIdContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().set_account_id(&input))
    }
    async fn update_account2(
        &self,
        request: tonic::Request<super::AccountUpdateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_account(&input))
    }
    async fn vote_witness_account(
        &self,
        request: tonic::Request<super::VoteWitnessContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().vote_witness_account(&input))
    }
    async fn update_setting(
        &self,
        request: tonic::Request<super::UpdateSettingContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_setting(&input))
    }
    async fn update_energy_limit(
        &self,
        request: tonic::Request<super::UpdateEnergyLimitContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_energy_limit(&input))
    }
    async fn vote_witness_account2(
        &self,
        request: tonic::Request<super::VoteWitnessContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().vote_witness_account(&input))
    }
    async fn create_asset_issue(
        &self,
        request: tonic::Request<super::AssetIssueContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().create_asset_issue(&input))
    }
    async fn create_asset_issue2(
        &self,
        request: tonic::Request<super::AssetIssueContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().create_asset_issue(&input))
    }
    async fn update_witness(
        &self,
        request: tonic::Request<super::WitnessUpdateContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().update_witness(&input))
    }
    async fn update_witness2(
        &self,
        request: tonic::Request<super::WitnessUpdateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_witness(&input))
    }
    async fn create_account(
        &self,
        request: tonic::Request<super::AccountCreateContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().create_account(&input))
    }
    async fn create_account2(
        &self,
        request: tonic::Request<super::AccountCreateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().create_account(&input))
    }
    async fn create_witness(
        &self,
        request: tonic::Request<super::WitnessCreateContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().create_witness(&input))
    }
    async fn create_witness2(
        &self,
        request: tonic::Request<super::WitnessCreateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().create_witness(&input))
    }
    async fn transfer_asset(
        &self,
        request: tonic::Request<super::TransferAssetContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().transfer_asset(&input))
    }
    async fn transfer_asset2(
        &self,
        request: tonic::Request<super::TransferAssetContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().transfer_asset(&input))
    }
    async fn participate_asset_issue(
        &self,
        request: tonic::Request<super::ParticipateAssetIssueContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().participate_asset_issue(&input))
    }
    async fn participate_asset_issue2(
        &self,
        request: tonic::Request<super::ParticipateAssetIssueContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().participate_asset_issue(&input))
    }
    async fn freeze_balance(
        &self,
        request: tonic::Request<super::FreezeBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().freeze_balance(&input))
    }
    async fn freeze_balance2(
        &self,
        request: tonic::Request<super::FreezeBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().freeze_balance(&input))
    }
    async fn freeze_balance_v2(
        &self,
        request: tonic::Request<super::FreezeBalanceV2Contract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().freeze_balance_v2(&input))
    }
    async fn unfreeze_balance(
        &self,
        request: tonic::Request<super::UnfreezeBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().unfreeze_balance(&input))
    }
    async fn unfreeze_balance2(
        &self,
        request: tonic::Request<super::UnfreezeBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().unfreeze_balance(&input))
    }
    async fn unfreeze_balance_v2(
        &self,
        request: tonic::Request<super::UnfreezeBalanceV2Contract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().unfreeze_balance_v2(&input))
    }
    async fn unfreeze_asset(
        &self,
        request: tonic::Request<super::UnfreezeAssetContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().unfreeze_asset(&input))
    }
    async fn unfreeze_asset2(
        &self,
        request: tonic::Request<super::UnfreezeAssetContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().unfreeze_asset(&input))
    }
    async fn withdraw_balance(
        &self,
        request: tonic::Request<super::WithdrawBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().withdraw_balance(&input))
    }
    async fn withdraw_balance2(
        &self,
        request: tonic::Request<super::WithdrawBalanceContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().withdraw_balance(&input))
    }
    async fn withdraw_expire_unfreeze(
        &self,
        request: tonic::Request<super::WithdrawExpireUnfreezeContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().withdraw_expire_unfreeze(&input))
    }
    async fn delegate_resource(
        &self,
        request: tonic::Request<super::DelegateResourceContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().delegate_resource(&input))
    }
    async fn un_delegate_resource(
        &self,
        request: tonic::Request<super::UnDelegateResourceContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().un_delegate_resource(&input))
    }
    async fn cancel_all_unfreeze_v2(
        &self,
        request: tonic::Request<super::CancelAllUnfreezeV2Contract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().cancel_all_unfreeze_v2(&input))
    }
    async fn update_asset(
        &self,
        request: tonic::Request<super::UpdateAssetContract>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        Self::transaction(self.mutation().update_asset(&input))
    }
    async fn update_asset2(
        &self,
        request: tonic::Request<super::UpdateAssetContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_asset(&input))
    }
    async fn proposal_create(
        &self,
        request: tonic::Request<super::ProposalCreateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().proposal_create(&input))
    }
    async fn proposal_approve(
        &self,
        request: tonic::Request<super::ProposalApproveContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().proposal_approve(&input))
    }
    async fn proposal_delete(
        &self,
        request: tonic::Request<super::ProposalDeleteContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().proposal_delete(&input))
    }
    async fn buy_storage(
        &self,
        request: tonic::Request<super::BuyStorageContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn buy_storage_bytes(
        &self,
        request: tonic::Request<super::BuyStorageBytesContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn sell_storage(
        &self,
        request: tonic::Request<super::SellStorageContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn exchange_create(
        &self,
        request: tonic::Request<super::ExchangeCreateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().exchange_create(&input))
    }
    async fn exchange_inject(
        &self,
        request: tonic::Request<super::ExchangeInjectContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().exchange_inject(&input))
    }
    async fn exchange_withdraw(
        &self,
        request: tonic::Request<super::ExchangeWithdrawContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().exchange_withdraw(&input))
    }
    async fn exchange_transaction(
        &self,
        request: tonic::Request<super::ExchangeTransactionContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().exchange_transaction(&input))
    }
    async fn market_sell_asset(
        &self,
        request: tonic::Request<super::MarketSellAssetContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().market_sell_asset(&input))
    }
    async fn market_cancel_order(
        &self,
        request: tonic::Request<super::MarketCancelOrderContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().market_cancel_order(&input))
    }
    async fn get_market_order_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrder>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.market_order(&input.value))
    }
    async fn get_market_order_by_account(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.market_orders_by_account(&input.value))
    }
    async fn get_market_price_by_pair(
        &self,
        request: tonic::Request<super::MarketOrderPair>,
    ) -> std::result::Result<tonic::Response<super::MarketPriceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.market_prices(&input))
    }
    async fn get_market_order_list_by_pair(
        &self,
        request: tonic::Request<super::MarketOrderPair>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.market_orders_by_pair(&input))
    }
    async fn get_market_pair_list(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderPairList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.market_pairs())
    }
    async fn list_nodes(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NodeList>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.list_nodes()))
    }
    async fn get_asset_issue_by_account(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.assets_by_account(&input.address))
    }
    async fn get_account_net(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::AccountNetMessage>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.account_net(input, ApiCursor::Head))
    }
    async fn get_account_resource(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::AccountResourceMessage>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.account_resource(input, ApiCursor::Head))
    }
    async fn get_asset_issue_by_name(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueContract>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.asset_by_name(&input.value))
    }
    async fn get_asset_issue_list_by_name(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.assets_by_name(&input.value))
    }
    async fn get_asset_issue_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueContract>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.asset_by_id(&input.value))
    }
    async fn get_now_block(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.now_block())
    }
    async fn get_now_block2(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.now_block().map(|v| q.block_extension(v)))
    }
    async fn get_block_by_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.block_by_num(input.num))
    }
    async fn get_block_by_num2(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.block_by_num(input.num).map(|v| q.block_extension(v)))
    }
    async fn get_transaction_count_by_block_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.transaction_count_by_block(input.num))
    }
    async fn get_block_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.block_by_id(&input.value))
    }
    async fn get_block_by_limit_next(
        &self,
        request: tonic::Request<super::BlockLimit>,
    ) -> std::result::Result<tonic::Response<super::BlockList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.blocks(input.start_num,input.end_num))
    }
    async fn get_block_by_limit_next2(
        &self,
        request: tonic::Request<super::BlockLimit>,
    ) -> std::result::Result<tonic::Response<super::BlockListExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.block_range_extension(input.start_num, input.end_num, ApiCursor::Head))
    }
    async fn get_block_by_latest_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.latest_blocks(input.num))
    }
    async fn get_block_by_latest_num2(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockListExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.latest_block_extensions(input.num, ApiCursor::Head))
    }
    async fn get_transaction_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.transaction(&input.value))
    }
    async fn deploy_contract(
        &self,
        request: tonic::Request<super::CreateSmartContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.deploy_contract(input))
    }
    async fn get_contract(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::SmartContract>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.contract(&input.value, ApiCursor::Head))
    }
    async fn get_contract_info(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::SmartContractDataWrapper>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.contract_info(&input.value, ApiCursor::Head))
    }
    async fn trigger_contract(
        &self,
        request: tonic::Request<super::TriggerSmartContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.trigger_contract(input))
    }
    async fn trigger_constant_contract(
        &self,
        request: tonic::Request<super::TriggerSmartContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.trigger_constant(input, ApiCursor::Head)).await
    }
    async fn estimate_energy(
        &self,
        request: tonic::Request<super::TriggerSmartContract>,
    ) -> std::result::Result<tonic::Response<super::EstimateEnergyMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| Ok(provider.estimate_energy(input, ApiCursor::Head))).await
    }
    async fn clear_contract_abi(
        &self,
        request: tonic::Request<super::ClearAbiContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().clear_contract_abi(&input))
    }
    async fn list_witnesses(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::WitnessList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.witnesses())
    }
    async fn get_paginated_now_witness_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::WitnessList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.paginated_witnesses(&input))
    }
    async fn get_delegated_resource(
        &self,
        request: tonic::Request<super::DelegatedResourceMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.delegated_resource(&input.from_address,&input.to_address))
    }
    async fn get_delegated_resource_v2(
        &self,
        request: tonic::Request<super::DelegatedResourceMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.delegated_resource(&input.from_address,&input.to_address))
    }
    async fn get_delegated_resource_account_index(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceAccountIndex>, tonic::Status>
    {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.delegated_resource_index(&input.value))
    }
    async fn get_delegated_resource_account_index_v2(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceAccountIndex>, tonic::Status>
    {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.delegated_resource_index(&input.value))
    }
    async fn get_can_delegated_max_size(
        &self,
        request: tonic::Request<super::CanDelegatedMaxSizeRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::CanDelegatedMaxSizeResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        Self::response(self.provider.delegated_max(input, ApiCursor::Head))
    }
    async fn get_available_unfreeze_count(
        &self,
        request: tonic::Request<super::GetAvailableUnfreezeCountRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::GetAvailableUnfreezeCountResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.available_unfreeze_count(&input.owner_address))
    }
    async fn get_can_withdraw_unfreeze_amount(
        &self,
        request: tonic::Request<super::CanWithdrawUnfreezeAmountRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::CanWithdrawUnfreezeAmountResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.withdrawable_unfreeze_amount(&input.owner_address,input.timestamp))
    }
    async fn list_proposals(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::ProposalList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.proposals())
    }
    async fn get_paginated_proposal_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::ProposalList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.paginated_proposals(&input))
    }
    async fn get_proposal_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Proposal>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(Self::identifier(&input.value).and_then(|id| q.proposal(id)))
    }
    async fn list_exchanges(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::ExchangeList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.exchanges())
    }
    async fn get_paginated_exchange_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::ExchangeList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.paginated_exchanges(&input))
    }
    async fn get_exchange_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Exchange>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(Self::identifier(&input.value).and_then(|id| q.exchange(id)))
    }
    async fn get_chain_parameters(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::ChainParameters>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.chain_parameters())
    }
    async fn get_asset_issue_list(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.assets())
    }
    async fn get_paginated_asset_issue_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.paginated_assets(&input))
    }
    async fn total_transaction(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(Ok(q.total_transactions()))
    }
    async fn get_next_maintenance_time(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.next_maintenance_time())
    }
    async fn get_transaction_info_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::TransactionInfo>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.transaction_info(&input.value))
    }
    async fn account_permission_update(
        &self,
        request: tonic::Request<super::AccountPermissionUpdateContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().account_permission_update(&input))
    }
    async fn get_transaction_sign_weight(
        &self,
        request: tonic::Request<super::Transaction>,
    ) -> std::result::Result<tonic::Response<super::TransactionSignWeight>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.sign_weight(input, ApiCursor::Head))
    }
    async fn get_transaction_approved_list(
        &self,
        request: tonic::Request<super::Transaction>,
    ) -> std::result::Result<tonic::Response<super::TransactionApprovedList>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.approved_list(input, ApiCursor::Head))
    }
    async fn get_node_info(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NodeInfo>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.node_info()))
    }
    async fn get_reward_info(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.reward(&input.value, ApiCursor::Head)))
    }
    async fn get_brokerage_info(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.brokerage(&input.value, ApiCursor::Head)))
    }
    async fn update_brokerage(
        &self,
        request: tonic::Request<super::UpdateBrokerageContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.mutation().update_brokerage(&input))
    }
    async fn create_shielded_transaction(
        &self,
        request: tonic::Request<super::PrivateParameters>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.shielded_transaction(&input, "type.googleapis.com/protocol.ShieldedTransferContract")).await
    }
    async fn get_merkle_tree_voucher_info(
        &self,
        request: tonic::Request<super::OutputPointInfo>,
    ) -> std::result::Result<tonic::Response<super::IncrementalMerkleVoucherInfo>, tonic::Status>
    {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.voucher(input, ApiCursor::Head)).await
    }
    async fn scan_note_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotes>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        self.blocking.run(move |_|provider.scan_ivk(input,ApiCursor::Head)).await.map(tonic::Response::new)
    }
    async fn scan_and_mark_note_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptAndMarkParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesMarked>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        self.blocking.run(move |_|provider.scan_mark(input,ApiCursor::Head)).await.map(tonic::Response::new)
    }
    async fn scan_note_by_ovk(
        &self,
        request: tonic::Request<super::OvkDecryptParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotes>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        self.blocking.run(move |_|provider.scan_ovk(input,ApiCursor::Head)).await.map(tonic::Response::new)
    }
    async fn get_spending_key(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| Ok(ShieldedWallet::spending_key())).await
    }
    async fn get_expanded_spending_key(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::ExpandedSpendingKeyMessage>, tonic::Status>
    {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::expanded_spending_key(&input.value)).await
    }
    async fn get_ak_from_ask(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::ak_from_ask(&input.value)).await
    }
    async fn get_nk_from_nsk(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::nk_from_nsk(&input.value)).await
    }
    async fn get_incoming_viewing_key(
        &self,
        request: tonic::Request<super::ViewingKeyMessage>,
    ) -> std::result::Result<tonic::Response<super::IncomingViewingKeyMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::incoming_viewing_key(&input)).await
    }
    async fn get_diversifier(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::DiversifierMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| Ok(ShieldedWallet::diversifier())).await
    }
    async fn get_new_shielded_address(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::ShieldedAddressInfo>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::new_address()).await
    }
    async fn get_zen_payment_address(
        &self,
        request: tonic::Request<super::IncomingViewingKeyDiversifierMessage>,
    ) -> std::result::Result<tonic::Response<super::PaymentAddressMessage>, tonic::Status> {
        let input = request.into_inner();
        self.blocking_response(move |_| ShieldedWallet::payment_address(&input)).await
    }
    async fn get_rcm(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| Ok(provider.rcm())).await
    }
    async fn is_spend(
        &self,
        request: tonic::Request<super::NoteParameters>,
    ) -> std::result::Result<tonic::Response<super::SpendResult>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| Ok(provider.is_spend(&input, ApiCursor::Head))).await
    }
    async fn create_shielded_transaction_without_spend_auth_sig(
        &self,
        request: tonic::Request<super::PrivateParametersWithoutAsk>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.shielded_transaction(&input, "type.googleapis.com/protocol.ShieldedTransferContract")).await
    }
    async fn get_shield_transaction_hash(
        &self,
        request: tonic::Request<super::Transaction>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| Ok(provider.shield_hash(&input))).await
    }
    async fn create_spend_auth_sig(
        &self,
        request: tonic::Request<super::SpendAuthSigParameters>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.spend_auth(input)).await
    }
    async fn create_shield_nullifier(
        &self,
        request: tonic::Request<super::NfParameters>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.nullifier(&input)).await
    }
    async fn create_shielded_contract_parameters(
        &self,
        request: tonic::Request<super::PrivateShieldedTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::ShieldedTrc20Parameters>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.shielded_trc20(input)).await
    }
    async fn create_shielded_contract_parameters_without_ask(
        &self,
        request: tonic::Request<super::PrivateShieldedTrc20ParametersWithoutAsk>,
    ) -> std::result::Result<tonic::Response<super::ShieldedTrc20Parameters>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.shielded_trc20_without_ask(input)).await
    }
    async fn scan_shielded_trc20_notes_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesTrc20>, tonic::Status> {
        let input=request.into_inner();let provider=self.provider.clone();
        self.blocking.run(move |_|provider.scan_trc20_ivk(input,ApiCursor::Head)).await.map(tonic::Response::new)
    }
    async fn scan_shielded_trc20_notes_by_ovk(
        &self,
        request: tonic::Request<super::OvkDecryptTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesTrc20>, tonic::Status> {
        let input=request.into_inner();let provider=self.provider.clone();
        self.blocking.run(move |_|provider.scan_trc20_ovk(input,ApiCursor::Head)).await.map(tonic::Response::new)
    }
    async fn is_shielded_trc20_contract_note_spent(
        &self,
        request: tonic::Request<super::NfTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::NullifierResult>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| Ok(provider.trc20_spent(&input, ApiCursor::Head))).await
    }
    async fn get_trigger_input_for_shielded_trc20_contract(
        &self,
        request: tonic::Request<super::ShieldedTrc20TriggerContractParameters>,
    ) -> std::result::Result<tonic::Response<super::BytesMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        self.blocking_response(move |_| provider.trigger_input(input)).await
    }
    async fn create_common_transaction(
        &self,
        request: tonic::Request<super::Transaction>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.mutation().create_common_transaction(input)))
    }
    async fn get_transaction_info_by_block_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::TransactionInfoList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.transaction_infos_by_block(input.num))
    }
    async fn get_burn_trx(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.burn_trx())
    }
    async fn get_transaction_from_pending(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.pending_transaction(&input.value))
    }
    async fn get_transaction_list_from_pending(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::TransactionIdList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.pending_ids())
    }
    async fn get_pending_size(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.pending_size())
    }
    async fn get_block(
        &self,
        request: tonic::Request<super::BlockReq>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.get_block(input, ApiCursor::Head))
    }
    async fn get_bandwidth_prices(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::PricesResponseMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.bandwidth_prices())
    }
    async fn get_energy_prices(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::PricesResponseMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.energy_prices())
    }
    async fn get_memo_fee(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::PricesResponseMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.memo_fee())
    }
}

#[tonic::async_trait]
impl crate::solidity::wallet_solidity_server::WalletSolidity for RpcApiServices {
    async fn get_account(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::Account>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.account(&input.address))
    }
    async fn get_account_by_id(
        &self,
        request: tonic::Request<super::Account>,
    ) -> std::result::Result<tonic::Response<super::Account>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.account_by_id(&input.account_id))
    }
    async fn list_witnesses(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::WitnessList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.witnesses())
    }
    async fn get_paginated_now_witness_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::WitnessList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.paginated_witnesses(&input))
    }
    async fn get_asset_issue_list(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.assets())
    }
    async fn get_paginated_asset_issue_list(
        &self,
        request: tonic::Request<super::PaginatedMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.paginated_assets(&input))
    }
    async fn get_asset_issue_by_name(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueContract>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.asset_by_name(&input.value))
    }
    async fn get_asset_issue_list_by_name(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.assets_by_name(&input.value))
    }
    async fn get_asset_issue_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::AssetIssueContract>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.asset_by_id(&input.value))
    }
    async fn get_now_block(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.now_block())
    }
    async fn get_now_block2(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.now_block().map(|v| q.block_extension(v)))
    }
    async fn get_block_by_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.block_by_num(input.num))
    }
    async fn get_block_by_num2(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.block_by_num(input.num).map(|v| q.block_extension(v)))
    }
    async fn get_transaction_count_by_block_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.transaction_count_by_block(input.num))
    }
    async fn get_delegated_resource(
        &self,
        request: tonic::Request<super::DelegatedResourceMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.delegated_resource(&input.from_address,&input.to_address))
    }
    async fn get_delegated_resource_v2(
        &self,
        request: tonic::Request<super::DelegatedResourceMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.delegated_resource(&input.from_address,&input.to_address))
    }
    async fn get_delegated_resource_account_index(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceAccountIndex>, tonic::Status>
    {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.delegated_resource_index(&input.value))
    }
    async fn get_delegated_resource_account_index_v2(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::DelegatedResourceAccountIndex>, tonic::Status>
    {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.delegated_resource_index(&input.value))
    }
    async fn get_can_delegated_max_size(
        &self,
        request: tonic::Request<super::CanDelegatedMaxSizeRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::CanDelegatedMaxSizeResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        Self::response(self.provider.delegated_max(input, self.http_cursor.unwrap_or(ApiCursor::Solidity)))
    }
    async fn get_available_unfreeze_count(
        &self,
        request: tonic::Request<super::GetAvailableUnfreezeCountRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::GetAvailableUnfreezeCountResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.available_unfreeze_count(&input.owner_address))
    }
    async fn get_can_withdraw_unfreeze_amount(
        &self,
        request: tonic::Request<super::CanWithdrawUnfreezeAmountRequestMessage>,
    ) -> std::result::Result<
        tonic::Response<super::CanWithdrawUnfreezeAmountResponseMessage>,
        tonic::Status,
    > {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.withdrawable_unfreeze_amount(&input.owner_address,input.timestamp))
    }
    async fn get_exchange_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Exchange>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(Self::identifier(&input.value).and_then(|id| q.exchange(id)))
    }
    async fn list_exchanges(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::ExchangeList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.exchanges())
    }
    async fn get_transaction_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::Transaction>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.transaction(&input.value))
    }
    async fn get_transaction_info_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::TransactionInfo>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.transaction_info(&input.value))
    }
    async fn get_merkle_tree_voucher_info(
        &self,
        request: tonic::Request<super::OutputPointInfo>,
    ) -> std::result::Result<tonic::Response<super::IncrementalMerkleVoucherInfo>, tonic::Status>
    {
        let input = request.into_inner();
        let provider = self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking_response(move |_| provider.voucher(input, cursor)).await
    }
    async fn scan_note_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotes>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking.run(move |_|provider.scan_ivk(input,cursor)).await.map(tonic::Response::new)
    }
    async fn scan_and_mark_note_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptAndMarkParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesMarked>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking.run(move |_|provider.scan_mark(input,cursor)).await.map(tonic::Response::new)
    }
    async fn scan_note_by_ovk(
        &self,
        request: tonic::Request<super::OvkDecryptParameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotes>, tonic::Status> {
        let input = request.into_inner();
        let provider=self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking.run(move |_|provider.scan_ovk(input,cursor)).await.map(tonic::Response::new)
    }
    async fn is_spend(
        &self,
        request: tonic::Request<super::NoteParameters>,
    ) -> std::result::Result<tonic::Response<super::SpendResult>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking_response(move |_| Ok(provider.is_spend(&input, cursor))).await
    }
    async fn scan_shielded_trc20_notes_by_ivk(
        &self,
        request: tonic::Request<super::IvkDecryptTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesTrc20>, tonic::Status> {
        let input=request.into_inner();let provider=self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking.run(move |_|provider.scan_trc20_ivk(input,cursor)).await.map(tonic::Response::new)
    }
    async fn scan_shielded_trc20_notes_by_ovk(
        &self,
        request: tonic::Request<super::OvkDecryptTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::DecryptNotesTrc20>, tonic::Status> {
        let input=request.into_inner();let provider=self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking.run(move |_|provider.scan_trc20_ovk(input,cursor)).await.map(tonic::Response::new)
    }
    async fn is_shielded_trc20_contract_note_spent(
        &self,
        request: tonic::Request<super::NfTrc20Parameters>,
    ) -> std::result::Result<tonic::Response<super::NullifierResult>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking_response(move |_| Ok(provider.trc20_spent(&input, cursor))).await
    }
    async fn get_reward_info(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.reward(&input.value, self.http_cursor.unwrap_or(ApiCursor::Solidity))))
    }
    async fn get_brokerage_info(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.brokerage(&input.value, self.http_cursor.unwrap_or(ApiCursor::Solidity))))
    }
    async fn trigger_constant_contract(
        &self,
        request: tonic::Request<super::TriggerSmartContract>,
    ) -> std::result::Result<tonic::Response<super::TransactionExtention>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking_response(move |_| provider.trigger_constant(input, cursor)).await
    }
    async fn estimate_energy(
        &self,
        request: tonic::Request<super::TriggerSmartContract>,
    ) -> std::result::Result<tonic::Response<super::EstimateEnergyMessage>, tonic::Status> {
        let input = request.into_inner();
        let provider = self.provider.clone();
        let cursor = self.http_cursor.unwrap_or(ApiCursor::Solidity);
        self.blocking_response(move |_| Ok(provider.estimate_energy(input, cursor))).await
    }
    async fn get_transaction_info_by_block_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::TransactionInfoList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.transaction_infos_by_block(input.num))
    }
    async fn get_market_order_by_id(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrder>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.market_order(&input.value))
    }
    async fn get_market_order_by_account(
        &self,
        request: tonic::Request<super::BytesMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.market_orders_by_account(&input.value))
    }
    async fn get_market_price_by_pair(
        &self,
        request: tonic::Request<super::MarketOrderPair>,
    ) -> std::result::Result<tonic::Response<super::MarketPriceList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.market_prices(&input))
    }
    async fn get_market_order_list_by_pair(
        &self,
        request: tonic::Request<super::MarketOrderPair>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.market_orders_by_pair(&input))
    }
    async fn get_market_pair_list(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::MarketOrderPairList>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.market_pairs())
    }
    async fn get_burn_trx(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::NumberMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.burn_trx())
    }
    async fn get_block(
        &self,
        request: tonic::Request<super::BlockReq>,
    ) -> std::result::Result<tonic::Response<super::BlockExtention>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.get_block(input, self.http_cursor.unwrap_or(ApiCursor::Solidity)))
    }
    async fn get_bandwidth_prices(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::PricesResponseMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.bandwidth_prices())
    }
    async fn get_energy_prices(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::PricesResponseMessage>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(self.http_cursor.unwrap_or(ApiCursor::Solidity));
        Self::response(q.energy_prices())
    }
}

#[tonic::async_trait]
impl crate::extension::wallet_extension_server::WalletExtension for RpcApiServices {
    async fn get_transactions_from_this(
        &self,
        request: tonic::Request<super::AccountPaginated>,
    ) -> std::result::Result<tonic::Response<super::TransactionList>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn get_transactions_from_this2(
        &self,
        request: tonic::Request<super::AccountPaginated>,
    ) -> std::result::Result<tonic::Response<super::TransactionListExtention>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn get_transactions_to_this(
        &self,
        request: tonic::Request<super::AccountPaginated>,
    ) -> std::result::Result<tonic::Response<super::TransactionList>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
    async fn get_transactions_to_this2(
        &self,
        request: tonic::Request<super::AccountPaginated>,
    ) -> std::result::Result<tonic::Response<super::TransactionListExtention>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
}

#[tonic::async_trait]
impl crate::database::database_server::Database for RpcApiServices {
    async fn get_block_reference(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::BlockReference>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.block_reference())
    }
    async fn get_dynamic_properties(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::DynamicProperties>, tonic::Status> {
        let input = request.into_inner();
        Self::response(self.provider.dynamic_properties())
    }
    async fn get_now_block(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.now_block())
    }
    async fn get_block_by_num(
        &self,
        request: tonic::Request<super::NumberMessage>,
    ) -> std::result::Result<tonic::Response<super::Block>, tonic::Status> {
        let input = request.into_inner();
        let q = self.query(ApiCursor::Head);
        Self::response(q.block_by_num(input.num))
    }
}

#[tonic::async_trait]
impl crate::monitor::monitor_server::Monitor for RpcApiServices {
    async fn get_stats_info(
        &self,
        request: tonic::Request<super::EmptyMessage>,
    ) -> std::result::Result<tonic::Response<super::MetricsInfo>, tonic::Status> {
        let input = request.into_inner();
        Ok(tonic::Response::new(self.provider.metrics()))
    }
}

#[tonic::async_trait]
impl crate::network::network_server::Network for RpcApiServices {}

#[tonic::async_trait]
impl crate::zksnark::tron_zksnark_server::TronZksnark for RpcApiServices {
    async fn check_zksnark_proof(
        &self,
        request: tonic::Request<super::ZksnarkRequest>,
    ) -> std::result::Result<tonic::Response<super::ZksnarkResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("method is not implemented by the pinned Java service"))
    }
}
