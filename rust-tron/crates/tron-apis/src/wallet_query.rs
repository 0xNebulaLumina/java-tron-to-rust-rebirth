use prost::Message;
use tron_crypto::selected_digest;
use tron_execution::{BlockLimits, RawBlock, RawWireTransaction};
use tron_protocol::protocol::*;
use tron_state::{StoreKind, dynamic};

use crate::{ApiContext, ApiCursor, ApiError, TypedReadView};

const MAX_PAGE: usize = 100;
const MAX_FULL_LIST_ITEMS: usize = 10_000;
const MAX_FULL_LIST_BYTES: usize = 16 * 1024 * 1024;
const MAX_MARKET_TRAVERSAL: usize = 10_000;
const MAX_BLOCK_RANGE: i64 = 100;

#[derive(Clone)]
pub struct WalletQuery {
    context: ApiContext,
    cursor: ApiCursor,
}

impl WalletQuery {
    #[must_use]
    pub fn new(context: ApiContext, cursor: ApiCursor) -> Self {
        Self { context, cursor }
    }
    #[must_use]
    pub fn head(context: ApiContext) -> Self {
        Self::new(context, ApiCursor::Head)
    }
    #[must_use]
    pub fn solidity(context: ApiContext) -> Self {
        Self::new(context, ApiCursor::Solidity)
    }
    #[must_use]
    pub fn pbft(context: ApiContext) -> Self {
        Self::new(context, ApiCursor::Pbft)
    }
    #[must_use]
    pub const fn cursor(&self) -> ApiCursor {
        self.cursor
    }
    fn view(&self) -> TypedReadView {
        self.context.view(self.cursor)
    }

    pub fn account(&self, address: &[u8]) -> Result<Account, ApiError> {
        self.decode(StoreKind::Account, address, "account")
    }
    pub fn account_by_id(&self, id: &[u8]) -> Result<Account, ApiError> {
        let address = self.bytes(StoreKind::AccountIdIndex, id, "account id")?;
        self.account(&address)
    }
    pub fn asset_by_id(&self, id: &[u8]) -> Result<AssetIssueContract, ApiError> {
        self.decode(StoreKind::AssetIssueV2, id, "asset")
    }
    pub fn assets_by_name(&self, name: &[u8]) -> Result<AssetIssueList, ApiError> {
        Ok(AssetIssueList {
            asset_issue: self
                .all::<AssetIssueContract>(StoreKind::AssetIssue)?
                .into_iter()
                .filter(|v| v.name == name)
                .collect(),
        })
    }
    pub fn asset_by_name(&self, name: &[u8]) -> Result<AssetIssueContract, ApiError> {
        let mut found = self.assets_by_name(name)?.asset_issue;
        if found.len() != 1 {
            return Err(ApiError::NotFound(
                "asset is not uniquely identified by name".into(),
            ));
        }
        Ok(found.remove(0))
    }
    pub fn assets_by_account(&self, address: &[u8]) -> Result<AssetIssueList, ApiError> {
        Ok(AssetIssueList {
            asset_issue: self
                .all::<AssetIssueContract>(StoreKind::AssetIssueV2)?
                .into_iter()
                .filter(|v| v.owner_address == address)
                .collect(),
        })
    }
    pub fn assets(&self) -> Result<AssetIssueList, ApiError> {
        Ok(AssetIssueList {
            asset_issue: self.all(StoreKind::AssetIssueV2)?,
        })
    }
    pub fn paginated_assets(&self, page: &PaginatedMessage) -> Result<AssetIssueList, ApiError> {
        Ok(AssetIssueList {
            asset_issue: self.page(StoreKind::AssetIssueV2, page, false)?,
        })
    }

    pub fn witnesses(&self) -> Result<WitnessList, ApiError> {
        let mut witnesses = self.all::<Witness>(StoreKind::Witness)?;
        witnesses.sort_by(|a, b| {
            b.vote_count
                .cmp(&a.vote_count)
                .then_with(|| a.address.cmp(&b.address))
        });
        Ok(WitnessList { witnesses })
    }
    pub fn paginated_witnesses(&self, page: &PaginatedMessage) -> Result<WitnessList, ApiError> {
        let mut witnesses: Vec<Witness> = self.page(StoreKind::Witness, page, true)?;
        witnesses.sort_by(|a, b| b.vote_count.cmp(&a.vote_count).then_with(|| a.address.cmp(&b.address)));
        Ok(WitnessList { witnesses })
    }
    pub fn proposals(&self) -> Result<ProposalList, ApiError> {
        Ok(ProposalList {
            proposals: self.all(StoreKind::Proposal)?,
        })
    }
    pub fn proposal(&self, id: i64) -> Result<Proposal, ApiError> {
        self.decode(StoreKind::Proposal, &id.to_be_bytes(), "proposal")
    }
    pub fn paginated_proposals(&self, page: &PaginatedMessage) -> Result<ProposalList, ApiError> {
        Ok(ProposalList { proposals: self.page(StoreKind::Proposal, page, false)? })
    }
    pub fn exchanges(&self) -> Result<ExchangeList, ApiError> {
        Ok(ExchangeList {
            exchanges: self.all(self.exchange_store())?,
        })
    }
    pub fn exchange(&self, id: i64) -> Result<Exchange, ApiError> {
        self.decode(self.exchange_store(), &id.to_be_bytes(), "exchange")
    }
    pub fn paginated_exchanges(&self, page: &PaginatedMessage) -> Result<ExchangeList, ApiError> {
        Ok(ExchangeList { exchanges: self.page(self.exchange_store(), page, false)? })
    }

    pub fn market_order(&self, id: &[u8]) -> Result<MarketOrder, ApiError> {
        self.decode(StoreKind::MarketOrder, id, "market order")
    }
    pub fn market_orders_by_account(&self, address: &[u8]) -> Result<MarketOrderList, ApiError> {
        let raw = self.bytes(StoreKind::MarketAccount, address, "market account")?;
        if raw.len() > MAX_FULL_LIST_BYTES {
            return Err(work_cap("market account byte cap exceeded"));
        }
        let account = MarketAccountOrder::decode(raw.as_slice()).map_err(codec)?;
        if account.orders.len() > MAX_MARKET_TRAVERSAL {
            return Err(work_cap("market account order cap exceeded"));
        }
        let mut orders = Vec::with_capacity(account.orders.len());
        let mut bytes = raw.len();
        let mut visited = std::collections::HashSet::with_capacity(account.orders.len());
        for id in account.orders {
            if !visited.insert(id.clone()) {
                return Err(ApiError::Internal("duplicate market order id".into()));
            }
            let encoded = self.bytes(StoreKind::MarketOrder, &id, "market order")?;
            bytes = bytes.saturating_add(encoded.len());
            if bytes > MAX_FULL_LIST_BYTES {
                return Err(work_cap("market account order byte cap exceeded"));
            }
            orders.push(MarketOrder::decode(encoded.as_slice()).map_err(codec)?);
        }
        Ok(MarketOrderList { orders })
    }
    pub fn market_prices(&self, pair: &MarketOrderPair) -> Result<MarketPriceList, ApiError> {
        let prefix = market_pair(pair)?;
        let rows = self.bounded_rows(
            StoreKind::MarketPairPriceToOrder,
            &prefix,
            MAX_MARKET_TRAVERSAL,
            "market price",
        )?;
        let mut prices = Vec::with_capacity(rows.len());
        for (key, _) in rows {
            if key.len() < prefix.len() + 16 {
                return Err(ApiError::Internal("malformed market price key".into()));
            }
            prices.push(MarketPrice {
                sell_token_quantity: i64::from_be_bytes(
                    key[prefix.len()..prefix.len() + 8].try_into().expect("length checked"),
                ),
                buy_token_quantity: i64::from_be_bytes(
                    key[prefix.len() + 8..prefix.len() + 16].try_into().expect("length checked"),
                ),
            });
        }
        Ok(MarketPriceList {
            sell_token_id: pair.sell_token_id.clone(),
            buy_token_id: pair.buy_token_id.clone(),
            prices,
        })
    }
    pub fn market_orders_by_pair(
        &self,
        pair: &MarketOrderPair,
    ) -> Result<MarketOrderList, ApiError> {
        let prefix = market_pair(pair)?;
        let mut orders = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut encoded_bytes = 0usize;
        for (_, value) in self.view().store(StoreKind::MarketPairPriceToOrder).prefix_window(&prefix, 0, MAX_PAGE) {
            encoded_bytes = encoded_bytes.saturating_add(value.len());
            if encoded_bytes > MAX_FULL_LIST_BYTES { return Err(ApiError::InvalidArgument("market order traversal byte cap exceeded".into())); }
            let ids = MarketOrderIdList::decode(value.as_slice()).map_err(codec)?;
            let mut id = ids.head;
            while !id.is_empty() {
                if orders.len() >= MAX_MARKET_TRAVERSAL { return Err(ApiError::InvalidArgument("market order traversal cardinality cap exceeded".into())); }
                if !visited.insert(id.clone()) { return Err(ApiError::Internal("cycle in market order chain".into())); }
                let encoded = self.bytes(StoreKind::MarketOrder, &id, "market order")?;
                encoded_bytes = encoded_bytes.saturating_add(encoded.len());
                if encoded_bytes > MAX_FULL_LIST_BYTES { return Err(work_cap("market order traversal byte cap exceeded")); }
                let order = MarketOrder::decode(encoded.as_slice()).map_err(codec)?;
                id = order.next.clone();
                orders.push(order);
            }
        }
        Ok(MarketOrderList { orders })
    }
    pub fn market_pairs(&self) -> Result<MarketOrderPairList, ApiError> {
        let rows = self.bounded_rows(
            StoreKind::MarketPairToPrice,
            &[],
            MAX_MARKET_TRAVERSAL,
            "market pair",
        )?;
        let mut order_pair = Vec::with_capacity(rows.len());
        for (key, _) in rows {
            if key.len() != 38 {
                return Err(ApiError::Internal("malformed market pair key".into()));
            }
            order_pair.push(MarketOrderPair {
                sell_token_id: key[..19].to_vec(),
                buy_token_id: key[19..].to_vec(),
            });
        }
        Ok(MarketOrderPairList { order_pair })
    }

    pub fn transaction(&self, id: &[u8]) -> Result<Transaction, ApiError> {
        self.decode(StoreKind::Transaction, id, "transaction")
    }
    pub fn transaction_info(&self, id: &[u8]) -> Result<TransactionInfo, ApiError> {
        self.decode(StoreKind::TransactionHistory, id, "transaction info")
    }
    pub fn transaction_infos_by_block(&self, number: i64) -> Result<TransactionInfoList, ApiError> {
        let prefix = number.to_be_bytes();
        let rows = self.bounded_rows(
            StoreKind::TransactionRet,
            &prefix,
            MAX_FULL_LIST_ITEMS,
            "transaction history",
        )?;
        Ok(TransactionInfoList {
            transaction_info: rows.into_iter()
                .map(|(_, value)| TransactionInfo::decode(value.as_slice()).map_err(codec))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn pending_size(&self) -> Result<NumberMessage, ApiError> {
        let pending = self.context.pending();
        let guard = pending
            .lock()
            .map_err(|_| ApiError::Internal("pending pool lock poisoned".into()))?;
        Ok(NumberMessage {
            num: i64::try_from(guard.len()).unwrap_or(i64::MAX),
        })
    }
    pub fn pending_ids(&self) -> Result<TransactionIdList, ApiError> {
        let pending = self.context.pending();
        let guard = pending
            .lock()
            .map_err(|_| ApiError::Internal("pending pool lock poisoned".into()))?;
        Ok(TransactionIdList {
            tx_id: guard
                .pending_ids()
                .into_iter()
                .map(|id| hex(id.as_bytes()))
                .collect(),
        })
    }
    pub fn pending_transaction(&self, id: &[u8]) -> Result<Transaction, ApiError> {
        let id: [u8; 32] = id.try_into().map_err(|_| {
            ApiError::InvalidArgument("pending transaction id must be 32 bytes".into())
        })?;
        let pending = self.context.pending();
        let guard = pending
            .lock()
            .map_err(|_| ApiError::Internal("pending pool lock poisoned".into()))?;
        guard
            .pending_transaction(&id.into())
            .map(|item| item.transaction.message().clone())
            .ok_or_else(|| ApiError::NotFound(format!(
                "pending transaction {} is unavailable",
                hex(&id)
            )))
    }

    pub fn block_by_num(&self, number: i64) -> Result<Block, ApiError> {
        if number < 0 {
            return Err(ApiError::InvalidArgument(
                "block number must be non-negative".into(),
            ));
        }
        let id = self.bytes(StoreKind::BlockIndex, &number.to_be_bytes(), "block")?;
        self.decode(StoreKind::Block, &id, "block")
    }
    pub fn block_by_id(&self, id: &[u8]) -> Result<Block, ApiError> {
        self.decode(StoreKind::Block, id, "block")
    }
    pub fn block_extension_by_num(&self, number: i64) -> Result<BlockExtention, ApiError> {
        if number < 0 {
            return Err(ApiError::InvalidArgument("block number must be non-negative".into()));
        }
        let id = self.bytes(StoreKind::BlockIndex, &number.to_be_bytes(), "block")?;
        let bytes = self.bytes(StoreKind::Block, &id, "block")?;
        self.block_extension_bytes(&bytes)
    }
    pub fn block_extension_by_id(&self, id: &[u8]) -> Result<BlockExtention, ApiError> {
        let bytes = self.bytes(StoreKind::Block, id, "block")?;
        self.block_extension_bytes(&bytes)
    }
    pub fn block_extension_bytes(&self, bytes: &[u8]) -> Result<BlockExtention, ApiError> {
        let raw = RawBlock::decode(bytes, BlockLimits::default())
            .map_err(|error| ApiError::Internal(format!("stored block wire is invalid: {error}")))?;
        let blockid = raw.block_id(self.context.crypto_engine())
            .map_err(|error| ApiError::Internal(format!("stored block header is invalid: {error}")))?
            .as_bytes().to_vec();
        let transactions = raw.message.transactions.iter().zip(raw.transaction_bytes()).map(|(transaction, wire)| {
            let txid = RawWireTransaction::decode(wire.to_vec())
                .map_err(|error| ApiError::Internal(format!("stored transaction wire is invalid: {error}")))?
                .transaction_id(self.context.crypto_engine()).as_bytes().to_vec();
            Ok(TransactionExtention { transaction: Some(transaction.clone()), txid, ..Default::default() })
        }).collect::<Result<Vec<_>, ApiError>>()?;
        Ok(BlockExtention { transactions, block_header: raw.message.block_header, blockid })
    }
    pub fn now_block(&self) -> Result<Block, ApiError> {
        self.block_by_num(self.dynamic_long("LATEST_BLOCK_HEADER_NUMBER")?)
    }
    pub fn blocks(&self, start: i64, end: i64) -> Result<BlockList, ApiError> {
        if start < 0 || end <= start || end - start > MAX_BLOCK_RANGE {
            return Err(ApiError::InvalidArgument(format!(
                "block range must satisfy 0 <= start < end and contain at most {MAX_BLOCK_RANGE} blocks"
            )));
        }
        let mut block = Vec::with_capacity((end - start) as usize);
        for n in start..end {
            block.push(self.block_by_num(n)?)
        }
        Ok(BlockList { block })
    }
    pub fn latest_blocks(&self, count: i64) -> Result<BlockList, ApiError> {
        if count <= 0 || count > MAX_BLOCK_RANGE {
            return Err(ApiError::InvalidArgument(format!(
                "latest block count must be in 1..={MAX_BLOCK_RANGE}"
            )));
        }
        let head = self.dynamic_long("LATEST_BLOCK_HEADER_NUMBER")?;
        self.blocks((head - count + 1).max(0), head + 1)
    }
    pub fn transaction_count_by_block(&self, number: i64) -> Result<NumberMessage, ApiError> {
        Ok(NumberMessage {
            num: self.block_by_num(number)?.transactions.len() as i64,
        })
    }
    pub fn block_extension(&self, block: Block) -> BlockExtention {
        let blockid = block
            .block_header
            .as_ref()
            .and_then(|h| h.raw_data.as_ref())
            .map(|raw| tron_primitives::BlockId::new(raw.number, selected_digest(self.context.crypto_engine(), &raw.encode_to_vec()).into()).as_bytes().to_vec())
            .unwrap_or_default();
        let transactions = block
            .transactions
            .iter()
            .map(|tx| TransactionExtention {
                transaction: Some(tx.clone()),
                txid: tx
                    .raw_data
                    .as_ref()
                    .map(|r| selected_digest(self.context.crypto_engine(), &r.encode_to_vec()).to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            })
            .collect();
        BlockExtention {
            transactions,
            block_header: block.block_header,
            blockid,
        }
    }

    pub fn delegated_resource(
        &self,
        from: &[u8],
        to: &[u8],
    ) -> Result<DelegatedResourceList, ApiError> {
        let mut prefix = from.to_vec();
        prefix.extend_from_slice(to);
        let rows = self.bounded_rows(
            StoreKind::DelegatedResource,
            &prefix,
            MAX_FULL_LIST_ITEMS,
            "delegated resource",
        )?;
        Ok(DelegatedResourceList {
            delegated_resource: rows.into_iter()
                .map(|(_, value)| DelegatedResource::decode(value.as_slice()).map_err(codec))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn delegated_resource_index(
        &self,
        address: &[u8],
    ) -> Result<DelegatedResourceAccountIndex, ApiError> {
        self.decode(
            StoreKind::DelegatedResourceAccountIndex,
            address,
            "delegated resource account index",
        )
    }
    pub fn available_unfreeze_count(
        &self,
        address: &[u8],
    ) -> Result<GetAvailableUnfreezeCountResponseMessage, ApiError> {
        let account = self.account(address)?;
        Ok(GetAvailableUnfreezeCountResponseMessage {
            count: 32_i64.saturating_sub(account.unfrozen_v2.len() as i64),
        })
    }
    pub fn withdrawable_unfreeze_amount(
        &self,
        address: &[u8],
        timestamp: i64,
    ) -> Result<CanWithdrawUnfreezeAmountResponseMessage, ApiError> {
        let account = self.account(address)?;
        Ok(CanWithdrawUnfreezeAmountResponseMessage {
            amount: account
                .unfrozen_v2
                .iter()
                .filter(|v| v.unfreeze_expire_time <= timestamp)
                .map(|v| v.unfreeze_amount)
                .sum(),
        })
    }

    /// Exact pinned java-tron behavior: `TransactionStore::getTotalTransactions`
    /// is deprecated and returns zero without walking the transaction store.
    #[must_use]
    pub const fn total_transactions(&self) -> NumberMessage {
        NumberMessage { num: 0 }
    }
    pub fn next_maintenance_time(&self) -> Result<NumberMessage, ApiError> {
        Ok(NumberMessage {
            num: self.dynamic_long("NEXT_MAINTENANCE_TIME")?,
        })
    }
    pub fn burn_trx(&self) -> Result<NumberMessage, ApiError> {
        Ok(NumberMessage {
            num: self.dynamic_long("BURN_TRX_AMOUNT")?,
        })
    }
    pub fn bandwidth_prices(&self) -> Result<PricesResponseMessage, ApiError> {
        self.price("BANDWIDTH_PRICE_HISTORY")
    }
    pub fn energy_prices(&self) -> Result<PricesResponseMessage, ApiError> {
        self.price("ENERGY_PRICE_HISTORY")
    }
    pub fn memo_fee(&self) -> Result<PricesResponseMessage, ApiError> {
        self.price("MEMO_FEE_HISTORY")
    }
    pub fn chain_parameters(&self) -> Result<ChainParameters, ApiError> {
        let parameters = dynamic::KEYS
            .iter()
            .filter_map(|(name, key)| {
                self.view()
                    .store(StoreKind::DynamicProperties)
                    .get(key)
                    .and_then(|v| decode_i64(&v))
                    .map(|value| chain_parameters::ChainParameter {
                        key: (*name).into(),
                        value,
                    })
            })
            .collect();
        Ok(ChainParameters {
            chain_parameter: parameters,
        })
    }
    pub fn block_reference(&self) -> Result<BlockReference, ApiError> {
        let number = self.dynamic_long("LATEST_BLOCK_HEADER_NUMBER")?;
        let hash = self.dynamic_raw("LATEST_BLOCK_HEADER_HASH")?;
        Ok(BlockReference {
            block_num: number,
            block_hash: hash.get(8..16).unwrap_or(&hash).to_vec(),
        })
    }

    fn exchange_store(&self) -> StoreKind {
        if self.dynamic_long("ALLOW_SAME_TOKEN_NAME").unwrap_or(0) == 0 {
            StoreKind::Exchange
        } else {
            StoreKind::ExchangeV2
        }
    }
    fn price(&self, name: &str) -> Result<PricesResponseMessage, ApiError> {
        Ok(PricesResponseMessage {
            prices: String::from_utf8(self.dynamic_raw(name)?)
                .map_err(|_| ApiError::Internal(format!("{name} is not UTF-8")))?,
        })
    }
    fn dynamic_raw(&self, name: &str) -> Result<Vec<u8>, ApiError> {
        let key = dynamic::key(name)
            .ok_or_else(|| ApiError::Internal(format!("unknown dynamic property {name}")))?;
        self.bytes(StoreKind::DynamicProperties, key, name)
    }
    fn dynamic_long(&self, name: &str) -> Result<i64, ApiError> {
        let bytes = self.dynamic_raw(name)?;
        decode_i64(&bytes)
            .ok_or_else(|| ApiError::Internal(format!("dynamic property {name} is not an i64")))
    }
    fn bytes(&self, kind: StoreKind, key: &[u8], name: &str) -> Result<Vec<u8>, ApiError> {
        self.view()
            .store(kind)
            .get(key)
            .ok_or_else(|| ApiError::NotFound(format!("{name} not found")))
    }
    fn decode<M: Message + Default>(
        &self,
        kind: StoreKind,
        key: &[u8],
        name: &str,
    ) -> Result<M, ApiError> {
        M::decode(self.bytes(kind, key, name)?.as_slice()).map_err(codec)
    }
    fn all<M: Message + Default>(&self, kind: StoreKind) -> Result<Vec<M>, ApiError> {
        let rows = self.view().store(kind).prefix_window(&[], 0, MAX_FULL_LIST_ITEMS + 1);
        if rows.len() > MAX_FULL_LIST_ITEMS { return Err(ApiError::InvalidArgument("full-list server work cap exceeded".into())); }
        let mut bytes = 0usize;
        rows.into_iter().map(|(_, value)| {
            bytes = bytes.saturating_add(value.len());
            if bytes > MAX_FULL_LIST_BYTES { return Err(ApiError::InvalidArgument("full-list byte cap exceeded".into())); }
            M::decode(value.as_slice()).map_err(codec)
        }).collect()
    }
    fn page<M: Message + Default>(&self, kind: StoreKind, page: &PaginatedMessage, positive_limit: bool) -> Result<Vec<M>, ApiError> {
        let (offset, limit) = pagination(page.offset, page.limit, positive_limit)?;
        let rows = self.view().store(kind).prefix_window(&[], offset, limit);
        let bytes = rows.iter().try_fold(0usize, |total, (key, value)| {
            total.checked_add(key.len())?.checked_add(value.len())
        }).ok_or_else(|| work_cap("page byte count overflow"))?;
        if bytes > MAX_FULL_LIST_BYTES {
            return Err(work_cap("page byte cap exceeded"));
        }
        rows.into_iter()
            .map(|(_, value)| M::decode(value.as_slice()).map_err(codec))
            .collect()
    }
    fn bounded_rows(
        &self,
        kind: StoreKind,
        prefix: &[u8],
        max_items: usize,
        label: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ApiError> {
        let rows = self.view().store(kind).prefix_window(prefix, 0, max_items + 1);
        if rows.len() > max_items {
            return Err(work_cap(&format!("{label} count cap exceeded")));
        }
        let bytes = rows.iter().try_fold(0usize, |total, (key, value)| {
            total.checked_add(key.len())?.checked_add(value.len())
        }).ok_or_else(|| work_cap(&format!("{label} byte count overflow")))?;
        if bytes > MAX_FULL_LIST_BYTES {
            return Err(work_cap(&format!("{label} byte cap exceeded")));
        }
        Ok(rows)
    }
}


fn pagination(offset: i64, limit: i64, positive_limit: bool) -> Result<(usize, usize), ApiError> {
    if offset < 0 || limit < 0 || (positive_limit && limit == 0) {
        return Err(ApiError::InvalidArgument(
            "invalid pagination: offset must be non-negative and limit must be positive".into(),
        ));
    }
    Ok((usize::try_from(offset).unwrap_or(usize::MAX), usize::try_from(limit).unwrap_or(usize::MAX).min(MAX_PAGE)))
}
fn market_pair(pair: &MarketOrderPair) -> Result<Vec<u8>, ApiError> {
    if pair.sell_token_id.is_empty()
        || pair.buy_token_id.is_empty()
        || pair.sell_token_id == pair.buy_token_id
    {
        return Err(ApiError::InvalidArgument("invalid market pair".into()));
    }
    let mut key = pair.sell_token_id.clone();
    key.extend_from_slice(&pair.buy_token_id);
    Ok(key)
}
fn decode_i64(bytes: &[u8]) -> Option<i64> {
    bytes.try_into().ok().map(i64::from_be_bytes)
}
fn codec(error: prost::DecodeError) -> ApiError {
    ApiError::Internal(error.to_string())
}
fn work_cap(message: &str) -> ApiError {
    ApiError::InvalidArgument(message.into())
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char)
    }
    s
}

/// java-tron leaves both WalletExtension transaction-history RPC families UNIMPLEMENTED.
pub struct WalletExtensionQuery;
impl WalletExtensionQuery {
    pub fn transactions_from_this(&self) -> Result<TransactionList, ApiError> {
        Err(ApiError::Unavailable(
            "UNIMPLEMENTED: WalletExtension/GetTransactionsFromThis".into(),
        ))
    }
    pub fn transactions_from_this2(&self) -> Result<TransactionListExtention, ApiError> {
        Err(ApiError::Unavailable(
            "UNIMPLEMENTED: WalletExtension/GetTransactionsFromThis2".into(),
        ))
    }
    pub fn transactions_to_this(&self) -> Result<TransactionList, ApiError> {
        Err(ApiError::Unavailable(
            "UNIMPLEMENTED: WalletExtension/GetTransactionsToThis".into(),
        ))
    }
    pub fn transactions_to_this2(&self) -> Result<TransactionListExtention, ApiError> {
        Err(ApiError::Unavailable(
            "UNIMPLEMENTED: WalletExtension/GetTransactionsToThis2".into(),
        ))
    }
}

#[derive(Clone)]
pub struct DatabaseQuery(pub WalletQuery);
impl DatabaseQuery {
    pub fn block_reference(&self) -> Result<BlockReference, ApiError> {
        self.0.block_reference()
    }
    pub fn now_block(&self) -> Result<Block, ApiError> {
        self.0.now_block()
    }
    pub fn block_by_num(&self, n: i64) -> Result<Block, ApiError> {
        self.0.block_by_num(n)
    }
}

pub trait MonitorSource: Send + Sync {
    fn stats(&self) -> MetricsInfo;
}
impl<F> MonitorSource for F
where
    F: Fn() -> MetricsInfo + Send + Sync,
{
    fn stats(&self) -> MetricsInfo { self() }
}
pub struct MonitorQuery<S>(pub S);
impl<S: MonitorSource> MonitorQuery<S> {
    #[must_use]
    pub fn stats(&self) -> MetricsInfo {
        self.0.stats()
    }
}

/// The canonical Network protobuf service intentionally has no descriptors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetworkQuery;
