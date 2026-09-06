use prost::Message;
use tron_crypto::{
    DuplicateSignerPolicy, PermissionError, PermissionKey, keccak256,
    recover_permission_weight, selected_digest,
};
use tron_execution::{ActuatorRegistry, default_active_permission, default_owner_permission};
use tron_primitives::TronAddress21;
use tron_protocol::protocol::*;
use tron_state::{CursorView, StoreKind};
use zeroize::Zeroize;

use crate::{ApiContext, ApiCursor, ApiError, MonitorSource, ShieldedWallet, WalletMutation, WalletQuery};

#[derive(Clone)]
pub struct RpcDomainProvider {
    context: ApiContext,
    monitor: Option<std::sync::Arc<dyn MonitorSource>>,
    node_info: Option<std::sync::Arc<dyn Fn() -> NodeInfo + Send + Sync>>,
}

impl RpcDomainProvider {
    #[must_use]
    pub fn new(context: ApiContext) -> Self { Self { context, monitor: None, node_info: None } }
    #[must_use]
    pub fn with_monitor(context: ApiContext, monitor: std::sync::Arc<dyn MonitorSource>) -> Self {
        Self { context, monitor: Some(monitor), node_info: None }
    }
    #[must_use]
    pub fn with_operational_sources(context: ApiContext, monitor: std::sync::Arc<dyn MonitorSource>, node_info: std::sync::Arc<dyn Fn() -> NodeInfo + Send + Sync>) -> Self {
        Self { context, monitor: Some(monitor), node_info: Some(node_info) }
    }
    fn query(&self, cursor: ApiCursor) -> WalletQuery { WalletQuery::new(self.context.clone(), cursor) }
    fn view(&self, cursor: ApiCursor) -> crate::TypedReadView { self.context.view(cursor) }
    fn digest(&self, bytes: &[u8]) -> Vec<u8> { selected_digest(self.context.crypto_engine(), bytes).to_vec() }
    fn require_range(start: i64, end: i64) -> Result<(), ApiError> { ShieldedWallet::validate_scan_range(start, end) }

    pub fn account_balance(&self, input: AccountBalanceRequest, cursor: ApiCursor) -> Result<AccountBalanceResponse, ApiError> {
        let account = input.account_identifier.as_ref().ok_or_else(|| ApiError::InvalidArgument("account identifier is required".into()))?;
        let balance = self.query(cursor).account(&account.address)?.balance;
        Ok(AccountBalanceResponse { balance, block_identifier: input.block_identifier })
    }
    pub fn block_balance_trace(&self, id: block_balance_trace::BlockIdentifier, cursor: ApiCursor) -> Result<BlockBalanceTrace, ApiError> {
        let block = if id.hash.is_empty() { self.query(cursor).block_by_num(id.number)? } else { self.query(cursor).block_by_id(&id.hash)? };
        let timestamp = block.block_header.as_ref().and_then(|h| h.raw_data.as_ref()).map_or(0, |h| h.timestamp);
        let store = self.view(cursor).store(StoreKind::BalanceTrace);
        let encoded = (!id.hash.is_empty()).then(|| store.get(&id.hash)).flatten()
            .or_else(|| store.get(&id.number.to_be_bytes()))
            .ok_or_else(|| ApiError::NotFound("block balance trace".into()))?;
        let mut trace = BlockBalanceTrace::decode(encoded.as_slice()).map_err(|error| ApiError::Internal(error.to_string()))?;
        trace.block_identifier = Some(id);
        trace.timestamp = timestamp;
        Ok(trace)
    }
    pub fn list_nodes(&self) -> NodeList { self.context.network().nodes() }
    pub fn account_net(&self, account: Account, cursor: ApiCursor) -> Result<AccountNetMessage, ApiError> {
        let stored = self.query(cursor).account(&account.address)?;
        Ok(AccountNetMessage { free_net_used: stored.free_net_usage, free_net_limit: 0, net_used: stored.net_usage, net_limit: 0, asset_net_used: stored.free_asset_net_usage, asset_net_limit: std::collections::BTreeMap::new(), total_net_limit: self.dynamic(cursor, "TOTAL_NET_LIMIT").unwrap_or(0), total_net_weight: self.dynamic(cursor, "TOTAL_NET_WEIGHT").unwrap_or(0) })
    }
    pub fn account_resource(&self, account: Account, cursor: ApiCursor) -> Result<AccountResourceMessage, ApiError> {
        let stored = self.query(cursor).account(&account.address)?;
        let resource = stored.account_resource.unwrap_or_default();
        Ok(AccountResourceMessage { free_net_used: stored.free_net_usage, free_net_limit: 0, net_used: stored.net_usage, net_limit: 0, asset_net_used: stored.free_asset_net_usage, asset_net_limit: std::collections::BTreeMap::new(), total_net_limit: self.dynamic(cursor,"TOTAL_NET_LIMIT").unwrap_or(0), total_net_weight: self.dynamic(cursor,"TOTAL_NET_WEIGHT").unwrap_or(0), total_tron_power_weight: self.dynamic(cursor,"TOTAL_TRON_POWER_WEIGHT").unwrap_or(0), tron_power_used: 0, tron_power_limit: 0, energy_used: resource.energy_usage, energy_limit: 0, total_energy_limit: self.dynamic(cursor,"TOTAL_ENERGY_CURRENT_LIMIT").unwrap_or(0), total_energy_weight: self.dynamic(cursor,"TOTAL_ENERGY_WEIGHT").unwrap_or(0), storage_used: 0, storage_limit: 0 })
    }
    pub fn block_range_extension(&self, start: i64, end: i64, cursor: ApiCursor) -> Result<BlockListExtention, ApiError> { if start < 0 || end <= start || end - start > 100 { return Err(ApiError::InvalidArgument("block range must satisfy 0 <= start < end and contain at most 100 blocks".into())); } let query=self.query(cursor); let block=(start..end).map(|number|query.block_extension_by_num(number)).collect::<Result<Vec<_>,_>>()?; Ok(BlockListExtention { block }) }
    pub fn latest_block_extensions(&self, count: i64, cursor: ApiCursor) -> Result<BlockListExtention, ApiError> { if count <= 0 || count > 100 { return Err(ApiError::InvalidArgument("latest block count must be in 1..=100".into())); } let query=self.query(cursor); let head=self.dynamic(cursor,"LATEST_BLOCK_HEADER_NUMBER")?; let block=((head-count+1).max(0)..=head).map(|number|query.block_extension_by_num(number)).collect::<Result<Vec<_>,_>>()?; Ok(BlockListExtention { block }) }
    pub fn deploy_contract(&self, input: CreateSmartContract) -> Result<TransactionExtention, ApiError> { WalletMutation::new(self.context.clone()).create_extension(transaction::contract::ContractType::CreateSmartContract as i32, "type.googleapis.com/protocol.CreateSmartContract", input.encode_to_vec()) }
    pub fn trigger_contract(&self, input: TriggerSmartContract) -> Result<TransactionExtention, ApiError> { WalletMutation::new(self.context.clone()).create_extension(transaction::contract::ContractType::TriggerSmartContract as i32, "type.googleapis.com/protocol.TriggerSmartContract", input.encode_to_vec()) }
    pub fn contract(&self, address: &[u8], cursor: ApiCursor) -> Result<SmartContract, ApiError> { self.decode(cursor, StoreKind::Contract, address, "contract") }
    pub fn contract_info(&self, address: &[u8], cursor: ApiCursor) -> Result<SmartContractDataWrapper, ApiError> { Ok(SmartContractDataWrapper { smart_contract: Some(self.contract(address,cursor)?), runtimecode: self.view(cursor).store(StoreKind::Code).get(address).unwrap_or_default(), contract_state: self.view(cursor).store(StoreKind::ContractState).get(address).map(|v| ContractState::decode(v.as_slice())).transpose().map_err(|e| ApiError::Internal(e.to_string()))? }) }
    pub fn delegated_max(&self, input: CanDelegatedMaxSizeRequestMessage, cursor: ApiCursor) -> Result<CanDelegatedMaxSizeResponseMessage, ApiError> { let account=self.query(cursor).account(&input.owner_address)?; Ok(CanDelegatedMaxSizeResponseMessage { max_size: account.balance.max(0) }) }
    pub fn trigger_constant(&self, input: TriggerSmartContract, cursor: ApiCursor) -> Result<TransactionExtention, ApiError> {
        let runtime = self.context.runtime().ok_or_else(|| ApiError::FailedPrecondition("constant VM runtime is not configured".into()))?;
        let max_energy = self.dynamic(cursor, "MAX_CPU_TIME_OF_ONE_TX").unwrap_or(100_000_000).max(1);
        let outcome = runtime.execute(&self.view(cursor), &input, max_energy)?;
        if !outcome.runtime_error.is_empty() { return Err(ApiError::FailedPrecondition(outcome.runtime_error)); }
        let mut extension = self.trigger_contract(input)?;
        extension.constant_result = vec![outcome.result];
        extension.energy_used = outcome.energy_used;
        extension.energy_penalty = outcome.energy_penalty;
        Ok(extension)
    }
    pub fn estimate_energy(&self, input: TriggerSmartContract, cursor: ApiCursor) -> EstimateEnergyMessage {
        let result = (|| -> Result<i64, ApiError> {
            let runtime = self.context.runtime().ok_or_else(|| ApiError::FailedPrecondition("constant VM runtime is not configured".into()))?;
            let view = self.view(cursor);
            let mut low = 0_i64;
            let mut high = self.dynamic(cursor, "MAX_CPU_TIME_OF_ONE_TX").unwrap_or(100_000_000).max(1);
            while low.saturating_add(1) < high {
                let mid = low + (high - low) / 2;
                if runtime.execute(&view, &input, mid)?.runtime_error.is_empty() { high = mid; } else { low = mid; }
            }
            let final_out = runtime.execute(&view, &input, high)?;
            if final_out.runtime_error.is_empty() { Ok(high) } else { Err(ApiError::FailedPrecondition(final_out.runtime_error)) }
        })();
        match result {
            Ok(energy_required) => EstimateEnergyMessage { result: Some(crate::error::success_return()), energy_required },
            Err(error) => EstimateEnergyMessage { result: Some(crate::error::failure_return(r#return::ResponseCode::OtherError, error.to_string().into_bytes())), energy_required: 0 },
        }
    }
    pub fn sign_weight(&self, tx: Transaction, cursor: ApiCursor) -> Result<TransactionSignWeight, ApiError> {
        let (permission, weight) = self.permission_weight(&tx, cursor)?;
        let enough = weight.current_weight >= permission.threshold;
        Ok(TransactionSignWeight {
            permission: Some(permission),
            current_weight: weight.current_weight,
            approved_list: weight.approved.into_iter().map(|address| address.as_bytes().to_vec()).collect(),
            result: Some(transaction_sign_weight::Result {
                code: if enough { transaction_sign_weight::result::ResponseCode::EnoughPermission } else { transaction_sign_weight::result::ResponseCode::NotEnoughPermission } as i32,
                message: if enough { "permission threshold satisfied" } else { "permission threshold not satisfied" }.into(),
            }),
            transaction: Some(WalletMutation::new(self.context.clone()).extension(tx)),
        })
    }
    pub fn approved_list(&self, tx: Transaction, cursor: ApiCursor) -> Result<TransactionApprovedList, ApiError> {
        let (_, weight) = self.permission_weight(&tx, cursor)?;
        Ok(TransactionApprovedList {
            approved_list: weight.approved.into_iter().map(|address| address.as_bytes().to_vec()).collect(),
            result: Some(transaction_approved_list::Result {
                code: transaction_approved_list::result::ResponseCode::Success as i32,
                message: "signatures recovered from transaction raw-data hash".into(),
            }),
            transaction: Some(WalletMutation::new(self.context.clone()).extension(tx)),
        })
    }
    pub fn reward(&self, address: &[u8], cursor: ApiCursor) -> NumberMessage { NumberMessage { num: self.view(cursor).store(StoreKind::RewardVi).get(address).and_then(|v| v.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(0) } }
    pub fn brokerage(&self, address: &[u8], cursor: ApiCursor) -> NumberMessage { let mut key=address.to_vec(); key.extend_from_slice(b"-brokerage"); NumberMessage { num: self.view(cursor).store(StoreKind::Delegation).get(&key).and_then(|v| v.as_slice().try_into().ok()).map(i64::from_be_bytes).unwrap_or(20) } }
    pub fn rcm(&self) -> BytesMessage { BytesMessage { value: tron_shielded::generate_r().to_vec() } }
    pub fn spend_auth(&self, p: SpendAuthSigParameters) -> Result<BytesMessage, ApiError> { ShieldedWallet::create_spend_auth_sig(&p.ask,&p.alpha,&p.tx_hash) }
    pub fn shield_hash(&self, tx: &Transaction) -> BytesMessage { BytesMessage { value: self.digest(&tx.raw_data.as_ref().map(Message::encode_to_vec).unwrap_or_default()) } }
    pub fn nullifier(&self, p: &NfParameters) -> Result<BytesMessage, ApiError> {
        let note = p.note.as_ref().ok_or_else(|| ApiError::InvalidArgument("note is required".into()))?;
        let voucher = p.voucher.as_ref().ok_or_else(|| ApiError::InvalidArgument("voucher is required".into()))?;
        let address = decode_hex(&note.payment_address)?;
        if address.len() != 43 { return Err(ApiError::InvalidArgument("payment address must encode 43 bytes".into())); }
        let value = u64::try_from(note.value).map_err(|_| ApiError::InvalidArgument("note value must be non-negative".into()))?;
        let position = voucher.tree.as_ref().ok_or_else(|| ApiError::InvalidArgument("voucher tree is required".into())).and_then(voucher_position)?;
        let nf = tron_shielded::compute_nf(
            address[..11].try_into().expect("checked payment address"),
            address[11..].try_into().expect("checked payment address"),
            value,
            p.note.as_ref().expect("checked note").rcm.as_slice().try_into().map_err(|_| ApiError::InvalidArgument("rcm must be 32 bytes".into()))?,
            p.ak.as_slice().try_into().map_err(|_| ApiError::InvalidArgument("ak must be 32 bytes".into()))?,
            p.nk.as_slice().try_into().map_err(|_| ApiError::InvalidArgument("nk must be 32 bytes".into()))?,
            position,
        ).map_err(|error| ApiError::InvalidArgument(error.to_string()))?;
        Ok(BytesMessage { value: nf.to_vec() })
    }
    pub fn is_spend(&self, p: &NoteParameters, cursor: ApiCursor) -> SpendResult {
        let nf = self.note_nullifier(p).ok();
        SpendResult { result: nf.as_ref().is_some_and(|key| self.view(cursor).store(StoreKind::Nullifier).get(key).is_some()), message: nf.map_or_else(|| "invalid shielded note parameters".into(), |_| "authenticated nullifier store checked".into()) }
    }
    pub fn voucher(&self, p: OutputPointInfo, cursor: ApiCursor) -> Result<IncrementalMerkleVoucherInfo,ApiError> {
        let mut vouchers=Vec::new();
        let mut paths=Vec::new();
        for point in p.out_points {
            let key=point.encode_to_vec();
            let bytes=self.view(cursor).store(StoreKind::IncrementalMerkleTree).get(&key).ok_or_else(||ApiError::NotFound("merkle voucher".into()))?;
            let voucher=IncrementalMerkleVoucher::decode(bytes.as_slice()).map_err(|e|ApiError::Internal(e.to_string()))?;
            let position=voucher.tree.as_ref().map(voucher_position).transpose()?.ok_or_else(||ApiError::InvalidArgument("voucher tree is required".into()))?;
            let siblings=voucher.filled.iter().map(|hash| hash.content.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("voucher sibling must be 32 bytes".into()))).collect::<Result<Vec<[u8;32]>,ApiError>>()?;
            paths.push(tron_shielded::JavaMerklePath{siblings,position}.encode()?);
            vouchers.push(voucher);
        }
        Ok(IncrementalMerkleVoucherInfo { vouchers, paths })
    }
    pub fn scan_ivk(&self,p:IvkDecryptParameters,cursor:ApiCursor)->Result<DecryptNotes,ApiError>{
        let ivk=p.ivk.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("ivk must be 32 bytes".into()))?;
        Ok(DecryptNotes{note_txs:self.scan_notes(p.start_block_index,p.end_block_index,cursor,|output|tron_shielded::decrypt_pre_zip212_note(ivk,output))?})
    }
    pub fn scan_mark(&self,p:IvkDecryptAndMarkParameters,cursor:ApiCursor)->Result<DecryptNotesMarked,ApiError>{
        let ivk=p.ivk.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("ivk must be 32 bytes".into()))?;
        let notes=self.scan_notes(p.start_block_index,p.end_block_index,cursor,|output|tron_shielded::decrypt_pre_zip212_note(ivk,output))?;
        let note_txs=notes.into_iter().map(|item|{
            let params=NoteParameters{note:item.note.clone(),ak:p.ak.clone(),nk:p.nk.clone(),txid:item.txid.clone(),index:item.index};
            decrypt_notes_marked::NoteTx{note:item.note,txid:item.txid,index:item.index,is_spend:self.is_spend(&params,cursor).result}
        }).collect();
        Ok(DecryptNotesMarked{note_txs})
    }
    pub fn scan_ovk(&self,p:OvkDecryptParameters,cursor:ApiCursor)->Result<DecryptNotes,ApiError>{
        let ovk=p.ovk.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("ovk must be 32 bytes".into()))?;
        Ok(DecryptNotes{note_txs:self.scan_notes(p.start_block_index,p.end_block_index,cursor,|output|tron_shielded::recover_pre_zip212_note(ovk,output))?})
    }
    pub fn scan_trc20_ivk(&self,p:IvkDecryptTrc20Parameters,cursor:ApiCursor)->Result<DecryptNotesTrc20,ApiError>{
        Self::require_range(p.start_block_index,p.end_block_index)?;
        let ivk:[u8;32]=p.ivk.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("ivk must be 32 bytes".into()))?;
        let contract=trc20_contract(&p.shielded_trc20_contract_address)?;
        if (!p.ak.is_empty()&&p.ak.len()!=32)||(!p.nk.is_empty()&&p.nk.len()!=32)||p.ak.is_empty()!=p.nk.is_empty(){return Err(ApiError::InvalidArgument("ak and nk must both be empty or 32 bytes".into()))}
        let mut note_txs=Vec::new();
        for number in p.start_block_index..p.end_block_index {
            for info in self.query(cursor).transaction_infos_by_block(number)?.transaction_info {
                let mut index=0i32;
                for log in info.log {
                    if trc20_log_kind(&log,&contract)!=Some(Trc20Log::Leaf){continue}
                    let Some((position,encrypted))=trc20_leaf(&log.data)? else{continue};
                    let current=index; index=index.checked_add(1).ok_or_else(||ApiError::Internal("shielded output index overflow".into()))?;
                    let Some(note)=tron_shielded::decrypt_pre_zip212_note(ivk,&encrypted)? else{continue};
                    let proto=trc20_note(note)?;
                    let is_spent=if p.ak.is_empty(){false}else{let nf=self.compute_note_nullifier(Some(&proto),&p.ak,&p.nk,i64::try_from(position).map_err(|_|ApiError::Internal("note position exceeds i64".into()))?)?;self.view(cursor).store(StoreKind::Nullifier).get(&nf).is_some()};
                    note_txs.push(decrypt_notes_trc20::NoteTx{note:Some(proto),position:i64::try_from(position).map_err(|_|ApiError::Internal("note position exceeds i64".into()))?,is_spent,txid:info.id.clone(),index:current,to_amount:String::new(),transparent_to_address:Vec::new()});
                }
            }
        }
        Ok(DecryptNotesTrc20{note_txs})
    }
    pub fn scan_trc20_ovk(&self,p:OvkDecryptTrc20Parameters,cursor:ApiCursor)->Result<DecryptNotesTrc20,ApiError>{
        Self::require_range(p.start_block_index,p.end_block_index)?;
        let ovk:[u8;32]=p.ovk.as_slice().try_into().map_err(|_|ApiError::InvalidArgument("ovk must be 32 bytes".into()))?;
        let contract=trc20_contract(&p.shielded_trc20_contract_address)?;
        let mut note_txs=Vec::new();
        for number in p.start_block_index..p.end_block_index {
            for info in self.query(cursor).transaction_infos_by_block(number)?.transaction_info {
                let mut index=0i32;let mut pending_nf=None;
                for log in info.log {
                    match trc20_log_kind(&log,&contract){
                        Some(Trc20Log::Spent)=>{if log.data.len()>=32{pending_nf=Some(log.data[..32].try_into().unwrap())}},
                        Some(Trc20Log::Leaf)=>{let Some((position,encrypted))=trc20_leaf(&log.data)? else{continue};let current=index;index=index.checked_add(1).ok_or_else(||ApiError::Internal("shielded output index overflow".into()))?;let Some(note)=tron_shielded::recover_pre_zip212_note(ovk,&encrypted)? else{continue};note_txs.push(decrypt_notes_trc20::NoteTx{note:Some(trc20_note(note)?),position:i64::try_from(position).map_err(|_|ApiError::Internal("note position exceeds i64".into()))?,is_spent:false,txid:info.id.clone(),index:current,to_amount:String::new(),transparent_to_address:Vec::new()})},
                        Some(Trc20Log::Burn)=>{let current=index;index=index.checked_add(1).ok_or_else(||ApiError::Internal("shielded output index overflow".into()))?;if log.data.len()<160{pending_nf=None;continue}let amount:[u8;32]=log.data[32..64].try_into().unwrap();let mut address=[0u8;21];address[0]=0x41;address[1..].copy_from_slice(&log.data[12..32]);if tron_shielded::recover_burn_record(ovk,&log.data[64..160],pending_nf,Some(amount),Some(address))?.is_some(){note_txs.push(decrypt_notes_trc20::NoteTx{note:None,position:0,is_spent:false,txid:info.id.clone(),index:current,to_amount:u256_decimal(amount),transparent_to_address:address.to_vec()})}pending_nf=None},
                        None=>{}
                    }
                }
            }
        }
        Ok(DecryptNotesTrc20{note_txs})
    }
    pub fn trc20_spent(&self,p:&NfTrc20Parameters,cursor:ApiCursor)->NullifierResult{let key=self.trc20_nullifier(p).ok();NullifierResult{is_spent:key.as_ref().is_some_and(|nf|self.view(cursor).store(StoreKind::Nullifier).get(nf).is_some())}}
    pub fn trigger_input(&self,p:ShieldedTrc20TriggerContractParameters)->Result<BytesMessage,ApiError>{Ok(BytesMessage{value:encode_trc20_trigger(p)?})}
    pub fn shielded_trc20(&self,input:PrivateShieldedTrc20Parameters)->Result<ShieldedTrc20Parameters,ApiError>{
        let ask=optional_key(&input.ask,"ask")?;
        let ak=ask.map(tron_shielded::ask_to_ak).unwrap_or([0;32]);
        self.build_shielded_trc20(Trc20Private{ask,ak,nsk:optional_key(&input.nsk,"nsk")?.unwrap_or([0;32]),ovk:optional_key(&input.ovk,"ovk")?,from_amount:parse_amount(&input.from_amount)?,spends:input.shielded_spends,receives:input.shielded_receives,to_address:input.transparent_to_address,to_amount:parse_amount(&input.to_amount)?,contract:input.shielded_trc20_contract_address})
    }
    pub fn shielded_trc20_without_ask(&self,input:PrivateShieldedTrc20ParametersWithoutAsk)->Result<ShieldedTrc20Parameters,ApiError>{
        self.build_shielded_trc20(Trc20Private{ask:None,ak:required::<32>(&input.ak,"ak")?,nsk:required::<32>(&input.nsk,"nsk")?,ovk:optional_key(&input.ovk,"ovk")?,from_amount:parse_amount(&input.from_amount)?,spends:input.shielded_spends,receives:input.shielded_receives,to_address:input.transparent_to_address,to_amount:parse_amount(&input.to_amount)?,contract:input.shielded_trc20_contract_address})
    }
    fn build_shielded_trc20(&self,input:Trc20Private)->Result<ShieldedTrc20Parameters,ApiError>{
        let _proof_slot=self.context.proof_generation().lock().map_err(|_|ApiError::Internal("shielded proof generation lock poisoned".into()))?;
        if input.spends.len()>2||input.receives.len()>2{return Err(ApiError::InvalidArgument("shielded TRC20 supports at most two spends and two outputs".into()))}
        let contract=trc20_contract(&input.contract)?;
        let spend_total=input.spends.iter().try_fold(0u64,|sum,s|note_value(s.note.as_ref()).and_then(|v|sum.checked_add(v).ok_or_else(||ApiError::InvalidArgument("shielded spend value overflow".into()))))?;
        let receive_total=input.receives.iter().try_fold(0u64,|sum,r|note_value(r.note.as_ref()).and_then(|v|sum.checked_add(v).ok_or_else(||ApiError::InvalidArgument("shielded receive value overflow".into()))))?;
        let kind=if input.from_amount>0&&input.to_amount==0&&input.spends.is_empty()&&input.receives.len()==1&&receive_total==input.from_amount{"mint"}else if input.from_amount==0&&input.to_amount==0&&(1..=2).contains(&input.spends.len())&&(1..=2).contains(&input.receives.len())&&spend_total==receive_total{"transfer"}else if input.from_amount==0&&input.to_amount>0&&input.spends.len()==1&&input.receives.len()<=1&&spend_total==receive_total.checked_add(input.to_amount).ok_or_else(||ApiError::InvalidArgument("burn value overflow".into()))?{"burn"}else{return Err(ApiError::InvalidArgument("invalid shielded TRC20 parameters".into()))};
        if kind=="burn"&&trc20_contract(&input.to_address).is_err(){return Err(ApiError::InvalidArgument("No valid transparent TRC-20 output address".into()))}
        if kind!="mint"&&input.ovk.is_none(){return Err(ApiError::InvalidArgument("No shielded TRC-20 ovk".into()))}
        let ovk=input.ovk.unwrap_or_else(tron_shielded::generate_r);
        let nk=tron_shielded::nsk_to_nk(input.nsk);
        let mut proving=tron_shielded::ProvingContext::new(self.context.shielded_parameters());
        let mut spends=Vec::with_capacity(input.spends.len());
        for spend in &input.spends{
            let note=spend.note.as_ref().ok_or_else(||ApiError::InvalidArgument("spend note is required".into()))?;
            let address=note_address(note)?;let value=u64::try_from(note.value).map_err(|_|ApiError::InvalidArgument("note value must be non-negative".into()))?;
            let path=format_trc20_path(&spend.path,spend.pos)?;
            let proof=proving.spend_proof(input.ak,input.nsk,address[..11].try_into().unwrap(),required::<32>(&note.rcm,"rcm")?,required::<32>(&spend.alpha,"alpha")?,value,required::<32>(&spend.root,"root")?,&path).map_err(shielded_error)?;
            let nf=tron_shielded::compute_nf(address[..11].try_into().unwrap(),address[11..].try_into().unwrap(),value,required::<32>(&note.rcm,"rcm")?,input.ak,nk,u64::try_from(spend.pos).map_err(|_|ApiError::InvalidArgument("position must be non-negative".into()))?).map_err(shielded_error)?;
            spends.push(SpendDescription{value_commitment:proof.value_commitment.to_vec(),anchor:spend.root.clone(),nullifier:nf.to_vec(),rk:proof.randomized_key.to_vec(),zkproof:proof.zkproof.to_vec(),spend_authority_signature:Vec::new()});
        }
        let mut receives=Vec::with_capacity(input.receives.len());
        for receive in &input.receives{
            let note=receive.note.as_ref().ok_or_else(||ApiError::InvalidArgument("receive note is required".into()))?;let address=note_address(note)?;let value=u64::try_from(note.value).map_err(|_|ApiError::InvalidArgument("note value must be non-negative".into()))?;
            let esk=tron_shielded::generate_r();let proof=proving.output_proof(esk,address[..11].try_into().unwrap(),address[11..].try_into().unwrap(),required::<32>(&note.rcm,"rcm")?,value).map_err(shielded_error)?;
            let mut memo=[0u8;512];if note.memo.len()>512{return Err(ApiError::InvalidArgument("memo must be at most 512 bytes".into()))}memo[..note.memo.len()].copy_from_slice(&note.memo);
            let encrypted=tron_shielded::encrypt_pre_zip212_note_with_esk(address.try_into().unwrap(),value,required::<32>(&note.rcm,"rcm")?,Some(ovk),proof.value_commitment,memo,esk).map_err(shielded_error)?;
            receives.push(ReceiveDescription{value_commitment:proof.value_commitment.to_vec(),note_commitment:encrypted.note_commitment.to_vec(),epk:encrypted.ephemeral_key.to_vec(),c_enc:encrypted.enc_ciphertext.to_vec(),c_out:encrypted.out_ciphertext.to_vec(),zkproof:proof.zkproof.to_vec()});
        }
        let value_balance=i64::try_from(spend_total).and_then(|s|i64::try_from(receive_total).map(|r|s-r)).map_err(|_|ApiError::InvalidArgument("shielded value balance exceeds i64".into()))?;
        let mut merged=contract.to_vec();if kind=="mint"{merged.extend_from_slice(&receive_total.to_be_bytes())}for s in &spends{merged.extend_from_slice(&spend_bytes(s)?)}for r in &receives{merged.extend_from_slice(&output_bytes(r)?)}for r in &receives{merged.extend_from_slice(&cipher_bytes(r)?)}if kind=="burn"{merged.extend_from_slice(&trc20_contract(&input.to_address)?);merged.extend_from_slice(&value_balance.to_be_bytes())}
        let hash: [u8;32]=self.digest(&merged).try_into().expect("selected digest");
        if let Some(ask)=input.ask{for (description,source) in spends.iter_mut().zip(&input.spends){description.spend_authority_signature=tron_shielded::spend_sig(ask,required::<32>(&source.alpha,"alpha")?,hash).map_err(shielded_error)?.to_vec()}}
        let binding=proving.binding_sig(value_balance,hash).map_err(shielded_error)?;
        let mut result=ShieldedTrc20Parameters{spend_description:spends,receive_description:receives,binding_signature:binding.to_vec(),message_hash:hash.to_vec(),trigger_contract_input:String::new(),parameter_type:kind.into()};
        if kind=="burn"{let mut amount=[0u8;32];amount[24..].copy_from_slice(&input.to_amount.to_be_bytes());let mut addr=[0u8;21];addr[0]=0x41;addr[1..].copy_from_slice(&trc20_contract(&input.to_address)?);result.trigger_contract_input=hex(&tron_shielded::encrypt_burn_record(ovk,amount,addr,required::<32>(&result.spend_description[0].nullifier,"nullifier")?).map_err(shielded_error)?)}
        if input.ask.is_some()||kind=="mint"{let sigs=result.spend_description.iter().map(|s|BytesMessage{value:s.spend_authority_signature.clone()}).collect();result.trigger_contract_input=hex(&encode_trc20_trigger(ShieldedTrc20TriggerContractParameters{shielded_trc20_parameters:Some(result.clone()),spend_authority_signature:sigs,amount:if kind=="mint"{input.from_amount}else{input.to_amount}.to_string(),transparent_to_address:input.to_address.clone()})?)}
        Ok(result)
    }
    pub fn shielded_transaction<M:Message>(&self,p:&M,type_name:&str)->Result<TransactionExtention,ApiError>{WalletMutation::new(self.context.clone()).create_extension(transaction::contract::ContractType::ShieldedTransferContract as i32,type_name,p.encode_to_vec())}
    pub fn get_block(&self,p:BlockReq,cursor:ApiCursor)->Result<BlockExtention,ApiError>{let query=self.query(cursor);if p.id_or_num.is_empty(){query.block_extension_by_num(self.dynamic(cursor,"LATEST_BLOCK_HEADER_NUMBER")?)}else if let Ok(n)=p.id_or_num.parse::<i64>(){query.block_extension_by_num(n)}else{query.block_extension_by_id(&decode_hex(&p.id_or_num)?)} }
    pub fn dynamic_properties(&self)->Result<DynamicProperties,ApiError>{Ok(DynamicProperties{last_solidity_block_num:self.dynamic(ApiCursor::Solidity,"LATEST_BLOCK_HEADER_NUMBER")?})}
    pub fn node_info(&self)->NodeInfo {
        if let Some(source) = &self.node_info { return source(); }
        let head = self.context.head().point();
        let solid = self.context.solidity().point();
        self.context.network().node_info(head.block, solid.block).into_proto()
    }
    pub fn metrics(&self)->MetricsInfo {
        if let Some(monitor) = &self.monitor { return monitor.stats(); }
        let head=self.context.head().point();
        let block=self.query(ApiCursor::Head).now_block().ok();
        let timestamp=block.as_ref().and_then(|b|b.block_header.as_ref()).and_then(|h|h.raw_data.as_ref()).map_or(0,|h|h.timestamp);
        MetricsInfo { interval:0,node:Some(metrics_info::NodeInfo{ip:String::new(),node_type:0,version:env!("CARGO_PKG_VERSION").into(),backup_status:0}),blockchain:Some(metrics_info::BlockChainInfo{head_block_num:head.block as i64,head_block_timestamp:timestamp,head_block_hash:hex(&head.identity.bytes()),fork_count:0,fail_fork_count:0,block_process_time:None,tps:None,transaction_cache_size:self.context.pending().lock().map(|p|p.len() as i32).unwrap_or(0),missed_transaction:None,witnesses:Vec::new(),fail_process_block_num:0,fail_process_block_reason:String::new(),dup_witness:Vec::new()}),net:None }
    }
    fn scan_notes<F>(&self,start:i64,end:i64,cursor:ApiCursor,mut decrypt:F)->Result<Vec<decrypt_notes::NoteTx>,ApiError>
    where F:FnMut(&tron_shielded::EncryptedNote)->tron_shielded::Result<Option<tron_shielded::DecryptedNote>> {
        Self::require_range(start,end)?;
        let mut found=Vec::new();
        for number in start..end {
            let block=self.query(cursor).block_by_num(number)?;
            for transaction in block.transactions {
                let txid=self.digest(&transaction.raw_data.as_ref().map(Message::encode_to_vec).unwrap_or_default());
                let Some(raw)=transaction.raw_data else{continue};
                for contract in raw.contract {
                    if contract.r#type!=transaction::contract::ContractType::ShieldedTransferContract as i32{continue}
                    let Some(parameter)=contract.parameter else{continue};
                    let shielded=ShieldedTransferContract::decode(parameter.value.as_slice()).map_err(|e|ApiError::Internal(e.to_string()))?;
                    for (index,output) in shielded.receive_description.iter().enumerate() {
                        let encrypted=tron_shielded::EncryptedNote{
                            value_commitment:output.value_commitment.as_slice().try_into().map_err(|_|ApiError::Internal("invalid stored value commitment".into()))?,
                            note_commitment:output.note_commitment.as_slice().try_into().map_err(|_|ApiError::Internal("invalid stored note commitment".into()))?,
                            ephemeral_key:output.epk.as_slice().try_into().map_err(|_|ApiError::Internal("invalid stored ephemeral key".into()))?,
                            enc_ciphertext:output.c_enc.as_slice().try_into().map_err(|_|ApiError::Internal("invalid stored incoming ciphertext".into()))?,
                            out_ciphertext:output.c_out.as_slice().try_into().map_err(|_|ApiError::Internal("invalid stored outgoing ciphertext".into()))?,
                        };
                        if let Some(note)=decrypt(&encrypted).map_err(|e|ApiError::InvalidArgument(e.to_string()))? {
                            let mut address=note.diversifier.to_vec(); address.extend_from_slice(&note.pk_d);
                            found.push(decrypt_notes::NoteTx{note:Some(Note{value:i64::try_from(note.value).map_err(|_|ApiError::Internal("shielded note value exceeds i64".into()))?,payment_address:hex(&address),rcm:note.rcm.to_vec(),memo:note.memo.to_vec()}),txid:txid.clone(),index:i32::try_from(index).map_err(|_|ApiError::Internal("shielded output index overflow".into()))?});
                        }
                    }
                }
            }
        }
        Ok(found)
    }
    fn permission_weight(&self, tx: &Transaction, cursor: ApiCursor) -> Result<(Permission, tron_crypto::PermissionWeight), ApiError> {
        let raw = tx.raw_data.as_ref().ok_or_else(|| ApiError::InvalidArgument("transaction raw_data is required".into()))?;
        let contract = raw.contract.first().ok_or_else(|| ApiError::InvalidArgument("transaction contract is required".into()))?;
        if raw.contract.len() != 1 { return Err(ApiError::InvalidArgument("transaction must contain exactly one contract".into())); }
        let owner = ActuatorRegistry::empty().owner_address(contract).map_err(|error| ApiError::InvalidArgument(format!("{error:?}")))?;
        let account = self.query(cursor).account(&owner)?;
        let permission = match contract.permission_id {
            0 => account.owner_permission.unwrap_or_else(|| default_owner_permission(&owner)),
            2 if account.active_permission.is_empty() => {
                let operations = self.view(cursor).store(StoreKind::DynamicProperties).get(b"ACTIVE_DEFAULT_OPERATIONS").ok_or_else(|| ApiError::NotFound("dynamic property ACTIVE_DEFAULT_OPERATIONS".into()))?;
                default_active_permission(&owner, operations)
            }
            id => account.active_permission.into_iter().find(|permission| permission.id == id).ok_or_else(|| ApiError::FailedPrecondition(format!("permission {id} is missing")))?,
        };
        let keys = permission.keys.iter().map(|key| {
            TronAddress21::validate_mainnet(&key.address).map(|address| PermissionKey { address, weight: key.weight }).map_err(|_| ApiError::InvalidArgument("permission key has invalid address".into()))
        }).collect::<Result<Vec<_>, _>>()?;
        let prehash = self.digest(&raw.encode_to_vec());
        let weight = recover_permission_weight(self.context.crypto_engine(), &prehash, &tx.signature, &keys, DuplicateSignerPolicy::RecoveredAddress).map_err(map_permission_error)?;
        Ok((permission, weight))
    }
    fn note_nullifier(&self, p: &NoteParameters) -> Result<Vec<u8>, ApiError> {
        self.compute_note_nullifier(p.note.as_ref(), &p.ak, &p.nk, i64::from(p.index))
    }
    fn trc20_nullifier(&self, p: &NfTrc20Parameters) -> Result<Vec<u8>, ApiError> {
        self.compute_note_nullifier(p.note.as_ref(), &p.ak, &p.nk, p.position)
    }
    fn compute_note_nullifier(&self, note: Option<&Note>, ak: &[u8], nk: &[u8], position: i64) -> Result<Vec<u8>, ApiError> {
        let note = note.ok_or_else(|| ApiError::InvalidArgument("note is required".into()))?;
        let address = decode_hex(&note.payment_address)?;
        if address.len() != 43 { return Err(ApiError::InvalidArgument("payment address must encode 43 bytes".into())); }
        let value = u64::try_from(note.value).map_err(|_| ApiError::InvalidArgument("note value must be non-negative".into()))?;
        let position = u64::try_from(position).map_err(|_| ApiError::InvalidArgument("position must be non-negative".into()))?;
        Ok(tron_shielded::compute_nf(address[..11].try_into().unwrap(), address[11..].try_into().unwrap(), value, note.rcm.as_slice().try_into().map_err(|_| ApiError::InvalidArgument("rcm must be 32 bytes".into()))?, ak.try_into().map_err(|_| ApiError::InvalidArgument("ak must be 32 bytes".into()))?, nk.try_into().map_err(|_| ApiError::InvalidArgument("nk must be 32 bytes".into()))?, position).map_err(|error| ApiError::InvalidArgument(error.to_string()))?.to_vec())
    }
    fn dynamic(&self,cursor:ApiCursor,key:&str)->Result<i64,ApiError>{let raw=self.view(cursor).store(StoreKind::DynamicProperties).get(key.as_bytes()).ok_or_else(||ApiError::NotFound(format!("dynamic property {key}")))?; raw.as_slice().try_into().map(i64::from_be_bytes).map_err(|_|ApiError::Internal(format!("dynamic property {key} is not i64")))}
    fn decode<M:Message+Default>(&self,cursor:ApiCursor,kind:StoreKind,key:&[u8],name:&str)->Result<M,ApiError>{let bytes=self.view(cursor).store(kind).get(key).ok_or_else(||ApiError::NotFound(name.into()))?;M::decode(bytes.as_slice()).map_err(|e|ApiError::Internal(e.to_string()))}
}
struct Trc20Private{
    ask:Option<[u8;32]>,ak:[u8;32],nsk:[u8;32],ovk:Option<[u8;32]>,from_amount:u64,
    spends:Vec<SpendNoteTrc20>,receives:Vec<ReceiveNote>,to_address:Vec<u8>,to_amount:u64,contract:Vec<u8>,
}
impl Drop for Trc20Private{fn drop(&mut self){self.ask.zeroize();self.ak.zeroize();self.nsk.zeroize();self.ovk.zeroize();}}
fn optional_key(value:&[u8],name:&str)->Result<Option<[u8;32]>,ApiError>{if value.is_empty(){Ok(None)}else{required::<32>(value,name).map(Some)}}
fn parse_amount(value:&str)->Result<u64,ApiError>{value.trim().parse().map_err(|_|ApiError::InvalidArgument("invalid from_amount or to_amount".into()))}
fn note_value(note:Option<&Note>)->Result<u64,ApiError>{u64::try_from(note.ok_or_else(||ApiError::InvalidArgument("note is required".into()))?.value).map_err(|_|ApiError::InvalidArgument("note value must be non-negative".into()))}
fn note_address(note:&Note)->Result<Vec<u8>,ApiError>{let value=decode_hex(&note.payment_address)?;if value.len()!=43{return Err(ApiError::InvalidArgument("payment address must encode 43 bytes".into()))}Ok(value)}
fn format_trc20_path(path:&[u8],position:i64)->Result<Vec<u8>,ApiError>{
    if path.len()!=1024{return Err(ApiError::InvalidArgument("Merkle tree path format is wrong".into()))}
    let mut out=vec![0u8;1065];out[0]=32;for i in 0..32{out[1+i*33]=32;out[2+i*33..2+i*33+32].copy_from_slice(&path[i*32..(i+1)*32])}out[1057..].copy_from_slice(&u64::try_from(position).map_err(|_|ApiError::InvalidArgument("position must be non-negative".into()))?.to_le_bytes());Ok(out)
}
fn shielded_error(error:tron_shielded::ShieldedError)->ApiError{ApiError::InvalidArgument(error.to_string())}
fn voucher_position(tree: &IncrementalMerkleTree) -> Result<u64, ApiError> {
    let present = |hash: &Option<PedersenHash>| hash.as_ref().is_some_and(|value| !value.content.is_empty());
    let mut size = u64::from(present(&tree.left)) + u64::from(present(&tree.right));
    for (level, parent) in tree.parents.iter().enumerate() {
        if !parent.content.is_empty() {
            let shift = u32::try_from(level + 1).map_err(|_| ApiError::InvalidArgument("voucher tree depth is invalid".into()))?;
            size = size.checked_add(1_u64.checked_shl(shift).ok_or_else(|| ApiError::InvalidArgument("voucher tree depth exceeds 63".into()))?).ok_or_else(|| ApiError::InvalidArgument("voucher position overflow".into()))?;
        }
    }
    size.checked_sub(1).ok_or_else(|| ApiError::InvalidArgument("voucher tree is empty".into()))
}
fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn decode_hex(s:&str)->Result<Vec<u8>,ApiError>{if s.len()%2!=0{return Err(ApiError::InvalidArgument("block id must have even hex length".into()));}(0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).map_err(|_|ApiError::InvalidArgument("block id must be hexadecimal".into()))).collect()}
fn map_permission_error(error: PermissionError) -> ApiError {
    match error {
        PermissionError::SignatureFormat => ApiError::InvalidArgument(error.to_string()),
        PermissionError::ComputeAddress => ApiError::InvalidArgument(error.to_string()),
        PermissionError::SignerNotInPermission | PermissionError::DuplicateSigner | PermissionError::TooManySignatures => ApiError::FailedPrecondition(error.to_string()),
        PermissionError::WeightOverflow => ApiError::Internal(error.to_string()),
    }
}

#[derive(Clone,Copy,Eq,PartialEq)] enum Trc20Log{Leaf,Burn,Spent}
fn trc20_contract(address:&[u8])->Result<[u8;20],ApiError>{match address{[0x41,rest @ ..] if rest.len()==20=>Ok(rest.try_into().unwrap()),v if v.len()==20=>Ok(v.try_into().unwrap()),_=>Err(ApiError::InvalidArgument("shielded TRC20 contract address must be 20 or 21 bytes".into()))}}
fn trc20_log_kind(log:&transaction_info::Log,contract:&[u8;20])->Option<Trc20Log>{
    if log.address.as_slice()!=contract||log.topics.len()!=1{return None}
    const LEAVES:[&str;3]=["MintNewLeaf(uint256,bytes32,bytes32,bytes32,bytes32[21])","TransferNewLeaf(uint256,bytes32,bytes32,bytes32,bytes32[21])","BurnNewLeaf(uint256,bytes32,bytes32,bytes32,bytes32[21])"];
    if LEAVES.iter().any(|event|log.topics[0].as_slice()==keccak256(event.as_bytes())){Some(Trc20Log::Leaf)}else if log.topics[0].as_slice()==keccak256(b"TokenBurn(address,uint256,bytes32[3])"){Some(Trc20Log::Burn)}else if log.topics[0].as_slice()==keccak256(b"NoteSpent(bytes32)"){Some(Trc20Log::Spent)}else{None}
}
fn trc20_leaf(data:&[u8])->Result<Option<(u64,tron_shielded::EncryptedNote)>,ApiError>{
    if data.len()!=788{return Ok(None)}
    if data[..24].iter().any(|&v|v!=0){return Err(ApiError::InvalidArgument("shielded note position exceeds u64".into()))}
    Ok(Some((u64::from_be_bytes(data[24..32].try_into().unwrap()),tron_shielded::EncryptedNote{note_commitment:data[32..64].try_into().unwrap(),value_commitment:data[64..96].try_into().unwrap(),ephemeral_key:data[96..128].try_into().unwrap(),enc_ciphertext:data[128..708].try_into().unwrap(),out_ciphertext:data[708..788].try_into().unwrap()})))
}
fn u256_decimal(bytes:[u8;32])->String{let mut digits=vec![0u8];for byte in bytes{let mut carry=u16::from(byte);for digit in &mut digits{let value=u16::from(*digit)*256+carry;*digit=(value%10)as u8;carry=value/10}while carry>0{digits.push((carry%10)as u8);carry/=10}}digits.iter().rev().map(|d|char::from(b'0'+*d)).collect()}
fn trc20_note(note:tron_shielded::DecryptedNote)->Result<Note,ApiError>{let mut address=note.diversifier.to_vec();address.extend_from_slice(&note.pk_d);Ok(Note{value:i64::try_from(note.value).map_err(|_|ApiError::Internal("shielded note value exceeds i64".into()))?,payment_address:hex(&address),rcm:note.rcm.to_vec(),memo:note.memo.to_vec()})}

fn word_u256(value:u64)->[u8;32]{let mut word=[0;32];word[24..].copy_from_slice(&value.to_be_bytes());word}
fn required<const N:usize>(bytes:&[u8],name:&str)->Result<[u8;N],ApiError>{bytes.try_into().map_err(|_|ApiError::InvalidArgument(format!("{name} must be {N} bytes")))}
fn encode_trc20_trigger(p:ShieldedTrc20TriggerContractParameters)->Result<Vec<u8>,ApiError>{
    let params=p.shielded_trc20_parameters.ok_or_else(||ApiError::InvalidArgument("shielded TRC20 parameters are required".into()))?;
    let amount=p.amount.trim().parse::<u64>().map_err(|_|ApiError::InvalidArgument("amount must be an unsigned 64-bit decimal".into()))?;
    match params.parameter_type.as_str(){
        "mint"=>{if params.spend_description.len()!=0||params.receive_description.len()!=1||!p.spend_authority_signature.is_empty()||amount==0{return Err(ApiError::InvalidArgument("invalid mint parameters".into()))}let r=&params.receive_description[0];let mut out=Vec::with_capacity(1024);out.extend_from_slice(&word_u256(amount));out.extend_from_slice(&required::<32>(&r.note_commitment,"note commitment")?);out.extend_from_slice(&required::<32>(&r.value_commitment,"value commitment")?);out.extend_from_slice(&required::<32>(&r.epk,"epk")?);out.extend_from_slice(&required::<192>(&r.zkproof,"output proof")?);out.extend_from_slice(&required::<64>(&params.binding_signature,"binding signature")?);out.extend_from_slice(&required::<580>(&r.c_enc,"incoming ciphertext")?);out.extend_from_slice(&required::<80>(&r.c_out,"outgoing ciphertext")?);out.extend_from_slice(&[0;12]);Ok(out)}
        "transfer"=>encode_transfer_trigger(&params,&p.spend_authority_signature),
        "burn"=>encode_burn_trigger(&params,&p.spend_authority_signature,amount,&p.transparent_to_address),
        _=>Err(ApiError::InvalidArgument("parameter_type must be mint, transfer, or burn".into()))
    }
}
fn spend_bytes(s:&SpendDescription)->Result<Vec<u8>,ApiError>{let mut v=Vec::with_capacity(320);v.extend_from_slice(&required::<32>(&s.nullifier,"nullifier")?);v.extend_from_slice(&required::<32>(&s.anchor,"anchor")?);v.extend_from_slice(&required::<32>(&s.value_commitment,"value commitment")?);v.extend_from_slice(&required::<32>(&s.rk,"randomized key")?);v.extend_from_slice(&required::<192>(&s.zkproof,"spend proof")?);Ok(v)}
fn output_bytes(r:&ReceiveDescription)->Result<Vec<u8>,ApiError>{let mut v=Vec::with_capacity(288);v.extend_from_slice(&required::<32>(&r.note_commitment,"note commitment")?);v.extend_from_slice(&required::<32>(&r.value_commitment,"value commitment")?);v.extend_from_slice(&required::<32>(&r.epk,"epk")?);v.extend_from_slice(&required::<192>(&r.zkproof,"output proof")?);Ok(v)}
fn cipher_bytes(r:&ReceiveDescription)->Result<Vec<u8>,ApiError>{let mut v=Vec::with_capacity(672);v.extend_from_slice(&required::<580>(&r.c_enc,"incoming ciphertext")?);v.extend_from_slice(&required::<80>(&r.c_out,"outgoing ciphertext")?);v.extend_from_slice(&[0;12]);Ok(v)}
fn encode_transfer_trigger(p:&ShieldedTrc20Parameters,sigs:&[BytesMessage])->Result<Vec<u8>,ApiError>{let sc=p.spend_description.len();let rc=p.receive_description.len();if !(1..=2).contains(&sc)||!(1..=2).contains(&rc)||sigs.len()!=sc{return Err(ApiError::InvalidArgument("transfer requires one or two spends, matching signatures, and one or two outputs".into()))}let mut nfs=std::collections::BTreeSet::new();for s in &p.spend_description{if !nfs.insert(s.nullifier.clone()){return Err(ApiError::InvalidArgument("duplicate nullifier".into()))}}let input=p.spend_description.iter().map(spend_bytes).collect::<Result<Vec<_>,_>>()?.concat();let auth=sigs.iter().map(|s|required::<64>(&s.value,"spend authority signature").map(|v|v.to_vec())).collect::<Result<Vec<_>,_>>()?.concat();let output=p.receive_description.iter().map(output_bytes).collect::<Result<Vec<_>,_>>()?.concat();let cipher=p.receive_description.iter().map(cipher_bytes).collect::<Result<Vec<_>,_>>()?.concat();let a=192usize;let b=a+32+input.len();let c=b+32+auth.len();let d=c+32+output.len();let mut out=Vec::new();for x in [a,b,c]{out.extend_from_slice(&word_u256(x as u64))}out.extend_from_slice(&required::<64>(&p.binding_signature,"binding signature")?);out.extend_from_slice(&word_u256(d as u64));out.extend_from_slice(&word_u256(sc as u64));out.extend(input);out.extend_from_slice(&word_u256(sc as u64));out.extend(auth);out.extend_from_slice(&word_u256(rc as u64));out.extend(output);out.extend_from_slice(&word_u256(rc as u64));out.extend(cipher);Ok(out)}
fn encode_burn_trigger(p:&ShieldedTrc20Parameters,sigs:&[BytesMessage],amount:u64,address:&[u8])->Result<Vec<u8>,ApiError>{if amount==0||p.spend_description.len()!=1||p.receive_description.len()>1||sigs.len()!=1{return Err(ApiError::InvalidArgument("invalid burn parameters".into()))}let addr=trc20_contract(address)?;let burn=decode_hex(&p.trigger_contract_input)?;if burn.len()!=96{return Err(ApiError::InvalidArgument("burn cipher record must be 96 bytes".into()))}let mut out=spend_bytes(&p.spend_description[0])?;out.extend_from_slice(&required::<64>(&sigs[0].value,"spend authority signature")?);out.extend_from_slice(&word_u256(amount));out.extend_from_slice(&required::<64>(&p.binding_signature,"binding signature")?);let mut pay=[0;32];pay[11]=0x41;pay[12..].copy_from_slice(&addr);out.extend_from_slice(&pay);out.extend_from_slice(&burn);let output_offset=out.len()+64;let cipher_offset=output_offset+32+p.receive_description.len()*288;out.extend_from_slice(&word_u256(output_offset as u64));out.extend_from_slice(&word_u256(cipher_offset as u64));out.extend_from_slice(&word_u256(p.receive_description.len() as u64));if let Some(r)=p.receive_description.first(){out.extend(output_bytes(r)?)}out.extend_from_slice(&word_u256(p.receive_description.len() as u64));if let Some(r)=p.receive_description.first(){out.extend(cipher_bytes(r)?)}Ok(out)}
