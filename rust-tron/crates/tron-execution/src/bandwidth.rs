use tron_state::{GlobalResource, ResourceWindow, global_limit};

pub const TRX_PRECISION:i64=1_000_000;
pub const BANDWIDTH_WINDOW:i64=28_800;
pub const PER_SIGN_LENGTH:i64=65;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BandwidthPolicy { pub total_net_limit:i64,pub total_net_weight:i64,pub free_net_limit:i64,pub public_net_limit:i64,pub transaction_fee:i64,pub create_account_fee:i64,pub create_account_bandwidth_rate:i64,pub max_create_account_tx_size:i64,pub multi_sign_fee:i64,pub memo_fee:i64,pub support_unfreeze_delay:bool,pub harden_calculation:bool }
impl Default for BandwidthPolicy { fn default()->Self{Self{total_net_limit:43_200_000_000,total_net_weight:0,free_net_limit:5_000,public_net_limit:57_600_000_000,transaction_fee:1_000,create_account_fee:100_000,create_account_bandwidth_rate:1,max_create_account_tx_size:1_000,multi_sign_fee:1_000_000,memo_fee:0,support_unfreeze_delay:false,harden_calculation:false}}}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BandwidthAccount { pub address:Vec<u8>,pub balance:i64,pub frozen_bandwidth:i64,pub net_usage:i64,pub free_net_usage:i64,pub latest_consume_time:i64,pub latest_consume_free_time:i64,pub latest_operation_time:i64,pub net_window:i64,pub net_window_optimized:bool }
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicBandwidth { pub usage:i64,pub latest_time:i64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum BandwidthSource{Frozen,Free,Fee,CreateAccountFrozen,CreateAccountFee}
#[derive(Clone, Debug, Eq, PartialEq)] pub struct BandwidthCharge{pub source:BandwidthSource,pub net_usage:i64,pub net_fee:i64,pub multi_sign_fee:i64,pub memo_fee:i64,pub net_fee_for_bandwidth:bool}
#[derive(Clone, Debug, Eq, PartialEq)] pub enum BandwidthError{Arithmetic,TooBigNewAccount{size:i64,max:i64},Insufficient{address:Vec<u8>,bytes:i64,fee:i64}}
impl core::fmt::Display for BandwidthError{fn fmt(&self,f:&mut core::fmt::Formatter<'_>)->core::fmt::Result{match self{Self::Arithmetic=>f.write_str("long overflow"),Self::TooBigNewAccount{size,max}=>write!(f,"Too big new account transaction, the size is {size} bytes, maxTxSize {max}"),Self::Insufficient{address,bytes,fee}=>write!(f,"account [{address:02x?}] has insufficient bandwidth[{bytes}] and balance[{fee}]")}}} impl std::error::Error for BandwidthError{}

pub fn recover_usage(last:i64,last_time:i64,now:i64,window:i64)->i64{if last<=0||now>=last_time.saturating_add(window){0}else if now<=last_time{last}else{let remain=window-(now-last_time);((i128::from(last)*i128::from(remain)+i128::from(window)-1)/i128::from(window)) as i64}}
pub fn global_net_limit(frozen:i64,policy:BandwidthPolicy)->Result<i64,BandwidthError>{if frozen<0||policy.total_net_weight<=0||policy.total_net_limit<=0{return Ok(0)} if policy.harden_calculation{return global_limit(frozen,GlobalResource{limit:policy.total_net_limit,weight:policy.total_net_weight},policy.support_unfreeze_delay).map_err(|_|BandwidthError::Arithmetic)} let weight=if policy.support_unfreeze_delay{frozen as f64/TRX_PRECISION as f64}else{(frozen/TRX_PRECISION) as f64};Ok((weight*(policy.total_net_limit as f64/policy.total_net_weight as f64)) as i64)}

pub fn consume_bandwidth(account:&mut BandwidthAccount,public:&mut PublicBandwidth,bytes:i64,now:i64,operation_time:i64,create_account:bool,unsigned_size:i64,policy:BandwidthPolicy)->Result<BandwidthCharge,BandwidthError>{
 if create_account&&unsigned_size>policy.max_create_account_tx_size{return Err(BandwidthError::TooBigNewAccount{size:unsigned_size,max:policy.max_create_account_tx_size})}
 let mut cost=bytes;
 if create_account{cost=bytes.checked_mul(policy.create_account_bandwidth_rate).ok_or(BandwidthError::Arithmetic)?}
 let window=ResourceWindow{usage:account.net_usage,latest_slot:account.latest_consume_time,window:account.net_window,precise:account.net_window_optimized,standard_window:BANDWIDTH_WINDOW};let recovered=window.recover(now).map_err(|_|BandwidthError::Arithmetic)?;let limit=global_net_limit(account.frozen_bandwidth,policy)?;
 if cost<=limit.saturating_sub(recovered){let consumed=window.consume(cost,now).map_err(|_|BandwidthError::Arithmetic)?;account.net_usage=consumed.usage;account.latest_consume_time=consumed.latest_slot;account.net_window=consumed.window;account.net_window_optimized=consumed.precise;account.latest_operation_time=operation_time;return Ok(BandwidthCharge{source:if create_account{BandwidthSource::CreateAccountFrozen}else{BandwidthSource::Frozen},net_usage:cost,net_fee:0,multi_sign_fee:0,memo_fee:0,net_fee_for_bandwidth:!create_account})}
 if create_account{return charge_fee(account,policy.create_account_fee,bytes,BandwidthSource::CreateAccountFee,false)}
 let free=recover_usage(account.free_net_usage,account.latest_consume_free_time,now,BANDWIDTH_WINDOW);let public_used=recover_usage(public.usage,public.latest_time,now,BANDWIDTH_WINDOW);
 if bytes<=policy.free_net_limit.saturating_sub(free)&&bytes<=policy.public_net_limit.saturating_sub(public_used){account.free_net_usage=free.checked_add(bytes).ok_or(BandwidthError::Arithmetic)?;account.latest_consume_free_time=now;account.latest_operation_time=operation_time;public.usage=public_used.checked_add(bytes).ok_or(BandwidthError::Arithmetic)?;public.latest_time=now;return Ok(BandwidthCharge{source:BandwidthSource::Free,net_usage:bytes,net_fee:0,multi_sign_fee:0,memo_fee:0,net_fee_for_bandwidth:true})}
 let fee=bytes.checked_mul(policy.transaction_fee).ok_or(BandwidthError::Arithmetic)?;charge_fee(account,fee,bytes,BandwidthSource::Fee,true)
}
fn charge_fee(account:&mut BandwidthAccount,fee:i64,bytes:i64,source:BandwidthSource,net_fee_for_bandwidth:bool)->Result<BandwidthCharge,BandwidthError>{if account.balance<fee{return Err(BandwidthError::Insufficient{address:account.address.clone(),bytes,fee})}account.balance-=fee;Ok(BandwidthCharge{source,net_usage:0,net_fee:fee,multi_sign_fee:0,memo_fee:0,net_fee_for_bandwidth})}
pub fn charge_metadata_fees(account:&mut BandwidthAccount,signature_count:usize,has_memo:bool,policy:BandwidthPolicy)->Result<(i64,i64),BandwidthError>{let multi=if signature_count>1{policy.multi_sign_fee}else{0};let memo=if has_memo{policy.memo_fee}else{0};let total=multi.checked_add(memo).ok_or(BandwidthError::Arithmetic)?;if account.balance<total{return Err(BandwidthError::Insufficient{address:account.address.clone(),bytes:0,fee:total})}account.balance-=total;Ok((multi,memo))}
pub fn unsigned_create_account_size(serialized_without_ret:i64,signature_count:usize)->Result<i64,BandwidthError>{serialized_without_ret.checked_sub(i64::try_from(signature_count).map_err(|_|BandwidthError::Arithmetic)?.checked_mul(PER_SIGN_LENGTH).ok_or(BandwidthError::Arithmetic)?).ok_or(BandwidthError::Arithmetic)}
