use crate::{Precompile, Repository, TvmRules, Word};
use prost::Message;
use sha2::{Digest, Sha256};
use tron_crypto::{derive_address, CryptoEngine, PublicKey, RecoverableSignature};
use tron_protocol::protocol::{Account, DelegatedResource, Witness};
use tron_primitives::{Address20, TronAddress21};
use tron_state::{delegation, ResourceWindow, StoreKind};

pub const BATCH_VALIDATE_SIGN_ADDRESS:u32=0x0000_0009;
pub const VALIDATE_MULTI_SIGN_ADDRESS:u32=0x0000_000a;
pub const REWARD_BALANCE_ADDRESS:u32=0x0100_0005;
pub const IS_SR_CANDIDATE_ADDRESS:u32=0x0100_0006;
pub const VOTE_COUNT_ADDRESS:u32=0x0100_0007;
pub const USED_VOTE_COUNT_ADDRESS:u32=0x0100_0008;
pub const RECEIVED_VOTE_COUNT_ADDRESS:u32=0x0100_0009;
pub const TOTAL_VOTE_COUNT_ADDRESS:u32=0x0100_000a;
pub const GET_CHAIN_PARAMETER_ADDRESS:u32=0x0100_000b;
pub const AVAILABLE_UNFREEZE_V2_SIZE_ADDRESS:u32=0x0100_000c;
pub const UNFREEZABLE_BALANCE_V2_ADDRESS:u32=0x0100_000d;
pub const EXPIRE_UNFREEZE_BALANCE_V2_ADDRESS:u32=0x0100_000e;
pub const DELEGATABLE_RESOURCE_ADDRESS:u32=0x0100_000f;
pub const RESOURCE_V2_ADDRESS:u32=0x0100_0010;
pub const CHECK_UNDELEGATE_RESOURCE_ADDRESS:u32=0x0100_0011;
pub const RESOURCE_USAGE_ADDRESS:u32=0x0100_0012;
pub const TOTAL_RESOURCE_ADDRESS:u32=0x0100_0013;
pub const TOTAL_DELEGATED_RESOURCE_ADDRESS:u32=0x0100_0014;
pub const TOTAL_ACQUIRED_RESOURCE_ADDRESS:u32=0x0100_0015;

struct Native { kind: Kind }
#[derive(Clone,Copy)] enum Kind { Batch, Multi, Reward, IsSr, Vote, Used, Received, TotalVote, Chain, Available, Unfreezable, Expire, Delegatable, Resource, CheckUndelegate, Usage, TotalResource, TotalDelegated, TotalAcquired }
macro_rules! native {($name:ident,$kind:ident)=>{static $name:Native=Native{kind:Kind::$kind};}}
native!(BATCH,Batch);native!(MULTI,Multi);native!(REWARD,Reward);native!(IS_SR,IsSr);native!(VOTE,Vote);native!(USED,Used);native!(RECEIVED,Received);native!(TOTAL_VOTE,TotalVote);native!(CHAIN,Chain);native!(AVAILABLE,Available);native!(UNFREEZABLE,Unfreezable);native!(EXPIRE,Expire);native!(DELEGATABLE,Delegatable);native!(RESOURCE,Resource);native!(CHECK_UNDELEGATE,CheckUndelegate);native!(USAGE,Usage);native!(TOTAL_RESOURCE,TotalResource);native!(TOTAL_DELEGATED,TotalDelegated);native!(TOTAL_ACQUIRED,TotalAcquired);

fn low_address(a:&TronAddress21)->Option<u32>{let b=a.as_bytes();if b[1..17].iter().any(|v|*v!=0){None}else{Some(u32::from_be_bytes(b[17..21].try_into().ok()?))}}
pub(crate) fn contract(a:&TronAddress21,r:&TvmRules)->Option<&'static dyn Precompile>{Some(match low_address(a)?{
 BATCH_VALIDATE_SIGN_ADDRESS if r.solidity_059=>&BATCH, VALIDATE_MULTI_SIGN_ADDRESS if r.solidity_059=>&MULTI,
 REWARD_BALANCE_ADDRESS if r.vote=>&REWARD,IS_SR_CANDIDATE_ADDRESS if r.vote=>&IS_SR,VOTE_COUNT_ADDRESS if r.vote=>&VOTE,USED_VOTE_COUNT_ADDRESS if r.vote=>&USED,RECEIVED_VOTE_COUNT_ADDRESS if r.vote=>&RECEIVED,TOTAL_VOTE_COUNT_ADDRESS if r.vote=>&TOTAL_VOTE,
 GET_CHAIN_PARAMETER_ADDRESS if r.freeze_v2=>&CHAIN,AVAILABLE_UNFREEZE_V2_SIZE_ADDRESS if r.freeze_v2=>&AVAILABLE,UNFREEZABLE_BALANCE_V2_ADDRESS if r.freeze_v2=>&UNFREEZABLE,EXPIRE_UNFREEZE_BALANCE_V2_ADDRESS if r.freeze_v2=>&EXPIRE,DELEGATABLE_RESOURCE_ADDRESS if r.freeze_v2=>&DELEGATABLE,RESOURCE_V2_ADDRESS if r.freeze_v2=>&RESOURCE,CHECK_UNDELEGATE_RESOURCE_ADDRESS if r.freeze_v2=>&CHECK_UNDELEGATE,RESOURCE_USAGE_ADDRESS if r.freeze_v2=>&USAGE,TOTAL_RESOURCE_ADDRESS if r.freeze_v2=>&TOTAL_RESOURCE,TOTAL_DELEGATED_RESOURCE_ADDRESS if r.freeze_v2=>&TOTAL_DELEGATED,TOTAL_ACQUIRED_RESOURCE_ADDRESS if r.freeze_v2=>&TOTAL_ACQUIRED,_=>return None})}
fn out1(n:i64)->Vec<u8>{Word::from_u64(n as u64).to_be_bytes().to_vec()}
fn outn(ns:&[i64])->Vec<u8>{ns.iter().flat_map(|n|Word::from_u64(*n as u64).to_be_bytes()).collect()}
fn word(i:&[u8],n:usize)->Option<&[u8;32]>{i.get(n*32..n*32+32)?.try_into().ok()}
fn uint(i:&[u8],n:usize)->Option<usize>{let w=word(i,n)?;if w[..24].iter().any(|v|*v!=0){return None}usize::try_from(u64::from_be_bytes(w[24..].try_into().ok()?)).ok()}
fn int(i:&[u8],n:usize)->Option<i64>{Some(i64::from_be_bytes(word(i,n)?[24..].try_into().ok()?))}
fn address(i:&[u8],n:usize)->Option<TronAddress21>{let w=word(i,n)?;Some(TronAddress21::new(0x41,Address20::from_array(w[12..].try_into().ok()?)))}
fn frozen(a:&Account,t:i64)->i64{a.frozen_v2.iter().find(|v|i64::from(v.r#type)==t).map_or(0,|v|v.amount)}
fn legacy_bandwidth(a:&Account)->i64{a.frozen.iter().map(|v|v.frozen_balance).sum()}
fn legacy_energy(a:&Account)->i64{a.account_resource.as_ref().and_then(|r|r.frozen_balance_for_energy.as_ref()).map_or(0,|v|v.frozen_balance)}
fn total(a:&Account,t:i64)->i64{match t{0=>legacy_bandwidth(a)+frozen(a,0)+a.acquired_delegated_frozen_balance_for_bandwidth+a.acquired_delegated_frozen_v2_balance_for_bandwidth,1=>legacy_energy(a)+frozen(a,1)+a.account_resource.as_ref().map_or(0,|r|r.acquired_delegated_frozen_balance_for_energy+r.acquired_delegated_frozen_v2_balance_for_energy),_=>0}}
fn delegated(a:&Account,t:i64)->i64{match t{0=>a.delegated_frozen_balance_for_bandwidth+a.delegated_frozen_v2_balance_for_bandwidth,1=>a.account_resource.as_ref().map_or(0,|r|r.delegated_frozen_balance_for_energy+r.delegated_frozen_v2_balance_for_energy),_=>0}}
fn acquired(a:&Account,t:i64)->i64{match t{0=>a.acquired_delegated_frozen_balance_for_bandwidth+a.acquired_delegated_frozen_v2_balance_for_bandwidth,1=>a.account_resource.as_ref().map_or(0,|r|r.acquired_delegated_frozen_balance_for_energy+r.acquired_delegated_frozen_v2_balance_for_energy),_=>0}}
fn delegated_row(r:&Repository<'_>,from:&TronAddress21,to:&TronAddress21,locked:bool)->Option<DelegatedResource>{let k=delegation::resource_v2_key(from.as_bytes(),to.as_bytes(),locked);DelegatedResource::decode(r.get_raw(StoreKind::DelegatedResource,&k)?.as_slice()).ok()}
fn resource_v2(r:&Repository<'_>,from:&TronAddress21,to:&TronAddress21,t:i64)->i64{[false,true].into_iter().filter_map(|locked|delegated_row(r,from,to,locked)).map(|d|if t==0{d.frozen_balance_for_bandwidth}else if t==1{d.frozen_balance_for_energy}else{0}).sum()}
fn usage(r:&Repository<'_>,a:&Account,t:i64)->(i64,i64){let timestamp=r.dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP").ok().flatten().unwrap_or(0);let now=timestamp/3_000;let (raw,latest,window,precise,weight_key,limit_key)=if t==0{(a.net_usage,a.latest_consume_time,a.net_window_size,a.net_window_optimized,"TOTAL_NET_WEIGHT","TOTAL_NET_LIMIT")}else if t==1{let x=a.account_resource.as_ref();(x.map_or(0,|v|v.energy_usage),x.map_or(0,|v|v.latest_consume_time_for_energy),x.map_or(0,|v|v.energy_window_size),x.is_some_and(|v|v.energy_window_optimized),"TOTAL_ENERGY_WEIGHT","TOTAL_ENERGY_CURRENT_LIMIT")}else{return(0,0)};let effective_window=if window==0||(precise&&window<1_000){28_800}else if precise{window/1_000}else{window};if effective_window<=0||now>=latest.saturating_add(effective_window){return(0,0)}let recovered=ResourceWindow{usage:raw,latest_slot:latest,window,precise,standard_window:28_800}.recover(now).unwrap_or(0);let weight=r.dynamic_i64(weight_key).ok().flatten().unwrap_or(0);let limit=r.dynamic_i64(limit_key).ok().flatten().unwrap_or(0);let balance=if recovered<=0||weight<=0||limit<=0{0}else{i64::try_from(i128::from(recovered)*i128::from(weight)*1_000_000i128/i128::from(limit)).unwrap_or(i64::MAX)};(balance,(latest.saturating_add(effective_window)-now).saturating_mul(3))}
fn bytes_array(i:&[u8],head:usize,max:usize,strict:bool)->Option<Vec<Vec<u8>>>{let off=uint(i,head)?;if off%32!=0||off/32>=i.len()/32{return None}let base=off;let count=uint(i,base/32)?;if count>max{return None}let table=base.checked_add(32)?.checked_add(count.checked_mul(32)?)?;if table>i.len(){return None}let mut out=Vec::with_capacity(count);for n in 0..count{let rel=uint(i,base/32+1+n)?;let p=base.checked_add(rel)?;if p%32!=0||p+32>i.len(){return None}let len=uint(i,p/32)?;let start=p+32;let end=start.checked_add(len)?;if end>i.len(){return None}if strict {let padded=end.checked_add(31)?/32*32;if padded>i.len()||i[end..padded].iter().any(|b|*b!=0){return None}}out.push(i[start..end].to_vec())}Some(out)}
fn fixed_array(i:&[u8],head:usize,max:usize)->Option<Vec<[u8;32]>>{let off=uint(i,head)?;if off%32!=0{return None}let count=uint(i,off/32)?;if count>max{return None}(0..count).map(|n|word(i,off/32+1+n).copied()).collect()}
fn recover(hash:&[u8;32],sig:&[u8])->Option<TronAddress21>{let s=RecoverableSignature::from_consensus_wire(sig).ok()?;let p=PublicKey::recover_prehash(CryptoEngine::Secp256k1,hash,&s).ok()?;Some(derive_address(&p))}

impl Precompile for Native{
 fn energy(&self,i:&[u8],_:&TvmRules)->i64{match self.kind{Kind::Batch=>i64::try_from((i.len()/32).saturating_sub(5)/6).unwrap_or(i64::MAX).saturating_mul(1500),Kind::Multi=>i64::try_from((i.len()/32).saturating_sub(5)/5).unwrap_or(i64::MAX).saturating_mul(1500),Kind::Reward|Kind::Vote=>500,Kind::IsSr|Kind::Used|Kind::Received|Kind::TotalVote=>20,_=>50}}
 fn execute(&self,i:&[u8],rules:&TvmRules,r:&mut Repository<'_>)->(bool,Vec<u8>){self.execute_with_caller(i,rules,r,None)}
 fn execute_with_caller(&self,i:&[u8],rules:&TvmRules,r:&mut Repository<'_>,caller:Option<TronAddress21>)->(bool,Vec<u8>){let zero=||(true,out1(0));match self.kind{
  Kind::Batch=>{let Some(hash)=word(i,0).copied()else{return if rules.osaka{(false,Vec::new())}else{zero()}};let Some(sigs)=bytes_array(i,1,16,rules.osaka)else{return if rules.osaka{(false,Vec::new())}else{zero()}};let Some(addrs)=fixed_array(i,2,16)else{return if rules.osaka{(false,Vec::new())}else{zero()}};if sigs.is_empty()||sigs.len()!=addrs.len(){return zero()}let mut o=vec![0;32];for (n,(s,a)) in sigs.iter().zip(addrs).enumerate(){if recover(&hash,s).is_some_and(|x|x.as_bytes()[1..]==a[12..]){o[n]=1}}(true,o)}
  Kind::Multi=>{if i.len()<160{return if rules.osaka{(false,Vec::new())}else{zero()}}let(Some(owner),Some(pid),Some(data))=(address(i,0),int(i,1),word(i,2))else{return zero()};let Some(sigs)=bytes_array(i,3,5,rules.osaka)else{return if rules.osaka{(false,Vec::new())}else{zero()}};if sigs.is_empty(){return zero()}let mut pre=Vec::with_capacity(57);pre.extend_from_slice(owner.as_bytes());pre.extend_from_slice(&(pid as i32).to_be_bytes());pre.extend_from_slice(data);let hash:[u8;32]=Sha256::digest(pre).into();let Ok(Some(a))=r.account(&owner)else{return zero()};let permission=if pid==0{a.owner_permission.as_ref()}else if pid==1{a.witness_permission.as_ref()}else{a.active_permission.iter().find(|p|i64::from(p.id)==pid)};let Some(p)=permission else{return zero()};let mut seen=Vec::<TronAddress21>::new();let mut weight=0i64;for s in sigs{let Some(addr)=recover(&hash,&s)else{return zero()};if seen.contains(&addr){continue}let Some(k)=p.keys.iter().find(|k|k.address==addr.as_bytes())else{return zero()};let Some(w)=weight.checked_add(k.weight)else{return zero()};weight=w;seen.push(addr)}(true,out1(i64::from(weight>=p.threshold)))}
  Kind::Reward=>{let Some(a)=caller.and_then(|x|r.account(&x).ok().flatten())else{return zero()};(true,out1(a.allowance))}
  Kind::IsSr=>{if i.len()!=32{return zero()}let Some(a)=address(i,0)else{return zero()};(true,out1(i64::from(r.get_raw(StoreKind::Witness,a.as_bytes()).is_some())))}
  Kind::Vote=>{if i.len()!=64{return zero()}let(Some(a),Some(w))=(address(i,0),address(i,1))else{return zero()};let n=r.account(&a).ok().flatten().map_or(0,|x|x.votes.iter().filter(|v|v.vote_address==w.as_bytes()).map(|v|v.vote_count).sum());(true,out1(n))}
  Kind::Used=>{if i.len()!=32{return zero()}let Some(a)=address(i,0)else{return zero()};let n=r.account(&a).ok().flatten().map_or(0,|x|x.votes.iter().map(|v|v.vote_count).sum());(true,out1(n))}
  Kind::Received=>{if i.len()!=32{return zero()}let Some(a)=address(i,0)else{return zero()};let n=r.get_raw(StoreKind::Witness,a.as_bytes()).and_then(|v|Witness::decode(v.as_slice()).ok()).map_or(0,|w|w.vote_count);(true,out1(n))}
  Kind::TotalVote=>{if i.len()!=32{return zero()}let Some(x)=address(i,0)else{return zero()};let Some(a)=r.account(&x).ok().flatten()else{return zero()};let ordinary=legacy_bandwidth(&a)+legacy_energy(&a)+delegated(&a,0)+delegated(&a,1)+frozen(&a,0)+frozen(&a,1);let power=if r.dynamic_i64("ALLOW_NEW_RESOURCE_MODEL").ok().flatten()==Some(1){match a.old_tron_power{-1=>frozen(&a,2),0=>ordinary+frozen(&a,2),n=>n+frozen(&a,2)}}else{ordinary};(true,out1(power/1_000_000))}
  Kind::Chain=>{if i.len()!=32{return zero()}let Some(c)=int(i,0)else{return zero()};let key=match c{1=>"TOTAL_NET_LIMIT",2=>"TOTAL_NET_WEIGHT",3=>"TOTAL_ENERGY_CURRENT_LIMIT",4=>"TOTAL_ENERGY_WEIGHT",5=>"UNFREEZE_DELAY_DAYS",_=>return zero()};(true,out1(r.dynamic_i64(key).ok().flatten().unwrap_or(0)))}
  Kind::Available=>{if i.len()!=32{return zero()}let Some(x)=address(i,0)else{return zero()};let now=r.dynamic_i64("LATEST_BLOCK_HEADER_TIMESTAMP").ok().flatten().unwrap_or(0);let n=r.account(&x).ok().flatten().map_or(0,|a|a.unfrozen_v2.iter().filter(|v|v.unfreeze_expire_time>now).count());(true,out1(32i64.saturating_sub(n as i64).max(0)))}
  Kind::Unfreezable=>{if i.len()!=64{return zero()}let(Some(x),Some(t))=(address(i,0),int(i,1))else{return zero()};(true,out1(r.account(&x).ok().flatten().map_or(0,|a|frozen(&a,t))))}
  Kind::Expire=>{if i.len()!=64{return zero()}let(Some(x),Some(mut t))=(address(i,0),int(i,1))else{return zero()};if t<0{return zero()}t=t.checked_mul(1000).unwrap_or(i64::MAX);let n=r.account(&x).ok().flatten().map_or(0,|a|a.unfrozen_v2.iter().filter(|v|v.unfreeze_expire_time<=t).map(|v|v.unfreeze_amount).sum());(true,out1(n))}
  Kind::Delegatable=>{if i.len()!=64{return zero()}let(Some(x),Some(t))=(address(i,0),int(i,1))else{return zero()};let Some(a)=r.account(&x).ok().flatten()else{return zero()};let own=frozen(&a,t);let used=usage(r,&a,t).0;let legacy=if t==0{legacy_bandwidth(&a)+acquired(&a,0)}else if t==1{legacy_energy(&a)+acquired(&a,1)}else{return zero()};(true,out1((own-(used-legacy).max(0)).max(0)))}
  Kind::Resource=>{if i.len()!=96{return zero()}let(Some(to),Some(from),Some(t))=(address(i,0),address(i,1),int(i,2))else{return zero()};let n=if from==to{r.account(&from).ok().flatten().map_or(0,|a|frozen(&a,t))}else{resource_v2(r,&from,&to,t)};(true,out1(n))}
  Kind::CheckUndelegate=>{if i.len()!=96{return (true,outn(&[0,0,0]))}let(Some(x),Some(amount),Some(t))=(address(i,0),int(i,1),int(i,2))else{return (true,outn(&[0,0,0]))};if amount<=0{return (true,outn(&[0,0,0]))}let Some(a)=r.account(&x).ok().flatten()else{return (true,outn(&[0,0,0]))};let limit=total(&a,t);let (used,restore)=usage(r,&a,t);let amount=amount.min(limit);let clean=if limit<=used||limit<=0{0}else{((amount as f64)*((limit-used) as f64)/(limit as f64)) as i64};(true,outn(&[clean,amount-clean,restore]))}
  Kind::Usage=>{if i.len()!=64{return (true,outn(&[0,0]))}let(Some(x),Some(t))=(address(i,0),int(i,1))else{return (true,outn(&[0,0]))};let v=r.account(&x).ok().flatten().map_or((0,0),|a|usage(r,&a,t));(true,outn(&[v.0,v.1]))}
  Kind::TotalResource|Kind::TotalDelegated|Kind::TotalAcquired=>{if i.len()!=64{return zero()}let(Some(x),Some(t))=(address(i,0),int(i,1))else{return zero()};let n=r.account(&x).ok().flatten().map_or(0,|a|match self.kind{Kind::TotalResource=>total(&a,t),Kind::TotalDelegated=>delegated(&a,t),_=>acquired(&a,t)});(true,out1(n))}
 } }
}
