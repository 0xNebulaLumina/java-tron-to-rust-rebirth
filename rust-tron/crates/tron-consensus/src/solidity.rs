use std::collections::BTreeMap;
use crate::state::{ConsensusRead,StateError,StateFacade};

#[derive(Clone,Debug,Eq,PartialEq)] pub struct SolidityUpdate{pub previous:i64,pub candidate:i64,pub applied:i64,pub position:usize}
pub fn solidity_position(size:usize)->usize{((size as f64)*0.3)as usize}
pub fn update_solidity(state:&StateFacade<'_>)->Result<SolidityUpdate,StateError>{let mut child=state.child_session()?;let facade=StateFacade::new(&child);let active=facade.active_witnesses()?;if active.is_empty(){return Err(StateError::ArithmeticOverflow("empty active witness set"))}let mut numbers=Vec::with_capacity(active.len());for address in active{numbers.push(facade.witness(&address)?.ok_or_else(||StateError::InvalidProtobuf{store:tron_state::StoreKind::Witness,key:address,source:"missing active witness".into()})?.latest_block_num);}numbers.sort_unstable();let position=solidity_position(numbers.len());let candidate=numbers[position];let previous=facade.dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM")?;let applied=previous.max(candidate);if applied!=previous{facade.save_dynamic_long("LATEST_SOLIDIFIED_BLOCK_NUM",applied)?;}child.merge()?;Ok(SolidityUpdate{previous,candidate,applied,position})}

#[derive(Clone,Debug,Eq,PartialEq)] pub struct ForkSpec{pub version:i32,pub hard_fork_time:i64,pub rate_percent:usize}
#[derive(Clone,Debug,Default,Eq,PartialEq)] pub struct ForkState{pub latest_version:i32,pub stats:BTreeMap<i32,Vec<u8>>}
#[derive(Clone,Debug,Eq,PartialEq)] pub struct ForkUpdate{pub activated:bool,pub latest_version:i32,pub stats:Vec<u8>}
pub trait CanonicalForkEvaluator{fn passes(&self,spec:&ForkSpec,stats:&[u8])->bool;}
impl<F:Fn(&ForkSpec,&[u8])->bool> CanonicalForkEvaluator for F{fn passes(&self,s:&ForkSpec,b:&[u8])->bool{self(s,b)}}
pub fn java_fork_pass(spec:&ForkSpec,latest_block_time:i64,maintenance_interval:i64,stats:&[u8])->bool{if maintenance_interval<=0{return false}let hard=((spec.hard_fork_time-1)/maintenance_interval+1)*maintenance_interval;if latest_block_time<hard||stats.is_empty(){return false}let required=(spec.rate_percent*stats.len()).div_ceil(100);stats.iter().filter(|&&v|v==1).count()>=required}
pub fn update_fork(state:&mut ForkState,specs:&[ForkSpec],active:&[Vec<u8>],producer:&[u8],block_version:i32,evaluator:&impl CanonicalForkEvaluator)->ForkUpdate{
    let Some(slot)=active.iter().position(|a|a==producer)else{return ForkUpdate{activated:false,latest_version:state.latest_version,stats:vec![]}};
    if state.latest_version>=block_version{return ForkUpdate{activated:false,latest_version:state.latest_version,stats:state.stats.get(&block_version).cloned().unwrap_or_default()}}
    for spec in specs.iter().filter(|s|s.version>block_version){
        if !state.stats.get(&spec.version).is_some_and(|v|evaluator.passes(spec,v)){if let Some(stats)=state.stats.get_mut(&spec.version){if slot<stats.len(){stats[slot]=0;}}}
    }
    let stats=state.stats.entry(block_version).or_insert_with(||vec![0;active.len()]);if stats.len()!=active.len(){*stats=vec![0;active.len()]}
    let activates=specs.iter().find(|s|s.version==block_version).is_some_and(|s|evaluator.passes(s,stats));
    if activates{
        let result_stats=stats.clone();
        for lower in specs.iter().filter(|s|s.version<block_version){if !state.stats.get(&lower.version).is_some_and(|v|evaluator.passes(lower,v)){state.stats.insert(lower.version,vec![1;active.len()]);}}
        state.latest_version=block_version;return ForkUpdate{activated:true,latest_version:block_version,stats:result_stats}
    }
    let stats=state.stats.get_mut(&block_version).expect("inserted above");stats[slot]=1;ForkUpdate{activated:false,latest_version:state.latest_version,stats:stats.clone()}
}
pub fn maintenance_reset(state:&mut ForkState,specs:&[ForkSpec],active_size:usize,evaluator:&impl CanonicalForkEvaluator){for spec in specs{if let Some(stats)=state.stats.get(&spec.version){if !evaluator.passes(spec,stats){state.stats.insert(spec.version,vec![0;active_size]);}}}}
