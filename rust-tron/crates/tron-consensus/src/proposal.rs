use std::collections::{BTreeMap,BTreeSet};
use prost::Message;
use tron_protocol::protocol::{proposal::State,Proposal};
use tron_state::StoreKind;
use crate::state::{ConsensusRead,StateError,StateFacade};

#[derive(Clone,Debug,Eq,PartialEq)] pub struct ParameterRule{pub dynamic:&'static str,pub depends_on:Option<(i64,i64)>,pub one_shot:bool}
#[derive(Clone,Debug,Eq,PartialEq)] pub struct ProposalHistory{pub id:i64,pub approved:bool,pub active_approvals:usize,pub active_witnesses:usize,pub writes:Vec<(&'static str,i64)>}
#[derive(Clone,Debug,Eq,PartialEq)] pub struct ProposalScan{pub examined:Vec<i64>,pub history:Vec<ProposalHistory>}

pub fn approval_threshold(active:usize)->usize{active*7/10}
pub fn has_most_approvals(proposal:&Proposal,active:&[Vec<u8>])->bool{let set:BTreeSet<&[u8]>=active.iter().map(Vec::as_slice).collect();proposal.approvals.iter().filter(|a|set.contains(a.as_slice())).count()>=approval_threshold(active.len())}
pub fn process_expired_proposals(state:&StateFacade<'_>,rules:&BTreeMap<i64,ParameterRule>)->Result<ProposalScan,StateError>{
 let mut child=state.child_session()?;let facade=StateFacade::new(&child);let latest=facade.dynamic_long("LATEST_PROPOSAL_NUM").unwrap_or(0);let now=facade.dynamic_long("NEXT_MAINTENANCE_TIME")?;let active=facade.active_witnesses()?;let mut scan=ProposalScan{examined:vec![],history:vec![]};
 for id in (1..=latest).rev(){let key=id.to_be_bytes();let Some(bytes)=facade.store_get(StoreKind::Proposal,&key)else{continue};let mut p=Proposal::decode(bytes.as_slice()).map_err(|e|StateError::InvalidProtobuf{store:StoreKind::Proposal,key:key.to_vec(),source:e.to_string()})?;scan.examined.push(id);if p.state==State::Approved as i32||p.state==State::Disapproved as i32{break}if p.state==State::Canceled as i32||p.expiration_time>now{continue}let active_count={let set:BTreeSet<&[u8]>=active.iter().map(Vec::as_slice).collect();p.approvals.iter().filter(|a|set.contains(a.as_slice())).count()};let approved=active_count>=approval_threshold(active.len());let writes=if approved{apply_parameters(&facade,&p.parameters,rules)?}else{vec![]};p.state=if approved{State::Approved}else{State::Disapproved} as i32;facade.store_put(StoreKind::Proposal,&key,&p.encode_to_vec())?;scan.history.push(ProposalHistory{id,approved,active_approvals:active_count,active_witnesses:active.len(),writes});}
 child.merge()?;Ok(scan)
}
fn apply_parameters(state:&StateFacade<'_>,params:&BTreeMap<i64,i64>,rules:&BTreeMap<i64,ParameterRule>)->Result<Vec<(&'static str,i64)>,StateError>{let mut writes=Vec::new();for(&id,&value)in params{let Some(rule)=rules.get(&id)else{continue};if let Some((dependency,required))=rule.depends_on{let dependency_value=params.get(&dependency).copied().or_else(||rules.get(&dependency).and_then(|r|state.dynamic_long(r.dynamic).ok())).unwrap_or(0);if dependency_value!=required{continue}}if rule.one_shot&&state.dynamic_long(rule.dynamic).unwrap_or(0)!=0{continue}state.save_dynamic_long(rule.dynamic,value)?;writes.push((rule.dynamic,value));}Ok(writes)}
