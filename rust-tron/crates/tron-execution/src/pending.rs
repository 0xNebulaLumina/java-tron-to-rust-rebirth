use std::collections::VecDeque;
use tron_primitives::Hash32;
use tron_state::{PendingSession,Session,SessionError,SessionManager};
use crate::TransactionCache;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PendingLimits { pub maximum:usize, pub timeout_millis:i64, pub shielded_maximum:usize, pub smart_drain_limit:usize }
impl Default for PendingLimits { fn default()->Self { Self{maximum:2_000,timeout_millis:60_000,shielded_maximum:10,smart_drain_limit:100} } }
#[derive(Clone,Debug)]pub struct PendingTransaction<T>{pub id:Hash32,pub transaction:T,pub received_at:i64,pub shielded:bool,pub smart:bool}
#[derive(Clone,Debug,Eq,PartialEq)]pub enum PendingReject{Duplicate,Full,ShieldedFull,Expired,Execution(String),Closed}
#[derive(Clone,Debug,Eq,PartialEq)]pub enum BroadcastResult{Accepted{transaction_id:Hash32},Rejected{transaction_id:Hash32,reason:PendingReject}}

pub struct PendingPool<T>{limits:PendingLimits,pending:VecDeque<PendingTransaction<T>>,popped:VecDeque<PendingTransaction<T>>,smart:VecDeque<PendingTransaction<T>>,shielded:usize,session:Option<PendingSession>}
impl<T> PendingPool<T>{
 pub fn new(manager:SessionManager,limits:PendingLimits)->Result<Self,SessionError>{if limits.maximum==0||limits.timeout_millis<=0||limits.shielded_maximum>limits.maximum{return Err(SessionError::InvalidSession)};Ok(Self{limits,pending:VecDeque::new(),popped:VecDeque::new(),smart:VecDeque::new(),shielded:0,session:Some(PendingSession::new(manager)? )})}
 #[must_use]pub fn len(&self)->usize{self.pending.len()+self.popped.len()+self.smart.len()}
 #[must_use]pub fn is_empty(&self)->bool{self.len()==0}
 pub fn broadcast(&mut self,item:PendingTransaction<T>,now:i64)->BroadcastResult{
  let id=item.id;let reason=if self.session.is_none(){Some(PendingReject::Closed)}else if now-item.received_at>=self.limits.timeout_millis{Some(PendingReject::Expired)}else if self.contains(&id){Some(PendingReject::Duplicate)}else if self.len()>=self.limits.maximum{Some(PendingReject::Full)}else if item.shielded&&self.shielded>=self.limits.shielded_maximum{Some(PendingReject::ShieldedFull)}else{None};
  if let Some(reason)=reason{return BroadcastResult::Rejected{transaction_id:id,reason}}
  if item.shielded{self.shielded+=1}if item.smart{self.smart.push_back(item)}else{self.pending.push_back(item)}BroadcastResult::Accepted{transaction_id:id}
 }
 pub fn pop(&mut self,now:i64)->Option<PendingTransaction<T>> where T:Clone{self.expire(now);let item=self.pending.pop_front()?;self.popped.push_back(item.clone());Some(item)}
 pub fn take_next(&mut self,now:i64)->Option<PendingTransaction<T>>{self.expire(now);let item=self.pending.pop_front()?;if item.shielded{self.shielded-=1}Some(item)}
 pub fn mark_popped(&mut self,item:PendingTransaction<T>){if item.shielded{self.shielded+=1}self.popped.push_back(item)}
 pub fn execute_next<F>(&mut self,now:i64,mut execute:F)->Option<BroadcastResult> where F:FnMut(&PendingTransaction<T>,&Session)->Result<(),String>{let item=self.take_next(now)?;let id=item.id;let pending=self.session.as_ref()?;let mut child=match pending.child(){Ok(v)=>v,Err(e)=>return Some(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(e.to_string())})};match execute(&item,&child){Ok(())=>match pending.merge_child(&mut child){Ok(())=>{if item.shielded{self.shielded+=1}self.popped.push_back(item);Some(BroadcastResult::Accepted{transaction_id:id})},Err(e)=>Some(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(e.to_string())})},Err(message)=>{let _=child.revoke();Some(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(message)})}}}
 pub fn drain_smart<F>(&mut self,now:i64,mut execute:F)->Vec<BroadcastResult>where F:FnMut(&PendingTransaction<T>,&Session)->Result<(),String>{self.expire(now);let count=self.smart.len().min(self.limits.smart_drain_limit);let mut results=Vec::with_capacity(count);for _ in 0..count{let Some(item)=self.smart.pop_front()else{break};if item.shielded{self.shielded-=1}let id=item.id;let pending=self.session.as_ref().expect("open checked by queue ownership");let mut child=match pending.child(){Ok(v)=>v,Err(e)=>{results.push(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(e.to_string())});continue}};match execute(&item,&child){Ok(())=>match pending.merge_child(&mut child){Ok(())=>{if item.shielded{self.shielded+=1}self.popped.push_back(item);results.push(BroadcastResult::Accepted{transaction_id:id})},Err(e)=>results.push(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(e.to_string())})},Err(message)=>{let _=child.revoke();results.push(BroadcastResult::Rejected{transaction_id:id,reason:PendingReject::Execution(message)})}}}results}
 /// Rebuild order matches Java PendingManager.close(): transactions which
 /// remained pending are requeued before transactions popped for the abandoned block.
 /// Pending receipt timestamps are retained; every popped transaction is refreshed
 /// to the trusted close time before it is appended.
 pub fn requeue_after_fork(&mut self,cache:&mut TransactionCache,current_time:i64)->Result<(),SessionError>{let pending=self.session.as_mut().ok_or(SessionError::InvalidSession)?;pending.reset()?;cache.clear();for item in &mut self.popped{item.received_at=current_time}self.pending.append(&mut self.popped);self.recount();Ok(())}
 pub fn shutdown(&mut self)->Result<(),SessionError>{if let Some(mut session)=self.session.take(){session.close()?}self.pending.clear();self.popped.clear();self.smart.clear();self.shielded=0;Ok(())}
 fn contains(&self,id:&Hash32)->bool{self.pending.iter().chain(&self.popped).chain(&self.smart).any(|item|&item.id==id)}
 fn expire(&mut self,now:i64){let timeout=self.limits.timeout_millis;self.pending.retain(|item|now-item.received_at<timeout);self.popped.retain(|item|now-item.received_at<timeout);self.smart.retain(|item|now-item.received_at<timeout);self.recount()}
 fn recount(&mut self){self.shielded=self.pending.iter().chain(&self.popped).chain(&self.smart).filter(|item|item.shielded).count()}
 #[must_use]pub fn pending_ids(&self)->Vec<Hash32>{self.pending.iter().map(|x|x.id).collect()}
}
