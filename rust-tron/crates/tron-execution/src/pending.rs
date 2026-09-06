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

pub struct PendingPool<T>{manager:SessionManager,limits:PendingLimits,pending:VecDeque<PendingTransaction<T>>,popped:VecDeque<PendingTransaction<T>>,smart:VecDeque<PendingTransaction<T>>,shielded:usize,session:Option<PendingSession>,inject_discard_commit:bool,inject_replay_failure:bool}
pub struct ForkPendingSnapshot<T>{pending:VecDeque<PendingTransaction<T>>,popped:VecDeque<PendingTransaction<T>>,smart:VecDeque<PendingTransaction<T>>,shielded:usize}
impl<T> PendingPool<T>{
 pub fn new(manager:SessionManager,limits:PendingLimits)->Result<Self,SessionError>{if limits.maximum==0||limits.timeout_millis<=0||limits.shielded_maximum>limits.maximum{return Err(SessionError::InvalidSession)};Ok(Self{manager:manager.clone(),limits,pending:VecDeque::new(),popped:VecDeque::new(),smart:VecDeque::new(),shielded:0,session:Some(PendingSession::new(manager)? ),inject_discard_commit:false,inject_replay_failure:false})}
 #[must_use]pub fn len(&self)->usize{self.pending.len()+self.popped.len()+self.smart.len()}
 #[must_use]pub fn is_empty(&self)->bool{self.len()==0}
 pub fn broadcast(&mut self,item:PendingTransaction<T>,now:i64)->BroadcastResult{
  let id=item.id;let reason=if self.session.is_none(){Some(PendingReject::Closed)}else if now-item.received_at>=self.limits.timeout_millis{Some(PendingReject::Expired)}else if self.contains(&id){Some(PendingReject::Duplicate)}else if self.len()>=self.limits.maximum{Some(PendingReject::Full)}else if item.shielded&&self.shielded>=self.limits.shielded_maximum{Some(PendingReject::ShieldedFull)}else{None};
  if let Some(reason)=reason{return BroadcastResult::Rejected{transaction_id:id,reason}}
  if item.shielded{self.shielded+=1}if item.smart{self.smart.push_back(item)}else{self.pending.push_back(item)}BroadcastResult::Accepted{transaction_id:id}
 }
 /// Executes admission and transaction effects in a child of the canonical pending
 /// session, then publishes both the speculative state and queue entry atomically.
 /// Failed validation/execution never becomes visible in either pending state or queues.
 pub fn admit<F,E>(&mut self,item:PendingTransaction<T>,now:i64,execute:F)->Result<BroadcastResult,E>
 where F:FnOnce(&PendingTransaction<T>,&Session)->Result<(),E>,E:From<SessionError>{
  let id=item.id;
  let reason=if self.session.is_none(){Some(PendingReject::Closed)}else if now-item.received_at>=self.limits.timeout_millis{Some(PendingReject::Expired)}else if self.contains(&id){Some(PendingReject::Duplicate)}else if self.len()>=self.limits.maximum{Some(PendingReject::Full)}else if item.shielded&&self.shielded>=self.limits.shielded_maximum{Some(PendingReject::ShieldedFull)}else{None};
  if let Some(reason)=reason{return Ok(BroadcastResult::Rejected{transaction_id:id,reason})}
  let pending=self.session.as_ref().expect("open checked above");
  let mut child=pending.child().map_err(E::from)?;
  if let Err(error)=execute(&item,&child){let _=child.revoke();return Err(error)}
  if let Err(error)=pending.merge_child(&mut child){let _=child.revoke();return Err(E::from(error))}
  if item.shielded{self.shielded+=1}
  if item.smart{self.smart.push_back(item)}else{self.pending.push_back(item)}
  Ok(BroadcastResult::Accepted{transaction_id:id})
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
 /// Suspends the speculative pending layer before canonical state is rewound.
 /// The returned snapshot is reserved for exact failure restoration.
 pub fn suspend_for_fork(&mut self)->Result<ForkPendingSnapshot<T>,SessionError> where T:Clone{
  let snapshot=ForkPendingSnapshot{pending:self.pending.clone(),popped:self.popped.clone(),smart:self.smart.clone(),shielded:self.shielded};
  let mut session=self.session.take().ok_or(SessionError::InvalidSession)?;
  if let Err(error)=session.close(){self.session=Some(session);return Err(error)}
  Ok(snapshot)
 }
 /// Restores queue contents and timestamps exactly after a failed fork switch.
 pub fn restore_after_failed_fork(&mut self,snapshot:ForkPendingSnapshot<T>)->Result<(),SessionError>{
  self.pending=snapshot.pending;self.popped=snapshot.popped;self.smart=snapshot.smart;self.shielded=snapshot.shielded;
  self.session=Some(PendingSession::new(self.manager())?);Ok(())
 }
 /// Reopens pending execution and mirrors Java PendingManager.close ordering:
 /// held pending first, then transactions popped from abandoned blocks with a
 /// refreshed trusted timestamp.
 pub fn resume_after_fork(&mut self,mut abandoned:VecDeque<PendingTransaction<T>>,_cache:&mut TransactionCache,current_time:i64)->Result<(),SessionError>{
  if self.session.is_some(){return Err(SessionError::InvalidSession)}
  for item in &mut self.popped{item.received_at=current_time}for item in &mut abandoned{item.received_at=current_time}
  self.popped.append(&mut abandoned);self.recount();
  self.session=Some(PendingSession::new(self.manager())?);Ok(())
 }
 pub fn finish_fork_requeue(&mut self){self.pending.append(&mut self.popped);self.recount();}
 pub fn discard_fork_rebuild(&mut self)->Result<(),SessionError>{
  if self.inject_discard_commit{self.inject_discard_commit=false;self.session.as_mut().ok_or(SessionError::InvalidSession)?.inject_committed_close_failure()?}
  if let Some(mut session)=self.session.take(){session.close()?}
  self.pending.clear();self.popped.clear();self.smart.clear();self.shielded=0;Ok(())
 }
 /// Forces removal of a malformed speculative pending stack after ordinary
 /// discard failed, so an exact pre-fork snapshot can be reconstructed.
 pub fn force_discard_fork_rebuild(&mut self){
  self.manager.force_reset_pending_outer();self.session=None;
  self.pending.clear();self.popped.clear();self.smart.clear();self.shielded=0;
 }
 #[doc(hidden)]
 pub fn inject_committed_discard_failure(&mut self){self.inject_discard_commit=true}
 #[doc(hidden)]
 pub fn inject_replay_failure(&mut self){self.inject_replay_failure=true}
 /// Replays every transaction which contributed to the speculative pending
 /// session, while preserving its ordinary, popped, or smart queue ownership.
 /// Successful fork replay drops transactions no longer valid on the replacement
 /// branch; failed-fork restoration is strict because the original speculative
 /// state must be reconstructed exactly.
 pub fn replay_speculative<F>(&mut self,strict:bool,mut execute:F)->Result<(),SessionError>
 where F:FnMut(&mut PendingTransaction<T>,&Session)->Result<(),String>{
  if self.inject_replay_failure{self.inject_replay_failure=false;return Err(SessionError::InvalidSession)}
  let pending=self.session.as_ref().ok_or(SessionError::InvalidSession)?;
  let mut replay=VecDeque::with_capacity(self.len());
  replay.extend(std::mem::take(&mut self.pending).into_iter().map(|item|(0,item)));
  replay.extend(std::mem::take(&mut self.popped).into_iter().map(|item|(1,item)));
  replay.extend(std::mem::take(&mut self.smart).into_iter().map(|item|(2,item)));
  let mut retained=VecDeque::with_capacity(replay.len());
  while let Some((queue,mut item))=replay.pop_front(){
   let mut child=match pending.child(){Ok(child)=>child,Err(error)=>{retained.push_back((queue,item));retained.append(&mut replay);self.restore_replay(retained);return Err(error)}};
   match execute(&mut item,&child){
    Ok(())=>match pending.merge_child(&mut child){Ok(())=>retained.push_back((queue,item)),Err(error)=>{retained.push_back((queue,item));retained.append(&mut replay);self.restore_replay(retained);return Err(error)}},
    Err(_message) if !strict=>{let _=child.revoke();},
    Err(_message)=>{let _=child.revoke();retained.push_back((queue,item));retained.append(&mut replay);self.restore_replay(retained);return Err(SessionError::InvalidSession)},
   }
  }
  self.restore_replay(retained);Ok(())
 }
 fn restore_replay(&mut self,mut replay:VecDeque<(u8,PendingTransaction<T>)>){
  while let Some((queue,item))=replay.pop_front(){match queue{0=>self.pending.push_back(item),1=>self.popped.push_back(item),_=>self.smart.push_back(item)}}self.recount()
 }
 fn manager(&self)->SessionManager{self.manager.clone()}
 pub fn shutdown(&mut self)->Result<(),SessionError>{if let Some(mut session)=self.session.take(){session.close()?}self.pending.clear();self.popped.clear();self.smart.clear();self.shielded=0;Ok(())}
 fn contains(&self,id:&Hash32)->bool{self.pending.iter().chain(&self.popped).chain(&self.smart).any(|item|&item.id==id)}
 fn expire(&mut self,now:i64){let timeout=self.limits.timeout_millis;self.pending.retain(|item|now-item.received_at<timeout);self.popped.retain(|item|now-item.received_at<timeout);self.smart.retain(|item|now-item.received_at<timeout);self.recount()}
 fn recount(&mut self){self.shielded=self.pending.iter().chain(&self.popped).chain(&self.smart).filter(|item|item.shielded).count()}
 #[must_use]pub fn pending_ids(&self)->Vec<Hash32>{self.pending.iter().chain(&self.smart).map(|x|x.id).collect()}
 /// Java `getTxFromPending` searches the ordinary pending queue followed by
 /// `rePushTransactions` (the smart queue). Popped transactions contribute to
 /// `getPendingSize`, but are deliberately not queryable/listed.
 #[must_use]pub fn pending_transaction(&self,id:&Hash32)->Option<&PendingTransaction<T>>{
  self.pending.iter().chain(&self.smart).find(|item|&item.id==id)
 }
 #[must_use]pub fn queue_ids(&self)->(Vec<Hash32>,Vec<Hash32>,Vec<Hash32>){(self.pending.iter().map(|x|x.id).collect(),self.popped.iter().map(|x|x.id).collect(),self.smart.iter().map(|x|x.id).collect())}
}
