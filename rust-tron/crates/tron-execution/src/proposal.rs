use tron_protocol::{google::protobuf::Any, protocol::{proposal::State, transaction::result::Code, Proposal, ProposalApproveContract, ProposalCreateContract, ProposalDeleteContract}};
use tron_state::StoreKind;
use crate::{context::{checked_add, decode_typed_any, valid_address}, Actuator, ActuatorError, ActuatorResult, ExecutionContext, ValidationContext};

const CREATE: &str = "protocol.ProposalCreateContract";
const APPROVE: &str = "protocol.ProposalApproveContract";
const DELETE: &str = "protocol.ProposalDeleteContract";
const LONG_VALUE: i64 = 100_000_000_000_000_000;
const VALID_IDS: &[i64] = &[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,29,30,32,33,35,39,40,41,44,45,46,47,48,49,51,52,53,59,60,61,62,63,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,81,82,83,87,88,89,92,94,95,96,97,98];

fn key(id: i64) -> [u8; 8] { id.to_be_bytes() }
fn hex_bytes(value:&[u8])->String{value.iter().map(|byte|format!("{byte:02x}")).collect()}
fn require_account(context: &ExecutionContext<'_>, address: &[u8]) -> Result<(), ActuatorError> { if context.get(StoreKind::Account,address)?.is_none(){Err(ActuatorError::validation(format!("Account[{}] not exists",hex_bytes(address))))}else{Ok(())} }
fn proposal(context:&ExecutionContext<'_>,id:i64)->Result<Proposal,ActuatorError>{context.decode(StoreKind::Proposal,&key(id),"Proposal does not exist").map_err(|error|if error.message=="Proposal does not exist"{ActuatorError::validation(format!("Proposal[{id}] not exists"))}else{error})}
fn require_witness(context: &ExecutionContext<'_>, address: &[u8]) -> Result<(), ActuatorError> { if context.get(StoreKind::Witness,address)?.is_none(){Err(ActuatorError::validation(format!("Witness[{}] not exists",hex_bytes(address))))}else{Ok(())} }
fn one(value:i64,name:&str)->Result<(),ActuatorError>{if value==1{Ok(())}else{Err(ActuatorError::validation(format!("This value[{name}] is only allowed to be 1")))}}
fn boolean(value:i64,name:&str)->Result<(),ActuatorError>{if value==0||value==1{Ok(())}else{Err(ActuatorError::validation(format!("This value[{name}] is only allowed to be 1 or 0")))}}
fn range(value:i64,min:i64,max:i64)->Result<(),ActuatorError>{if (min..=max).contains(&value){Ok(())}else{Err(ActuatorError::validation(format!("Bad chain parameter value, valid range is [{min},{max}]")))}}
fn enabled(context:&ExecutionContext<'_>,name:&str)->Result<bool,ActuatorError>{Ok(context.dynamic_long(name).unwrap_or(0)!=0)}

/// Java ProposalUtil-compatible current-chain validation. Unsupported numeric gaps are rejected.
pub fn validate_proposal_parameter(context:&ExecutionContext<'_>,code:i64,value:i64)->Result<(),ActuatorError>{
 if !VALID_IDS.contains(&code){return Err(ActuatorError::validation("Bad chain parameter id"));}
 match code {
  0=>range(value,81_000,86_400_000),
  1..=8|11=>range(value,0,LONG_VALUE), 12=>Ok(()),
  9=>one(value,"ALLOW_CREATION_OF_CONTRACTS"), 10=>{if context.dynamic_long("REMOVE_THE_POWER_OF_THE_GR").unwrap_or(0)==-1{return Err(ActuatorError::validation("This proposal has been executed before and is only allowed to be executed once"));}one(value,"REMOVE_THE_POWER_OF_THE_GR")},
  13=>range(value,10,if enabled(context,"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX")?{400}else{100}),
  14=>one(value,"ALLOW_UPDATE_ACCOUNT_NAME"),15=>one(value,"ALLOW_SAME_TOKEN_NAME"),16=>one(value,"ALLOW_DELEGATE_RESOURCE"),
  17|19=>range(value,0,LONG_VALUE),
  18=>{one(value,"ALLOW_TVM_TRANSFER_TRC10")?;if !enabled(context,"ALLOW_SAME_TOKEN_NAME")?{return Err(ActuatorError::validation("[ALLOW_SAME_TOKEN_NAME] proposal must be approved before [ALLOW_TVM_TRANSFER_TRC10] can be proposed"));}Ok(())},
  20=>one(value,"ALLOW_MULTI_SIGN"),21=>one(value,"ALLOW_ADAPTIVE_ENERGY"),22|23=>range(value,0,100_000_000_000),24|25|30|39|48|49|72|98=>boolean(value,"proposal"),
  26=>{one(value,"ALLOW_TVM_CONSTANTINOPLE")?;if !enabled(context,"ALLOW_TVM_TRANSFER_TRC10")?{return Err(ActuatorError::validation("[ALLOW_TVM_TRANSFER_TRC10] proposal must be approved before [ALLOW_TVM_CONSTANTINOPLE] can be proposed"));}Ok(())},
  29=>range(value,1,10_000),31=>range(value,0,LONG_VALUE),32=>{one(value,"ALLOW_TVM_SOLIDITY_059")?;if !enabled(context,"ALLOW_CREATION_OF_CONTRACTS")?{return Err(ActuatorError::validation("[ALLOW_CREATION_OF_CONTRACTS] proposal must be approved before [ALLOW_TVM_SOLIDITY_059] can be proposed"));}Ok(())},33=>range(value,1,1_000),
  35=>{one(value,"FORBID_TRANSFER_TO_CONTRACT")?;if !enabled(context,"ALLOW_CREATION_OF_CONTRACTS")?{return Err(ActuatorError::validation("[ALLOW_CREATION_OF_CONTRACTS] proposal must be approved before [FORBID_TRANSFER_TO_CONTRACT] can be proposed"));}Ok(())},
  40=>one(value,"ALLOW_PBFT"),41=>one(value,"ALLOW_TVM_ISTANBUL"),44=>one(value,"ALLOW_MARKET_TRANSACTION"),45|46=>range(value,0,10_000_000_000),47=>range(value,0,if enabled(context,"ALLOW_TVM_LONDON")?{LONG_VALUE}else{10_000_000_000}),
  51=>one(value,"ALLOW_NEW_RESOURCE_MODEL"),52=>{one(value,"ALLOW_TVM_FREEZE")?;for dependency in ["ALLOW_DELEGATE_RESOURCE","ALLOW_MULTI_SIGN","ALLOW_TVM_CONSTANTINOPLE","ALLOW_TVM_SOLIDITY_059"]{if !enabled(context,dependency)?{return Err(ActuatorError::validation(format!("[{dependency}] proposal must be approved before [ALLOW_TVM_FREEZE] can be proposed")));}}Ok(())},
  53=>one(value,"ALLOW_ACCOUNT_ASSET_OPTIMIZATION"),59=>{one(value,"ALLOW_TVM_VOTE")?;if !enabled(context,"ALLOW_CHANGE_DELEGATION")?{return Err(ActuatorError::validation("[ALLOW_CHANGE_DELEGATION] proposal must be approved before [ALLOW_TVM_VOTE] can be proposed"));}Ok(())},
  60=>one(value,"ALLOW_TVM_COMPATIBLE_EVM"),61=>range(value,0,100_000),62=>range(value,0,1_000_000_000_000),63=>one(value,"ALLOW_TVM_LONDON"),65=>one(value,"ALLOW_HIGHER_LIMIT_FOR_MAX_CPU_TIME_OF_ONE_TX"),66=>one(value,"ALLOW_ASSET_OPTIMIZATION"),67=>one(value,"ALLOW_NEW_REWARD"),68=>range(value,0,1_000_000_000),69=>one(value,"ALLOW_DELEGATE_OPTIMIZATION"),70=>range(value,1,365),71=>one(value,"ALLOW_OPTIMIZED_RETURN_VALUE_OF_CHAIN_ID"),
  73=>range(value,0,LONG_VALUE),74=>range(value,0,10_000),75=>range(value,0,100_000),76=>one(value,"ALLOW_TVM_SHANGHAI"),77=>{one(value,"ALLOW_CANCEL_ALL_UNFREEZE_V2")?;if context.dynamic_long("UNFREEZE_DELAY_DAYS").unwrap_or(0)==0{return Err(ActuatorError::validation("[UNFREEZE_DELAY_DAYS] proposal must be approved before [ALLOW_CANCEL_ALL_UNFREEZE_V2] can be proposed"));}Ok(())},
  78=>{let Some(current)=context.get(StoreKind::DynamicProperties,tron_state::dynamic::key("MAX_DELEGATE_LOCK_PERIOD").unwrap())?.and_then(|bytes|bytes.try_into().ok().map(i64::from_be_bytes))else{return Err(ActuatorError::validation("Bad chain parameter id [MAX_DELEGATE_LOCK_PERIOD]"));};if value<=current||value>10_512_000{return Err(ActuatorError::validation(format!("This value[MAX_DELEGATE_LOCK_PERIOD] is only allowed to be greater than {current} and less than or equal to 10512000 !")));}if context.dynamic_long("UNFREEZE_DELAY_DAYS").unwrap_or(0)==0{return Err(ActuatorError::validation("[UNFREEZE_DELAY_DAYS] proposal must be approved before [MAX_DELEGATE_LOCK_PERIOD] can be proposed"));}Ok(())},
  79=>one(value,"ALLOW_OLD_REWARD_OPT"),81=>one(value,"ALLOW_ENERGY_ADJUSTMENT"),82=>if (500..=10_000).contains(&value){Ok(())}else{Err(ActuatorError::validation("This value[MAX_CREATE_ACCOUNT_TX_SIZE] is only allowed to be greater than or equal to 500 and less than or equal to 10000!"))},83=>one(value,"ALLOW_TVM_CANCUN"),87=>one(value,"ALLOW_STRICT_MATH"),88=>one(value,"CONSENSUS_LOGIC_OPTIMIZATION"),89=>one(value,"ALLOW_TVM_BLOB"),
  92=>if value>0&&value<31_536_003_000{Ok(())}else{Err(ActuatorError::validation("Invalid PROPOSAL_EXPIRE_TIME"))},94=>one(value,"ALLOW_TVM_SELFDESTRUCT_RESTRICTION"),95=>{if !enabled(context,"ALLOW_TVM_SHANGHAI")?{return Err(ActuatorError::validation("[ALLOW_TVM_PRAGUE] requires [ALLOW_TVM_SHANGHAI] to be enacted first"));}one(value,"ALLOW_TVM_PRAGUE")},96=>one(value,"ALLOW_TVM_OSAKA"),97=>one(value,"ALLOW_HARDEN_RESOURCE_CALCULATION"),_=>Ok(())
 }
}

macro_rules! actuator {
    ($name:ident, $contract:ty, $url:expr) => {
        pub struct $name {
            any: Any,
            contract: $contract,
        }

        impl $name {
            pub fn new(any: Any) -> Result<Self, ActuatorError> {
                let contract = decode_typed_any(&any, $url)?;
                Ok(Self { any, contract })
            }

            pub fn raw_any(&self) -> &Any {
                &self.any
            }
        }
    };
}

actuator!(ProposalCreateActuator, ProposalCreateContract, CREATE);
impl Actuator for ProposalCreateActuator{
 fn owner_address(&self)->Result<&[u8],ActuatorError>{Ok(&self.contract.owner_address)}
 fn validate(&self,c:&ValidationContext<'_>)->Result<(),ActuatorError>{if !valid_address(&self.contract.owner_address){return Err(ActuatorError::validation("Invalid address"));}require_account(c,&self.contract.owner_address)?;require_witness(c,&self.contract.owner_address)?;if self.contract.parameters.is_empty(){return Err(ActuatorError::validation("This proposal has no parameter."));}for (&id,&value) in &self.contract.parameters{validate_proposal_parameter(c,id,value)?;}Ok(())}
 fn execute_in(&self,c:&mut ExecutionContext<'_>,r:&mut ActuatorResult)->Result<(),ActuatorError>{let id=checked_add(c.dynamic_long("LATEST_PROPOSAL_NUM")?,1)?;let now=c.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?;let next=c.dynamic_long("NEXT_MAINTENANCE_TIME")?;let interval=c.dynamic_long("MAINTENANCE_TIME_INTERVAL")?;let expire=c.dynamic_long("PROPOSAL_EXPIRE_TIME").unwrap_or(259_200_000);let round=(checked_add(now,expire)?-next)/interval;let proposal=Proposal{proposal_id:id,proposer_address:self.contract.owner_address.clone(),parameters:self.contract.parameters.clone(),expiration_time:next+(round+1)*interval,create_time:now,approvals:vec![],state:State::Pending as i32};c.put_message(StoreKind::Proposal,&key(id),&proposal)?;c.put_dynamic_long("LATEST_PROPOSAL_NUM",id)?;r.code=Code::Sucess;Ok(())}}


actuator!(ProposalApproveActuator, ProposalApproveContract, APPROVE);
impl Actuator for ProposalApproveActuator{fn owner_address(&self)->Result<&[u8],ActuatorError>{Ok(&self.contract.owner_address)}fn validate(&self,c:&ValidationContext<'_>)->Result<(),ActuatorError>{if !valid_address(&self.contract.owner_address){return Err(ActuatorError::validation("Invalid address"));}require_account(c,&self.contract.owner_address)?;require_witness(c,&self.contract.owner_address)?;let p=proposal(c,self.contract.proposal_id)?;if c.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?>=p.expiration_time{return Err(ActuatorError::validation(format!("Proposal[{}] expired",self.contract.proposal_id)));}if p.state==State::Canceled as i32{return Err(ActuatorError::validation(format!("Proposal[{}] canceled",self.contract.proposal_id)));}let has=p.approvals.contains(&self.contract.owner_address);if self.contract.is_add_approval&&has{return Err(ActuatorError::validation(format!("Witness[{}]has approved proposal[{}] before",hex_bytes(&self.contract.owner_address),self.contract.proposal_id)));}if !self.contract.is_add_approval&&!has{return Err(ActuatorError::validation(format!("Witness[{}]has not approved proposal[{}] before",hex_bytes(&self.contract.owner_address),self.contract.proposal_id)));}Ok(())}fn execute_in(&self,c:&mut ExecutionContext<'_>,r:&mut ActuatorResult)->Result<(),ActuatorError>{let mut p=proposal(c,self.contract.proposal_id)?;if self.contract.is_add_approval{p.approvals.push(self.contract.owner_address.clone())}else{p.approvals.retain(|a|a!=&self.contract.owner_address)}c.put_message(StoreKind::Proposal,&key(p.proposal_id),&p)?;r.code=Code::Sucess;Ok(())}}

actuator!(ProposalDeleteActuator, ProposalDeleteContract, DELETE);
impl Actuator for ProposalDeleteActuator{fn owner_address(&self)->Result<&[u8],ActuatorError>{Ok(&self.contract.owner_address)}fn validate(&self,c:&ValidationContext<'_>)->Result<(),ActuatorError>{if !valid_address(&self.contract.owner_address){return Err(ActuatorError::validation("Invalid address"));}require_account(c,&self.contract.owner_address)?;let p=proposal(c,self.contract.proposal_id)?;if p.proposer_address!=self.contract.owner_address{return Err(ActuatorError::validation(format!("Proposal[{}] is not proposed by {}",self.contract.proposal_id,hex_bytes(&self.contract.owner_address))));}if c.dynamic_long("LATEST_BLOCK_HEADER_TIMESTAMP")?>=p.expiration_time{return Err(ActuatorError::validation(format!("Proposal[{}] expired",self.contract.proposal_id)));}if p.state==State::Canceled as i32{return Err(ActuatorError::validation(format!("Proposal[{}] canceled",self.contract.proposal_id)));}Ok(())}fn execute_in(&self,c:&mut ExecutionContext<'_>,r:&mut ActuatorResult)->Result<(),ActuatorError>{let mut p=proposal(c,self.contract.proposal_id)?;p.state=State::Canceled as i32;c.put_message(StoreKind::Proposal,&key(p.proposal_id),&p)?;r.code=Code::Sucess;Ok(())}}
