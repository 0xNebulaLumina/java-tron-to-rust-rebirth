use core::fmt;

use crate::{dynamic, TypedStore};
use tron_storage::{NoWriteFaults, WriteFaultInjector};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicValue { Int(i32), Long(i64), Raw(Vec<u8>) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyEncoding { Int, Long, Raw }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicError {
    UnknownProperty(String), MissingProperty(String), InvalidLength { name: String, expected: usize, actual: usize },
    InvalidSlots(usize), InvalidMaintenanceInterval,
    MaintenanceTimestampOverflow { operation: &'static str },
    ArithmeticOverflow { name: String, current: i64, amount: i64 },
    InvalidAdaptiveRatio(i64), Storage(String),
}
impl fmt::Display for DynamicError { fn fmt(&self, f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"dynamic property error: {self:?}") } }
impl std::error::Error for DynamicError {}

#[derive(Clone)]
pub struct DynamicProperties { store: TypedStore }
impl DynamicProperties {
    pub fn encoding(name:&str)->Result<PropertyEncoding,DynamicError>{
        Self::key(name)?;
        Ok(match name {
            "TOTAL_SIGN_NUM"|"STATE_FLAG"|"BLOCK_FILLED_SLOTS_INDEX"|"MAX_FROZEN_TIME"|"MIN_FROZEN_TIME"|"MAX_FROZEN_SUPPLY_NUMBER"|"MAX_FROZEN_SUPPLY_TIME"|"MIN_FROZEN_SUPPLY_TIME"|"WITNESS_ALLOWANCE_FROZEN_TIME"|"VERSION_NUMBER"=>PropertyEncoding::Int,
            "LATEST_BLOCK_HEADER_HASH"|"AVAILABLE_CONTRACT_TYPE"|"ACTIVE_DEFAULT_OPERATIONS"|"BLOCK_FILLED_SLOTS"|"ENERGY_PRICE_HISTORY"|"BANDWIDTH_PRICE_HISTORY"|"MEMO_FEE_HISTORY"=>PropertyEncoding::Raw,
            _=>PropertyEncoding::Long,
        })
    }
    pub fn get(&self,name:&str)->Result<DynamicValue,DynamicError>{match Self::encoding(name)?{PropertyEncoding::Int=>self.get_int(name).map(DynamicValue::Int),PropertyEncoding::Long=>self.get_long(name).map(DynamicValue::Long),PropertyEncoding::Raw=>self.get_raw(name).map(DynamicValue::Raw)}}
    pub fn save(&self,name:&str,value:DynamicValue)->Result<(),DynamicError>{match (Self::encoding(name)?,value){(PropertyEncoding::Int,DynamicValue::Int(v))=>self.save_int(name,v),(PropertyEncoding::Long,DynamicValue::Long(v))=>self.save_long(name,v),(PropertyEncoding::Raw,DynamicValue::Raw(v))=>self.save_raw(name,&v),(expected,actual)=>Err(DynamicError::UnknownProperty(format!("encoding mismatch for {name}: expected {expected:?}, got {actual:?}")))}}
    pub fn initialize_migration_missing(&self,defaults:&[(String,DynamicValue)])->Result<usize,DynamicError>{let mut inserted=0;for (name,value) in defaults{let key=Self::key(name)?;if self.store.contains_key(key){continue}let bytes=match value{DynamicValue::Int(v)=>v.to_be_bytes().to_vec(),DynamicValue::Long(v)=>v.to_be_bytes().to_vec(),DynamicValue::Raw(v)=>v.clone()};if self.store.put_if_absent(key,&bytes).map_err(|e|DynamicError::Storage(e.to_string()))?{inserted+=1}}Ok(inserted)}

    #[must_use] pub fn new(store: TypedStore) -> Self { Self { store } }
    #[must_use] pub fn store(&self) -> &TypedStore { &self.store }
    pub fn key(name: &str) -> Result<&'static [u8], DynamicError> { dynamic::key(name).ok_or_else(|| DynamicError::UnknownProperty(name.into())) }
    pub fn get_raw(&self, name: &str) -> Result<Vec<u8>, DynamicError> { self.store.get(Self::key(name)?).ok_or_else(|| DynamicError::MissingProperty(name.into())) }
    pub fn get_optional_raw(&self, name: &str) -> Result<Option<Vec<u8>>, DynamicError> { Ok(self.store.get(Self::key(name)?)) }
    pub fn save_raw(&self, name: &str, value: &[u8]) -> Result<(), DynamicError> { self.store.put(Self::key(name)?, value).map_err(|e|DynamicError::Storage(e.to_string())) }
    pub fn get_int(&self, name: &str) -> Result<i32, DynamicError> { let v=self.get_raw(name)?; let n=v.len(); let a:[u8;4]=v.try_into().map_err(|_|DynamicError::InvalidLength{name:name.into(),expected:4,actual:n})?; Ok(i32::from_be_bytes(a)) }
    pub fn save_int(&self, name:&str, value:i32)->Result<(),DynamicError>{self.save_raw(name,&value.to_be_bytes())}
    pub fn get_long(&self, name: &str) -> Result<i64, DynamicError> { let v=self.get_raw(name)?; let n=v.len(); let a:[u8;8]=v.try_into().map_err(|_|DynamicError::InvalidLength{name:name.into(),expected:8,actual:n})?; Ok(i64::from_be_bytes(a)) }
    pub fn save_long(&self,name:&str,value:i64)->Result<(),DynamicError>{self.save_raw(name,&value.to_be_bytes())}
    pub fn is_enabled(&self,name:&str)->Result<bool,DynamicError>{Ok(self.get_long(name)?==1)}
    pub fn is_unfreeze_delay_enabled(&self)->Result<bool,DynamicError>{Ok(self.get_long("UNFREEZE_DELAY_DAYS")?>0)}
    pub fn get_allow_same_token_name(&self)->Result<i64,DynamicError>{self.get_long("ALLOW_SAME_TOKEN_NAME")}
    pub fn save_allow_same_token_name(&self,value:i64)->Result<(),DynamicError>{self.save_long("ALLOW_SAME_TOKEN_NAME",value)}

    fn add_long_checked(&self,name:&str,amount:i64,ignore_zero:bool,clamp_for_new_reward:bool)->Result<i64,DynamicError>{
        if ignore_zero && amount==0{return self.get_long(name)}
        let current=self.get_long(name)?;
        let mut next=current.checked_add(amount).ok_or_else(||DynamicError::ArithmeticOverflow{name:name.into(),current,amount})?;
        if clamp_for_new_reward && self.is_enabled("ALLOW_NEW_REWARD")? && next<0 {next=0;}
        self.save_long(name,next)?; Ok(next)
    }
    pub fn add_total_net_weight(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_NET_WEIGHT",amount,true,true)}
    pub fn add_total_energy_weight(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_ENERGY_WEIGHT",amount,true,true)}
    pub fn add_total_tron_power_weight(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_TRON_POWER_WEIGHT",amount,true,true)}
    pub fn add_transaction_fee_pool(&self,amount:i64)->Result<i64,DynamicError>{if amount<=0{return self.get_long("TRANSACTION_FEE_POOL")}self.add_long_checked("TRANSACTION_FEE_POOL",amount,false,false)}
    pub fn add_burned_trx(&self,amount:i64)->Result<i64,DynamicError>{if amount<=0{return self.get_long("BURN_TRX_AMOUNT")}self.add_long_checked("BURN_TRX_AMOUNT",amount,false,false)}
    pub fn add_total_transaction_cost(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_TRANSACTION_COST",amount,false,false)}
    pub fn add_total_create_account_cost(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_CREATE_ACCOUNT_COST",amount,false,false)}
    pub fn add_total_create_witness_cost(&self,amount:i64)->Result<i64,DynamicError>{self.add_long_checked("TOTAL_CREATE_WITNESS_COST",amount,false,false)}

    pub fn save_total_energy_limit(&self,total:i64)->Result<(),DynamicError>{
        let ratio=self.get_long("ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO")?;
        if ratio<=0{return Err(DynamicError::InvalidAdaptiveRatio(ratio));}
        let target=total/ratio;
        let mut batch=self.store.batch();
        batch.put(self.store.name(),Self::key("TOTAL_ENERGY_LIMIT")?,&total.to_be_bytes())
            .put(self.store.name(),Self::key("TOTAL_ENERGY_TARGET_LIMIT")?,&target.to_be_bytes());
        batch.commit().map_err(|e|DynamicError::Storage(e.to_string()))
    }
    pub fn save_total_energy_limit2(&self,total:i64)->Result<(),DynamicError>{
        let ratio=self.get_long("ADAPTIVE_RESOURCE_LIMIT_TARGET_RATIO")?;
        if ratio<=0{return Err(DynamicError::InvalidAdaptiveRatio(ratio));}
        let adaptive=self.is_enabled("ALLOW_ADAPTIVE_ENERGY")?;
        let target=total/ratio;
        let mut batch=self.store.batch();
        batch.put(self.store.name(),Self::key("TOTAL_ENERGY_LIMIT")?,&total.to_be_bytes())
            .put(self.store.name(),Self::key("TOTAL_ENERGY_TARGET_LIMIT")?,&target.to_be_bytes());
        if !adaptive {batch.put(self.store.name(),Self::key("TOTAL_ENERGY_CURRENT_LIMIT")?,&total.to_be_bytes());}
        batch.commit().map_err(|e|DynamicError::Storage(e.to_string()))
    }

    pub fn apply_block(&self,filled:bool)->Result<(),DynamicError>{
        self.apply_block_with_faults(filled, &NoWriteFaults)
    }
    pub fn apply_block_with_faults(&self,filled:bool,faults:&dyn WriteFaultInjector)->Result<(),DynamicError>{
        let mut slots=self.get_raw("BLOCK_FILLED_SLOTS")?;
        if slots.len()!=128{return Err(DynamicError::InvalidSlots(slots.len()))}
        let index=self.get_int("BLOCK_FILLED_SLOTS_INDEX")?.rem_euclid(128) as usize;
        slots[index]=u8::from(filled);
        let next_index=((index+1)%128) as i32;
        let mut batch=self.store.batch();
        batch.put(self.store.name(),Self::key("BLOCK_FILLED_SLOTS")?,&slots)
            .put(self.store.name(),Self::key("BLOCK_FILLED_SLOTS_INDEX")?,&next_index.to_be_bytes());
        batch.commit_with_faults(faults).map_err(|e|DynamicError::Storage(e.to_string()))
    }
    pub fn calculate_filled_slots_count(&self)->Result<i32,DynamicError>{let slots=self.get_raw("BLOCK_FILLED_SLOTS")?;if slots.len()!=128{return Err(DynamicError::InvalidSlots(slots.len()))}Ok((100_i64*slots.iter().map(|&v|i64::from(v)).sum::<i64>()/128) as i32)}
    pub fn update_next_maintenance_time(&self,block_time:i64)->Result<i64,DynamicError>{
        let current=self.get_long("NEXT_MAINTENANCE_TIME")?;
        let interval=self.get_long("MAINTENANCE_TIME_INTERVAL")?;
        if interval<=0{return Err(DynamicError::InvalidMaintenanceInterval)}
        let overflow=|operation|DynamicError::MaintenanceTimestampOverflow{operation};
        let difference=i64::try_from(i128::from(block_time).checked_sub(i128::from(current)).ok_or_else(||overflow("subtract"))?).map_err(|_|overflow("subtract"))?;
        let quotient=i64::try_from(i128::from(difference).checked_div(i128::from(interval)).ok_or_else(||overflow("divide"))?).map_err(|_|overflow("divide"))?;
        let periods=i64::try_from(i128::from(quotient).checked_add(1).ok_or_else(||overflow("round"))?).map_err(|_|overflow("round"))?;
        let offset=i64::try_from(i128::from(periods).checked_mul(i128::from(interval)).ok_or_else(||overflow("multiply"))?).map_err(|_|overflow("multiply"))?;
        let next=i64::try_from(i128::from(current).checked_add(i128::from(offset)).ok_or_else(||overflow("add"))?).map_err(|_|overflow("add"))?;
        self.save_long("NEXT_MAINTENANCE_TIME",next)?;
        Ok(next)
    }

    pub fn proposal_expire_time(&self,minimum:i64,maximum:i64)->Result<Option<i64>,DynamicError>{let value=self.get_long("PROPOSAL_EXPIRE_TIME")?;Ok((value>minimum&&value<maximum).then_some(value))}
    pub fn supports_max_delegate_lock_period(&self,base_period:i64)->Result<bool,DynamicError>{Ok(self.get_long("MAX_DELEGATE_LOCK_PERIOD")?>base_period&&self.is_unfreeze_delay_enabled()?)}
    pub fn fork_stats(&self,version:i32)->Option<Vec<u8>>{self.store.get(format!("FORK_VERSION_{version}").as_bytes())}
    pub fn save_fork_stats(&self,version:i32,stats:&[u8])->Result<(),DynamicError>{self.store.put(format!("FORK_VERSION_{version}").as_bytes(),stats).map_err(|e|DynamicError::Storage(e.to_string()))}
    pub fn forked(&self,version:i32)->bool{self.store.get(format!("FORK_CONTROLLER{version}").as_bytes()).as_deref()==Some(b"true")}
    pub fn save_forked(&self,version:i32,value:bool)->Result<(),DynamicError>{self.store.put(format!("FORK_CONTROLLER{version}").as_bytes(),if value{b"true"}else{b"false"}).map_err(|e|DynamicError::Storage(e.to_string()))}
}
