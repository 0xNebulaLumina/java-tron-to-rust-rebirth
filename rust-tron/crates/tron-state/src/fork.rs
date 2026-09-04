use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::dynamic_properties::{DynamicError, DynamicProperties};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkVersion { pub version: i32, pub hard_fork_time: i64, pub hard_fork_rate: i32 }

pub trait ForkSchedule { fn versions(&self) -> &[ForkVersion]; }
pub trait ForkClock { fn latest_block_number(&self) -> i64; fn latest_block_timestamp(&self) -> i64; }
pub trait ForkMath { fn activation_time(&self, hard_fork_time:i64, maintenance_interval:i64)->Result<i64,ForkError>; fn required_witnesses(&self,count:usize,rate:i32)->usize; }

#[derive(Clone,Copy,Debug,Default)] pub struct JavaForkMath;
impl ForkMath for JavaForkMath {
    fn activation_time(&self,time:i64,interval:i64)->Result<i64,ForkError> {
        if interval<=0{return Err(ForkError::InvalidInterval)}
        let overflow=|operation|ForkError::TimestampOverflow{operation};
        let numerator=i64::try_from(i128::from(time).checked_sub(1).ok_or_else(||overflow("subtract"))?).map_err(|_|overflow("subtract"))?;
        let divisor=i128::from(interval);
        let quotient=i64::try_from(i128::from(numerator).checked_div(divisor).ok_or_else(||overflow("divide"))?).map_err(|_|overflow("divide"))?;
        let remainder=i128::from(numerator).checked_rem(divisor).ok_or_else(||overflow("remainder"))?;
        let rounded=if remainder!=0&&numerator>0{i64::try_from(i128::from(quotient).checked_add(1).ok_or_else(||overflow("round"))?).map_err(|_|overflow("round"))?}else{quotient};
        i64::try_from(i128::from(rounded).checked_mul(divisor).ok_or_else(||overflow("multiply"))?).map_err(|_|overflow("multiply"))
    }
    fn required_witnesses(&self,count:usize,rate:i32)->usize { ((count as u128).saturating_mul(rate.max(0) as u128).saturating_add(99)/100) as usize }
}

#[derive(Clone,Debug,Eq,PartialEq)]
pub enum ForkError {
    Dynamic(DynamicError), UnknownVersion(i32), InvalidInterval,
    TimestampOverflow { operation: &'static str }, InvalidWitnessMembership,
    InvalidForkStatsValue { version: i32, index: usize, value: u8 },
    InvalidWitnessRoster { version: i32 },
}
impl From<DynamicError> for ForkError { fn from(value:DynamicError)->Self{Self::Dynamic(value)} }
impl fmt::Display for ForkError { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"fork controller error: {self:?}")} }
impl std::error::Error for ForkError {}

pub struct ForkController<'a,S,C,M>{properties:DynamicProperties,schedule:&'a S,clock:&'a C,math:&'a M,energy_limit_height:i64}
impl<'a,S:ForkSchedule,C:ForkClock,M:ForkMath> ForkController<'a,S,C,M>{
    #[must_use] pub fn new(properties:DynamicProperties,schedule:&'a S,clock:&'a C,math:&'a M,energy_limit_height:i64)->Self{Self{properties,schedule,clock,math,energy_limit_height}}
    pub fn init(&self,active:&[Vec<u8>])->Result<i32,ForkError>{self.validate_active(active)?;let mut latest=self.latest_version()?;if latest==0{for item in self.schedule.versions(){if self.pass(item.version,active)?{latest=latest.max(item.version)}}if latest!=0{self.properties.save_int("VERSION_NUMBER",latest)?;}}Ok(latest)}
    pub fn pass(&self,version:i32,active:&[Vec<u8>])->Result<bool,ForkError>{
        self.validate_active(active)?;
        if version==5{return Ok(self.clock.latest_block_number()>=self.energy_limit_height)}
        let item=self.schedule.versions().iter().find(|v|v.version==version);
        let Some(stats)=self.normalized_stats(version,active)? else{return Ok(false)};
        if version<5{return Ok(stats.iter().all(|&v|v==1))}
        let item=item.ok_or(ForkError::UnknownVersion(version))?;
        let interval=self.properties.get_long("MAINTENANCE_TIME_INTERVAL")?;if interval<=0{return Err(ForkError::InvalidInterval)}
        if self.clock.latest_block_timestamp()<self.math.activation_time(item.hard_fork_time,interval)?{return Ok(false)}
        let ones=stats.iter().filter(|&&v|v==1).count();Ok(ones>=self.math.required_witnesses(active.len(),item.hard_fork_rate))
    }
    pub fn update(&self,active:&[Vec<u8>],witness:&[u8],candidate:i32)->Result<(),ForkError>{
        self.validate_active(active)?;
        let Some(slot)=active.iter().position(|v|v.as_slice()==witness) else{return Ok(())};
        if candidate<5{return Ok(())}let latest=self.latest_version()?;if latest>=candidate{return Ok(())}
        let candidate_passes=self.pass(candidate,active)?;
        let mut writes:BTreeMap<i32,Vec<u8>>=BTreeMap::new();
        for item in self.schedule.versions().iter().filter(|v|v.version>candidate){
            if !self.pass(item.version,active)?{if let Some(mut stats)=self.normalized_stats(item.version,active)?{stats[slot]=0;writes.insert(item.version,stats);}}
        }
        if candidate_passes {
            for item in self.schedule.versions().iter().filter(|v|v.version<candidate){if !self.pass(item.version,active)?{writes.insert(item.version,vec![1;active.len()]);}}
        } else {
            let mut stats=self.normalized_stats(candidate,active)?.unwrap_or_else(||vec![0;active.len()]);stats[slot]=1;writes.insert(candidate,stats);
        }
        self.commit(active,&writes,candidate_passes.then_some(candidate))
    }
    pub fn reset(&self,active:&[Vec<u8>])->Result<(),ForkError>{
        self.validate_active(active)?;let mut writes=BTreeMap::new();
        for item in self.schedule.versions(){if self.properties.fork_stats(item.version).is_some()&&!self.pass(item.version,active)?{writes.insert(item.version,vec![0;active.len()]);}}
        self.commit(active,&writes,None)
    }
    fn validate_active(&self,active:&[Vec<u8>])->Result<(),ForkError>{let mut seen=BTreeSet::new();if active.is_empty()||active.iter().any(|w|w.is_empty()||!seen.insert(w.as_slice())){Err(ForkError::InvalidWitnessMembership)}else{Ok(())}}
    fn normalized_stats(&self,version:i32,active:&[Vec<u8>])->Result<Option<Vec<u8>>,ForkError>{
        let Some(stats)=self.properties.fork_stats(version) else{return Ok(None)};
        for (index,&value) in stats.iter().enumerate(){if value>1{return Err(ForkError::InvalidForkStatsValue{version,index,value})}}
        let roster_key=Self::roster_key(version);
        let Some(encoded_roster)=self.properties.store().get(&roster_key) else{return Ok(Some(if stats.len()==active.len(){stats}else{vec![0;active.len()]}))};
        let roster=Self::decode_roster(version,&encoded_roster)?;
        if roster.len()!=stats.len(){return Err(ForkError::InvalidWitnessRoster{version})}
        let previous:BTreeMap<&[u8],u8>=roster.iter().map(Vec::as_slice).zip(stats).collect();
        Ok(Some(active.iter().map(|w|previous.get(w.as_slice()).copied().unwrap_or(0)).collect()))
    }
    fn commit(&self,active:&[Vec<u8>],writes:&BTreeMap<i32,Vec<u8>>,version:Option<i32>)->Result<(),ForkError>{
        if writes.is_empty()&&version.is_none(){return Ok(())}
        let roster=Self::encode_roster(active);let mut batch=self.properties.store().batch();let name=self.properties.store().name();
        for (&fork,stats) in writes{batch.put(name,format!("FORK_VERSION_{fork}").as_bytes(),stats).put(name,&Self::roster_key(fork),&roster);}
        if let Some(version)=version{batch.put(name,DynamicProperties::key("VERSION_NUMBER")?,&version.to_be_bytes());}
        batch.commit().map_err(|e|ForkError::Dynamic(DynamicError::Storage(e.to_string())))
    }
    fn roster_key(version:i32)->Vec<u8>{format!("FORK_WITNESSES_{version}").into_bytes()}
    fn encode_roster(active:&[Vec<u8>])->Vec<u8>{let mut out=Vec::new();for witness in active{out.extend_from_slice(&(witness.len() as u32).to_be_bytes());out.extend_from_slice(witness);}out}
    fn decode_roster(version:i32,bytes:&[u8])->Result<Vec<Vec<u8>>,ForkError>{
        let mut offset=0;let mut roster=Vec::new();let mut seen=BTreeSet::new();
        while offset<bytes.len(){if bytes.len()-offset<4{return Err(ForkError::InvalidWitnessRoster{version})}let size=u32::from_be_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;offset+=4;if size==0||size>bytes.len()-offset{return Err(ForkError::InvalidWitnessRoster{version})}let witness=bytes[offset..offset+size].to_vec();offset+=size;if !seen.insert(witness.clone()){return Err(ForkError::InvalidWitnessRoster{version})}roster.push(witness);}
        Ok(roster)
    }
    fn latest_version(&self)->Result<i32,ForkError>{match self.properties.get_optional_raw("VERSION_NUMBER")?{None=>Ok(0),Some(bytes)=>{let actual=bytes.len();let encoded:[u8;4]=bytes.try_into().map_err(|_|DynamicError::InvalidLength{name:"VERSION_NUMBER".into(),expected:4,actual})?;Ok(i32::from_be_bytes(encoded))}}}
}
