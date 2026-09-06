use prost::Message;
use tron_crypto::{selected_digest, CryptoEngine};
use tron_primitives::Hash32;
use tron_protocol::protocol::Transaction;

#[derive(Clone, Debug)]
pub struct RawWireTransaction {
    transaction: Transaction,
    full_bytes: Vec<u8>,
    raw_data_bytes: Vec<u8>,
    signature_verification_cached: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionWireError {
    MalformedProtobuf,
    MissingRawData,
    MultipleRawData,
}
impl core::fmt::Display for TransactionWireError { fn fmt(&self, f:&mut core::fmt::Formatter<'_>)->core::fmt::Result { f.write_str(match self { Self::MalformedProtobuf=>"Transaction proto data parse exception", Self::MissingRawData=>"transaction raw_data is missing", Self::MultipleRawData=>"transaction contains multiple raw_data fields" }) } }
impl std::error::Error for TransactionWireError {}

impl RawWireTransaction {
    pub fn decode(bytes: impl Into<Vec<u8>>) -> Result<Self, TransactionWireError> {
        let full_bytes=bytes.into();
        let transaction=Transaction::decode(full_bytes.as_slice()).map_err(|_|TransactionWireError::MalformedProtobuf)?;
        let mut raw=None;
        scan_fields(&full_bytes, |number,wire,payload,_| {
            if number==1 && wire==2 { if raw.is_some(){return Err(TransactionWireError::MultipleRawData)} raw=Some(payload.to_vec()); }
            Ok(())
        })?;
        Ok(Self{transaction,full_bytes,raw_data_bytes:raw.ok_or(TransactionWireError::MissingRawData)?,signature_verification_cached:false})
    }
    #[must_use] pub fn message(&self)->&Transaction { &self.transaction }
    #[must_use] pub fn full_bytes(&self)->&[u8] { &self.full_bytes }
    #[must_use] pub fn raw_data_bytes(&self)->&[u8] { &self.raw_data_bytes }
    #[must_use] pub fn transaction_id(&self,engine:CryptoEngine)->Hash32 { selected_digest(engine,&self.raw_data_bytes).into() }
    #[must_use] pub fn full_hash(&self,engine:CryptoEngine)->Hash32 { selected_digest(engine,&self.full_bytes).into() }
    #[must_use] pub const fn signature_verification_cached(&self)->bool { self.signature_verification_cached }
    pub fn clear_signature_verification_cache(&mut self) { self.signature_verification_cached=false; }
    pub fn set_signature_verification_cached(&mut self, verified: bool) { self.signature_verification_cached=verified; }
    #[must_use] pub fn has_top_level_unknown_fields(&self)->bool { let mut unknown=false; let _=scan_fields(&self.full_bytes,|n,_,_,_|{unknown|=!matches!(n,1|2|5);Ok(())}); unknown }
    pub fn sanitize_top_level_unknown_fields(&mut self)->Result<bool,TransactionWireError>{
        if !self.has_top_level_unknown_fields(){return Ok(false)}
        let mut clean=Vec::with_capacity(self.full_bytes.len());
        scan_fields(&self.full_bytes,|n,_,_,encoded|{if matches!(n,1|2|5){clean.extend_from_slice(encoded)}Ok(())})?;
        self.transaction=Transaction::decode(clean.as_slice()).map_err(|_|TransactionWireError::MalformedProtobuf)?;
        self.full_bytes=clean;
        Ok(true)
    }
    pub fn strip_redundant_results(&mut self)->bool {
        let contract_count=self.transaction.raw_data.as_ref().map_or(0,|r|r.contract.len());
        if contract_count==0 || self.transaction.ret.len()<=contract_count{return false}
        self.transaction.ret.truncate(contract_count);
        self.full_bytes=self.transaction.encode_to_vec();
        true
    }
    #[must_use] pub fn bytes_without_results(&self)->Vec<u8>{let mut tx=self.transaction.clone();tx.ret.clear();tx.encode_to_vec()}
}

pub(crate) fn scan_fields(mut bytes:&[u8],mut visit:impl FnMut(u32,u8,&[u8],&[u8])->Result<(),TransactionWireError>)->Result<(),TransactionWireError>{
    while !bytes.is_empty(){let start=bytes;let (key,key_len)=varint(bytes)?;bytes=&bytes[key_len..];let number=(key>>3) as u32;let wire=(key&7) as u8;if number==0{return Err(TransactionWireError::MalformedProtobuf)}
        let payload;
        match wire {0=>{let(_,n)=varint(bytes)?;payload=&bytes[..n];bytes=&bytes[n..]},1=>{if bytes.len()<8{return Err(TransactionWireError::MalformedProtobuf)}payload=&bytes[..8];bytes=&bytes[8..]},2=>{let(len,n)=varint(bytes)?;let len=usize::try_from(len).map_err(|_|TransactionWireError::MalformedProtobuf)?;if bytes.len()<n+len{return Err(TransactionWireError::MalformedProtobuf)}payload=&bytes[n..n+len];bytes=&bytes[n+len..]},5=>{if bytes.len()<4{return Err(TransactionWireError::MalformedProtobuf)}payload=&bytes[..4];bytes=&bytes[4..]},_=>return Err(TransactionWireError::MalformedProtobuf)}
        let consumed=start.len()-bytes.len();visit(number,wire,payload,&start[..consumed])?;
    }Ok(())
}
fn varint(bytes:&[u8])->Result<(u64,usize),TransactionWireError>{let mut value=0u64;for(i,b)in bytes.iter().copied().take(10).enumerate(){if i==9&&b>1{return Err(TransactionWireError::MalformedProtobuf)}value|=u64::from(b&0x7f)<<(7*i);if b&0x80==0{return Ok((value,i+1))}}Err(TransactionWireError::MalformedProtobuf)}
