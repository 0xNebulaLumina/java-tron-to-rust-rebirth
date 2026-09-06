use prost::{Enumeration, Message};
use crate::framing::MAX_FRAME_SIZE;

#[derive(Clone, PartialEq, Message)] pub struct CompressMessage { #[prost(enumeration="CompressType", tag="1")] pub r#type:i32, #[prost(bytes="vec", tag="2")] pub data:Vec<u8> }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)] #[repr(i32)] pub enum CompressType { Uncompress=0, Snappy=1 }
#[derive(Debug, thiserror::Error)] pub enum CompressionError { #[error("unknown compression type {0}")] Unknown(i32), #[error("uncompressed message exceeds 5,242,880-byte limit")] TooLarge, #[error("invalid snappy payload: {0}")] Snappy(#[from] snap::Error) }

pub fn envelope(data:&[u8], snappy:bool)->Result<CompressMessage,CompressionError>{
 if data.len()>MAX_FRAME_SIZE{return Err(CompressionError::TooLarge)}
 if snappy { Ok(CompressMessage{r#type:CompressType::Snappy as i32,data:snap::raw::Encoder::new().compress_vec(data)?}) } else { Ok(CompressMessage{r#type:CompressType::Uncompress as i32,data:data.to_vec()}) }
}
pub fn open(message:&CompressMessage)->Result<Vec<u8>,CompressionError>{
 match CompressType::try_from(message.r#type).map_err(|_|CompressionError::Unknown(message.r#type))? {
  CompressType::Uncompress=>{if message.data.len()>MAX_FRAME_SIZE{return Err(CompressionError::TooLarge)} Ok(message.data.clone())},
  CompressType::Snappy=>{let len=snap::raw::decompress_len(&message.data)?;if len>MAX_FRAME_SIZE{return Err(CompressionError::TooLarge)};Ok(snap::raw::Decoder::new().decompress_vec(&message.data)?) }
 }
}
