use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub const MAX_FRAME_SIZE: usize = 5_242_880;
pub const MAX_VARINT_BYTES: usize = 5;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Traffic {
    pub received_wire: u64,
    pub received_payload: u64,
    pub sent_wire: u64,
    pub sent_payload: u64,
}

#[derive(Debug, Default)]
pub struct VarintFrameCodec { traffic: Traffic }
impl VarintFrameCodec {
    pub fn traffic(&self) -> &Traffic { &self.traffic }
    pub(crate) fn record_sent_wire(&mut self, bytes: usize) { self.traffic.sent_wire = self.traffic.sent_wire.saturating_add(bytes as u64); }
    pub(crate) fn record_sent_payload(&mut self, bytes: usize) { self.traffic.sent_payload = self.traffic.sent_payload.saturating_add(bytes as u64); }
    fn prefix(len: usize, dst: &mut BytesMut) {
        let mut n = len as u32;
        while n >= 0x80 { dst.put_u8((n as u8) | 0x80); n >>= 7; }
        dst.put_u8(n as u8);
    }
}
impl Decoder for VarintFrameCodec {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let mut len = 0u32;
        let mut shift = 0;
        let mut prefix = None;
        for (i, byte) in src.iter().take(MAX_VARINT_BYTES).copied().enumerate() {
            if i == MAX_VARINT_BYTES - 1 {
                if byte & 0x80 != 0 || byte > 0x0f {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed protobuf varint32 frame length"));
                }
            }
            len |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 { prefix = Some(i + 1); break; }
            shift += 7;
        }
        let Some(prefix_len) = prefix else {
            if src.len() >= MAX_VARINT_BYTES { return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed protobuf varint32 frame length")); }
            return Ok(None);
        };
        let len = len as usize;
        if len > MAX_FRAME_SIZE { return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds 5,242,880-byte limit")); }
        if src.len() < prefix_len + len { return Ok(None); }
        src.advance(prefix_len);
        let frame = src.split_to(len).freeze();
        self.traffic.received_wire = self.traffic.received_wire.saturating_add((prefix_len + len) as u64);
        self.traffic.received_payload = self.traffic.received_payload.saturating_add(len as u64);
        Ok(Some(frame))
    }
}
impl Encoder<Bytes> for VarintFrameCodec {
    type Error = io::Error;
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        if item.len() > MAX_FRAME_SIZE { return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds 5,242,880-byte limit")); }
        dst.reserve(5 + item.len()); Self::prefix(item.len(), dst); dst.extend_from_slice(&item);
        Ok(())
    }
}
