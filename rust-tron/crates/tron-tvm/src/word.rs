use core::{cmp::Ordering, fmt, ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Not, Rem, Sub}};
use ruint::aliases::U256;
use tron_primitives::{Address20, Hash32, TronAddress21};

/// A TVM data word. The backing integer is deliberately not exposed.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Word(U256);

impl Word {
    pub const ZERO: Self = Self(U256::ZERO);
    pub const ONE: Self = Self(U256::from_limbs([1, 0, 0, 0]));
    pub const MAX: Self = Self(U256::MAX);
    pub const MIN_SIGNED: Self = Self(U256::from_limbs([0, 0, 0, 1 << 63]));

    #[must_use] pub fn from_be_bytes(bytes: [u8; 32]) -> Self { Self(U256::from_be_bytes(bytes)) }
    #[must_use] pub fn to_be_bytes(self) -> [u8; 32] { self.0.to_be_bytes() }
    #[must_use] pub fn from_u64(value: u64) -> Self { Self(U256::from(value)) }
    #[must_use] pub fn is_zero(self) -> bool { self == Self::ZERO }
    #[must_use] pub fn bit(self, index: usize) -> bool { index < 256 && self.0.bit(index) }
    #[must_use] pub fn bytes_occupied(self) -> usize { (256_usize.saturating_sub(self.0.leading_zeros()) + 7) / 8 }
    #[must_use] pub fn leading_zeros(self) -> u32 { self.0.leading_zeros() as u32 }
    #[must_use] pub fn low_u32(self) -> u32 { self.0.as_limbs()[0] as u32 }
    #[must_use] pub fn low_u64(self) -> u64 { self.0.as_limbs()[0] }
    #[must_use] pub fn low_i32(self) -> i32 { self.low_u32() as i32 }
    #[must_use] pub fn low_i64(self) -> i64 { self.low_u64() as i64 }
    #[must_use] pub fn to_i32_safe(self) -> i32 { if self > Self::from_u64(i32::MAX as u64) { i32::MAX } else { self.low_i32() } }
    #[must_use] pub fn to_i64_safe(self) -> i64 { if self > Self::from_u64(i64::MAX as u64) { i64::MAX } else { self.low_i64() } }
    #[must_use] pub fn last20(self) -> Address20 { Address20::from_array(self.to_be_bytes()[12..].try_into().expect("fixed slice")) }
    #[must_use] pub fn to_tron_address(self) -> TronAddress21 { TronAddress21::new(0x41, self.last20()) }
    #[must_use] pub fn as_hash(self) -> Hash32 { Hash32::from_array(self.to_be_bytes()) }
    #[must_use] pub fn no_leading_zero_bytes(self) -> Vec<u8> { let b=self.to_be_bytes(); let n=b.iter().position(|v|*v!=0).unwrap_or(32); b[n..].to_vec() }
    #[must_use] pub fn wrapping_add(self, rhs: Self) -> Self { Self(self.0.wrapping_add(rhs.0)) }
    #[must_use] pub fn wrapping_sub(self, rhs: Self) -> Self { Self(self.0.wrapping_sub(rhs.0)) }
    #[must_use] pub fn wrapping_mul(self, rhs: Self) -> Self { Self(self.0.wrapping_mul(rhs.0)) }
    #[must_use] pub fn unsigned_div(self, rhs: Self) -> Self { if rhs.is_zero() { Self::ZERO } else { Self(self.0 / rhs.0) } }
    #[must_use] pub fn unsigned_rem(self, rhs: Self) -> Self { if rhs.is_zero() { Self::ZERO } else { Self(self.0 % rhs.0) } }
    #[must_use] pub fn is_negative(self) -> bool { self.bit(255) }
    #[must_use] fn neg(self) -> Self { Self::ZERO.wrapping_sub(self) }
    #[must_use] pub fn signed_cmp(self, rhs: Self) -> Ordering { match (self.is_negative(),rhs.is_negative()) { (true,false)=>Ordering::Less,(false,true)=>Ordering::Greater,_=>self.cmp(&rhs) } }
    #[must_use] pub fn signed_div(self, rhs: Self) -> Self { if rhs.is_zero(){return Self::ZERO;} let neg=self.is_negative()^rhs.is_negative(); let a=if self.is_negative(){self.neg()}else{self}; let b=if rhs.is_negative(){rhs.neg()}else{rhs}; let q=a.unsigned_div(b); if neg {q.neg()} else {q} }
    #[must_use] pub fn signed_rem(self, rhs: Self) -> Self { if rhs.is_zero(){return Self::ZERO;} let neg=self.is_negative(); let a=if neg{self.neg()}else{self}; let b=if rhs.is_negative(){rhs.neg()}else{rhs}; let r=a.unsigned_rem(b); if neg {r.neg()} else {r} }
    #[must_use] pub fn shl(self, shift: Self) -> Self { let s=shift.to_i32_safe(); if s>=256 {Self::ZERO} else {Self(self.0 << s)} }
    #[must_use] pub fn shr(self, shift: Self) -> Self { let s=shift.to_i32_safe(); if s>=256 {Self::ZERO} else {Self(self.0 >> s)} }
    #[must_use] pub fn sar(self, shift: Self) -> Self { let s=shift.to_i32_safe(); if s>=256 {if self.is_negative(){Self::MAX}else{Self::ZERO}} else if !self.is_negative(){self.shr(shift)} else { let shifted=self.0 >> s; let fill=U256::MAX << (256-s); Self(shifted|fill) } }
    #[must_use] pub fn sign_extend(self, byte: Self) -> Self { let b=byte.to_i32_safe(); if b>=32 {return self;} let bit=(b as usize)*8+7; if self.bit(bit) { let mask=U256::MAX << (bit+1); Self(self.0|mask) } else { let mask=(U256::from(1u8) << (bit+1))-U256::from(1u8); Self(self.0&mask) } }
}
impl Ord for Word { fn cmp(&self, rhs:&Self)->Ordering { self.0.cmp(&rhs.0) } }
impl PartialOrd for Word { fn partial_cmp(&self,rhs:&Self)->Option<Ordering>{Some(self.cmp(rhs))} }
impl fmt::Debug for Word { fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { write!(f,"Word(0x")?; for b in self.to_be_bytes(){write!(f,"{b:02x}")?;} write!(f,")") } }
impl From<u8> for Word { fn from(v:u8)->Self{Self(U256::from(v))} } impl From<u64> for Word { fn from(v:u64)->Self{Self::from_u64(v)} }
impl Add for Word {type Output=Self;fn add(self,r:Self)->Self{self.wrapping_add(r)}} impl Sub for Word{type Output=Self;fn sub(self,r:Self)->Self{self.wrapping_sub(r)}} impl Mul for Word{type Output=Self;fn mul(self,r:Self)->Self{self.wrapping_mul(r)}} impl Div for Word{type Output=Self;fn div(self,r:Self)->Self{self.unsigned_div(r)}} impl Rem for Word{type Output=Self;fn rem(self,r:Self)->Self{self.unsigned_rem(r)}}
impl BitAnd for Word{type Output=Self;fn bitand(self,r:Self)->Self{Self(self.0&r.0)}} impl BitOr for Word{type Output=Self;fn bitor(self,r:Self)->Self{Self(self.0|r.0)}} impl BitXor for Word{type Output=Self;fn bitxor(self,r:Self)->Self{Self(self.0^r.0)}} impl Not for Word{type Output=Self;fn not(self)->Self{Self(!self.0)}}
