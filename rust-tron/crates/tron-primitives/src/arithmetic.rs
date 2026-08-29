use core::fmt;
use num_bigint::BigInt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticMode { Strict, Legacy }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MathPolicy {
    pub allow_strict_math: bool,
    pub disable_java_lang_math: bool,
}
impl MathPolicy {
    pub const fn arithmetic_mode(self) -> ArithmeticMode {
        if self.disable_java_lang_math { ArithmeticMode::Strict } else { ArithmeticMode::Legacy }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticError { Overflow, DivisionByZero }
impl fmt::Display for ArithmeticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Overflow => f.write_str("integer overflow"), Self::DivisionByZero => f.write_str("division by zero") }
    }
}
impl std::error::Error for ArithmeticError {}

pub trait JavaInteger: Copy {
    fn checked_add(self, rhs: Self) -> Option<Self>;
    fn checked_sub(self, rhs: Self) -> Option<Self>;
    fn checked_mul(self, rhs: Self) -> Option<Self>;
}
macro_rules! java_integer {
    ($($ty:ty),+ $(,)?) => {$(
        impl JavaInteger for $ty {
            fn checked_add(self, rhs: Self) -> Option<Self> { self.checked_add(rhs) }
            fn checked_sub(self, rhs: Self) -> Option<Self> { self.checked_sub(rhs) }
            fn checked_mul(self, rhs: Self) -> Option<Self> { self.checked_mul(rhs) }
        }
    )+};
}
java_integer!(i32, i64);

pub fn add<T: JavaInteger>(left: T, right: T, _mode: ArithmeticMode) -> Result<T, ArithmeticError> {
    left.checked_add(right).ok_or(ArithmeticError::Overflow)
}
pub fn subtract<T: JavaInteger>(left: T, right: T, _mode: ArithmeticMode) -> Result<T, ArithmeticError> {
    left.checked_sub(right).ok_or(ArithmeticError::Overflow)
}
pub fn multiply<T: JavaInteger>(left: T, right: T, _mode: ArithmeticMode) -> Result<T, ArithmeticError> {
    left.checked_mul(right).ok_or(ArithmeticError::Overflow)
}

pub fn add_exact_i64(left: i64, right: i64) -> Result<i64, ArithmeticError> { left.checked_add(right).ok_or(ArithmeticError::Overflow) }
pub fn subtract_exact_i64(left: i64, right: i64) -> Result<i64, ArithmeticError> { left.checked_sub(right).ok_or(ArithmeticError::Overflow) }
pub fn multiply_exact_i64(left: i64, right: i64) -> Result<i64, ArithmeticError> { left.checked_mul(right).ok_or(ArithmeticError::Overflow) }
pub fn add_exact_i32(left: i32, right: i32) -> Result<i32, ArithmeticError> { left.checked_add(right).ok_or(ArithmeticError::Overflow) }
pub fn multiply_exact_i32(left: i32, right: i32) -> Result<i32, ArithmeticError> { left.checked_mul(right).ok_or(ArithmeticError::Overflow) }
pub const fn min_i32(left: i32, right: i32) -> i32 { if left <= right { left } else { right } }
pub const fn min_i64(left: i64, right: i64) -> i64 { if left <= right { left } else { right } }
pub const fn max_i32(left: i32, right: i32) -> i32 { if left >= right { left } else { right } }
pub const fn max_i64(left: i64, right: i64) -> i64 { if left >= right { left } else { right } }

/// Java `Math.abs(long)` semantics: `Long.MIN_VALUE` remains negative because its
/// positive magnitude is not representable.
pub const fn abs_i64(value: i64) -> i64 { if value < 0 { value.wrapping_neg() } else { value } }

/// Raw-bit floating operations delegated to the selected Java-compatible engine.
/// Providers must preserve Java behavior for NaN, signed zero, and infinities:
/// round(NaN)=0, round(-∞)=MIN, round(+∞)=MAX; ceil preserves -0.0 and infinities;
/// signum preserves NaN and both signed zeroes. Random is intentionally excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatOperation {
    RoundF32 { input_bits: u32 },
    RoundF64 { input_bits: u64 },
    CeilF64 { input_bits: u64 },
    SignumF64 { input_bits: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatResult {
    I32(i32),
    I64(i64),
    F64Bits(u64),
}

pub trait FloatMathProvider {
    type Error;
    fn strict_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error>;
    fn legacy_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error>;
}

pub fn float_operation<P: FloatMathProvider>(
    provider: &P,
    operation: FloatOperation,
    use_strict_math: bool,
) -> Result<FloatResult, P::Error> {
    if use_strict_math { provider.strict_float(operation) } else { provider.legacy_float(operation) }
}

/// Java Math.floorDiv semantics, including MIN / -1 returning MIN.
pub fn floor_div_i64(dividend: i64, divisor: i64) -> Result<i64, ArithmeticError> {
    if divisor == 0 { return Err(ArithmeticError::DivisionByZero); }
    if dividend == i64::MIN && divisor == -1 { return Ok(i64::MIN); }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    Ok(if remainder != 0 && (dividend ^ divisor) < 0 { quotient - 1 } else { quotient })
}
pub fn floor_div_i32(dividend: i32, divisor: i32) -> Result<i32, ArithmeticError> {
    if divisor == 0 { return Err(ArithmeticError::DivisionByZero); }
    if dividend == i32::MIN && divisor == -1 { return Ok(i32::MIN); }
    let quotient = dividend / divisor;
    let remainder = dividend % divisor;
    Ok(if remainder != 0 && (dividend ^ divisor) < 0 { quotient - 1 } else { quotient })
}

/// Java BigInteger.divide semantics: truncation toward zero.
pub fn bigint_divide_truncating(dividend: &BigInt, divisor: &BigInt) -> Result<BigInt, ArithmeticError> {
    if divisor == &BigInt::from(0) { Err(ArithmeticError::DivisionByZero) } else { Ok(dividend / divisor) }
}

/// Floating-point consensus behavior belongs behind an injected implementation.
/// `tron-primitives` deliberately supplies no host `pow` engine.
pub trait PowProvider {
    type Error;
    fn strict_pow(&self, base_bits: u64, exponent_bits: u64) -> Result<u64, Self::Error>;
    fn legacy_pow(&self, base_bits: u64, exponent_bits: u64) -> Result<u64, Self::Error>;
}

pub fn pow_bits<P: PowProvider>(provider: &P, base_bits: u64, exponent_bits: u64, policy: MathPolicy) -> Result<u64, P::Error> {
    if policy.allow_strict_math { provider.strict_pow(base_bits, exponent_bits) } else { provider.legacy_pow(base_bits, exponent_bits) }
}
