use core::{cell::{Cell, RefCell}, cmp::Ordering, convert::Infallible, time::Duration};
use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;

use tron_primitives::{
    arithmetic::{abs_i64, add, float_operation, floor_div_i64, max_i64, min_i32, multiply, pow_bits, subtract, FloatMathProvider, FloatOperation, FloatResult},
    bytes::{bigint_to_fixed_bytes, concat_fixed, exact_slice, from_hex, i32_from_be_bytes, i32_from_le_bytes, i32_to_be_bytes, i32_to_le_bytes, i64_from_be_bytes, i64_from_le_bytes, i64_to_be_bytes, i64_to_le_bytes, locale_root_lowercase_key, locale_root_uppercase_key, parse_bytes, positive_to_i64_truncating, reverse_unsigned_lexicographic_cmp, to_hex, to_hex_or_empty, unsigned_lexicographic_cmp, utf8_from_string, ByteError},
    compare_price, compare_price_key, merkle_root, ref_block_bytes, ref_block_hash,
    ArithmeticMode, BlockId, BlockWire, ConsensusTime, DigestProvider, FixedBytesError, Hash32,
    MarketKeyError, MarketPrice, MathPolicy, MonotonicClock, MonotonicInstant, PowProvider,
    TransactionWire, TronAddress21, UnixMillis, WallClock,
};
use tron_primitives::time::{ManualMonotonicClock, ManualWallClock};

#[derive(Clone, Debug)]
enum Json { Null, Bool(bool), Number(i64), String(String), Array(Vec<Json>), Object(BTreeMap<String, Json>) }
impl Json {
    fn object(&self) -> &BTreeMap<String, Json> { if let Self::Object(value) = self { value } else { panic!("expected object: {self:?}") } }
    fn array(&self) -> &[Json] { if let Self::Array(value) = self { value } else { panic!("expected array: {self:?}") } }
    fn string(&self) -> &str { if let Self::String(value) = self { value } else { panic!("expected string: {self:?}") } }
    fn number(&self) -> i64 { if let Self::Number(value) = self { *value } else { panic!("expected number: {self:?}") } }
    fn boolean(&self) -> bool { if let Self::Bool(value) = self { *value } else { panic!("expected bool: {self:?}") } }
}

struct Parser<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Parser<'a> {
    fn parse(input: &'a str) -> Json { let mut parser = Self { bytes: input.as_bytes(), offset: 0 }; let value = parser.value(); parser.space(); assert_eq!(parser.offset, parser.bytes.len()); value }
    fn space(&mut self) { while self.bytes.get(self.offset).is_some_and(u8::is_ascii_whitespace) { self.offset += 1; } }
    fn take(&mut self, byte: u8) { self.space(); assert_eq!(self.bytes.get(self.offset), Some(&byte)); self.offset += 1; }
    fn value(&mut self) -> Json {
        self.space();
        match self.bytes[self.offset] {
            b'n' => { self.offset += 4; Json::Null }
            b't' => { self.offset += 4; Json::Bool(true) }
            b'f' => { self.offset += 5; Json::Bool(false) }
            b'"' => Json::String(self.text()),
            b'[' => self.list(),
            b'{' => self.map(),
            _ => self.integer(),
        }
    }
    fn text(&mut self) -> String {
        self.take(b'"'); let mut output = String::new();
        while self.bytes[self.offset] != b'"' {
            let byte = self.bytes[self.offset]; self.offset += 1;
            if byte == b'\\' {
                let escaped = self.bytes[self.offset]; self.offset += 1;
                match escaped { b'"' | b'\\' | b'/' => output.push(escaped as char), b'b' => output.push('\u{8}'), b'f' => output.push('\u{c}'), b'n' => output.push('\n'), b'r' => output.push('\r'), b't' => output.push('\t'), b'u' => {
                    let digits = core::str::from_utf8(&self.bytes[self.offset..self.offset + 4]).unwrap(); self.offset += 4;
                    output.push(char::from_u32(u32::from_str_radix(digits, 16).unwrap()).unwrap());
                }, _ => panic!("bad escape") }
            } else {
                let rest = core::str::from_utf8(&self.bytes[self.offset - 1..]).unwrap(); let ch = rest.chars().next().unwrap(); output.push(ch); self.offset += ch.len_utf8() - 1;
            }
        }
        self.offset += 1; output
    }
    fn integer(&mut self) -> Json { let start = self.offset; if self.bytes[self.offset] == b'-' { self.offset += 1; } while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) { self.offset += 1; } Json::Number(core::str::from_utf8(&self.bytes[start..self.offset]).unwrap().parse().unwrap()) }
    fn list(&mut self) -> Json { self.take(b'['); let mut values = Vec::new(); self.space(); if self.bytes[self.offset] != b']' { loop { values.push(self.value()); self.space(); if self.bytes[self.offset] != b',' { break; } self.offset += 1; } } self.take(b']'); Json::Array(values) }
    fn map(&mut self) -> Json { self.take(b'{'); let mut values = BTreeMap::new(); self.space(); if self.bytes[self.offset] != b'}' { loop { let key = self.text(); self.take(b':'); assert!(values.insert(key, self.value()).is_none()); self.space(); if self.bytes[self.offset] != b',' { break; } self.offset += 1; } } self.take(b'}'); Json::Object(values) }
}

fn field<'a>(row: &'a BTreeMap<String, Json>, name: &str) -> &'a Json { row.get(name).unwrap_or_else(|| panic!("missing {name} in {:?}", row.get("id"))) }
fn optional<'a>(row: &'a BTreeMap<String, Json>, name: &str) -> Option<&'a Json> { row.get(name) }
fn ordering(value: &str) -> Ordering { match value { "less" => Ordering::Less, "equal" => Ordering::Equal, "greater" => Ordering::Greater, _ => panic!("bad ordering") } }
fn mode(value: &str) -> ArithmeticMode { match value { "strict" => ArithmeticMode::Strict, "legacy" => ArithmeticMode::Legacy, _ => panic!("bad mode") } }
fn hex(value: &str) -> Vec<u8> { from_hex(Some(value)).unwrap() }
fn hash_with_suffix(suffix: u8) -> Hash32 { let mut bytes = [0; 32]; bytes[31] = suffix; Hash32::from_array(bytes) }
fn price(value: &Json) -> MarketPrice { let pair = value.array(); MarketPrice { sell_quantity: pair[0].number(), buy_quantity: pair[1].number() } }
fn price_key(value: &Json) -> Vec<u8> {
    let price = price(value);
    let mut key = vec![0; 38];
    key.extend_from_slice(&price.sell_quantity.to_be_bytes());
    key.extend_from_slice(&price.buy_quantity.to_be_bytes());
    key
}
fn assert_row_schema(group: &str, row: &BTreeMap<String, Json>) {
    let schemas: &[&str] = match group {
        "ids" => &["accepted,expected_prefix,hex,id,kind", "accepted,hex,id,kind,prefix", "accepted,id,input_length,kind"],
        "bytes_order_null" => &["actual,error,id,operation,parts_hex,width", "bytes_hex,id,input,operation,output", "end,error,id,input_hex,operation,start", "end,id,input_hex,operation,output_hex,start", "error,id,input,operation", "id,input,operation,output", "id,input,operation,output_hex", "id,input_hex,length,offset,operation,output_hex", "id,left_hex,operation,ordering,right_hex", "id,operation,output_hex,parts_hex,width"],
        "bigint_fixed_bytes" => &["boundary,id,input,operation,output_hex,width"],
        "deterministic_math_surface" => &["id,input,note,operation,output", "id,input,operation,output", "id,input,operation,output,provider", "id,input,operation,output_bits_hex,provider", "id,left,operation,output,right", "id,operation,reason,status"],
        "math" => &["allow_strict_math,arithmetic_mode,disable_java_lang_math,id,operation,provider_method", "error,id,left,mode,operation,right", "id,left,operation,output,right"],
        "clocks" => &["advance_millis,clock,error,id,start_millis", "advance_millis,clock,id,output_millis,start_millis", "advance_nanos,clock,id,output_nanos,start_nanos", "ambient_clock_reads,clock,id,input_millis,output_millis"],
        "merkle" => &["duplicates_last,hash_calls,id,leaves,name,odd_promotions,pair_inputs_hex,root", "duplicates_last,hash_calls,id,leaves_hex,name,odd_promotions,pair_inputs_hex,root_hex", "hash_calls,id,leaves,name,odd_promotions,pair_inputs_hex,root", "hash_calls,id,leaves,name,odd_promotions,pair_inputs_hex,root_hex", "hash_calls,id,leaves_hex,name,odd_promotions,pair_inputs_hex,root_hex"],
        "raw_hash_inputs" => &["calls_each,expected_a_byte,expected_b_byte,id,input_hex,operation,provider_a_byte,provider_b_byte", "calls_each,expected_a_hex,expected_a_suffix,expected_b_hex,expected_b_suffix,height,id,input_hex,operation,provider_a_suffix,provider_b_suffix", "digest_calls,digest_output_byte,excluded_hex,id,input_hex,operation,result_hex", "digest_calls,digest_output_byte,height,id,input_hex,operation,postprocess,result_hex", "digest_calls,digest_output_byte,id,included,input_hex,operation,result_hex"],
        "wire_hash_boundaries" => &["calls_each,expected_a_byte,expected_b_byte,id,input_hex,operation,provider_a_byte,provider_b_byte", "calls_each,expected_a_hex,expected_a_suffix,expected_b_hex,expected_b_suffix,height,id,input_hex,operation,provider_a_suffix,provider_b_suffix", "digest_calls,digest_output_byte,excluded_hex,id,input_hex,operation,result_hex", "digest_calls,digest_output_byte,height,id,input_hex,operation,overlay,result_hex", "digest_calls,digest_output_byte,id,includes_signatures,input_hex,operation,result_hex"],
        "block_id_inconsistency" => &["block_height,block_suffix,hash_height,hash_suffix,id,operation,ordering", "equals,id,left_hash_suffix,left_height,operation,ordering,right_hash_suffix,right_height", "id,left_hash_suffix,left_height,operation,ordering,right_hash_suffix,right_height"],
        "tapos" => &["block_id,id,ref_block_hash", "block_id_hex,id,ref_block_hash_hex", "height,height_hex,id,ref_block_bytes_hex", "height,id,ref_block_bytes", "height,id,ref_block_bytes_hex"],
        "market_comparator" => &["bytes_hex,case,id,output", "case,error,id,length", "case,id,left,operation,ordering,right", "case,id,left,ordering,right", "case,id,left_pair_prefix_hex,ordering,right_pair_prefix_hex"],
        "arithmetic" => &["allow_strict_math,arithmetic_mode,disable_java_lang_math,id,operation,provider_method", "error,id,left,mode,operation,right"],
        "unicode_keys" => &["id,input,operation,output"],
        "block_id_comparators" => &["id,left_height,left_suffix,operation,ordering,right_height,right_suffix"],
        "market" => &["bytes,id,name,result", "id,left,name,ordering,right", "id,left_price,name,operation,ordering,right_price", "id,left_price,name,ordering,path,right_price"],
        _ => panic!("unknown vector group {group}"),
    };
    let actual = row.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert!(schemas.iter().any(|schema| schema.split(',').collect::<BTreeSet<_>>() == actual), "{}: unconsumed/unexpected fields in {group}: {actual:?}", field(row, "id").string());
}

struct PowSpy(Cell<Option<&'static str>>);
impl PowProvider for PowSpy {
    type Error = Infallible;
    fn strict_pow(&self, _: u64, _: u64) -> Result<u64, Self::Error> { self.0.set(Some("strict_pow")); Ok(1) }
    fn legacy_pow(&self, _: u64, _: u64) -> Result<u64, Self::Error> { self.0.set(Some("legacy_pow")); Ok(2) }
}

struct ByteDigest { byte: u8, inputs: RefCell<Vec<Vec<u8>>> }
impl ByteDigest { fn new(byte: u8) -> Self { Self { byte, inputs: RefCell::new(Vec::new()) } } fn calls(&self) -> usize { self.inputs.borrow().len() } }
impl DigestProvider for ByteDigest {
    type Error = Infallible;
    fn digest(&self, input: &[u8]) -> Result<Hash32, Self::Error> { self.inputs.borrow_mut().push(input.to_vec()); Ok(Hash32::from_array([self.byte; 32])) }
}

struct JavaFloat;
impl FloatMathProvider for JavaFloat {
    type Error = Infallible;
    fn strict_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error> {
        Ok(match operation {
            FloatOperation::RoundF32 { input_bits } => FloatResult::I32(f32::from_bits(input_bits).round() as i32),
            FloatOperation::RoundF64 { input_bits } => FloatResult::I64(f64::from_bits(input_bits).round() as i64),
            FloatOperation::CeilF64 { input_bits } => FloatResult::F64Bits(f64::from_bits(input_bits).ceil().to_bits()),
            FloatOperation::SignumF64 { input_bits } => { let value = f64::from_bits(input_bits); FloatResult::F64Bits(if value.is_nan() || value == 0.0 { input_bits } else { value.signum().to_bits() }) }
        })
    }
    fn legacy_float(&self, operation: FloatOperation) -> Result<FloatResult, Self::Error> { self.strict_float(operation) }
}
fn float_bits(value: &str) -> u64 { match value { "NaN" => f64::NAN.to_bits(), "+Infinity" => f64::INFINITY.to_bits(), "-Infinity" => f64::NEG_INFINITY.to_bits(), "-0.0" => (-0.0f64).to_bits(), _ => value.parse::<f64>().unwrap().to_bits() } }

fn execute_deterministic_math(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string();
    match field(row, "operation").string() {
        "min_i32" => assert_eq!(min_i32(field(row, "left").number() as i32, field(row, "right").number() as i32), field(row, "output").number() as i32, "{id}"),
        "max_i64" => assert_eq!(max_i64(field(row, "left").number(), field(row, "right").number()), field(row, "output").number(), "{id}"),
        "abs_i64" => { assert_eq!(abs_i64(field(row, "input").number()), field(row, "output").number(), "{id}"); if let Some(note) = optional(row, "note") { assert_eq!(note.string(), "Java MIN overflow", "{id}"); } },
        "round_f32" => { assert_eq!(field(row, "input").string(), "NaN", "{id}"); assert_eq!(field(row, "provider").string(), "injected_strict_or_legacy", "{id}"); let request = FloatOperation::RoundF32 { input_bits: f32::NAN.to_bits() }; for strict in [false, true] { assert_eq!(float_operation(&JavaFloat, request, strict).unwrap(), FloatResult::I32(field(row, "output").number() as i32), "{id}"); } },
        "round_f64" => { assert_eq!(field(row, "provider").string(), "injected_strict_or_legacy", "{id}"); let request = FloatOperation::RoundF64 { input_bits: float_bits(field(row, "input").string()) }; for strict in [false, true] { assert_eq!(float_operation(&JavaFloat, request, strict).unwrap(), FloatResult::I64(field(row, "output").number()), "{id}"); } },
        operation @ ("ceil_f64" | "signum_f64") => { assert_eq!(field(row, "provider").string(), "injected_strict_or_legacy", "{id}"); let input_bits = float_bits(field(row, "input").string()); let request = if operation == "ceil_f64" { FloatOperation::CeilF64 { input_bits } } else { FloatOperation::SignumF64 { input_bits } }; let expected = if let Some(bits) = optional(row, "output_bits_hex") { u64::from_str_radix(bits.string(), 16).unwrap() } else { float_bits(field(row, "output").string()) }; for strict in [false, true] { assert_eq!(float_operation(&JavaFloat, request, strict).unwrap(), FloatResult::F64Bits(expected), "{id}"); } },
        "random" => { assert_eq!(field(row, "status").string(), "excluded", "{id}"); assert_eq!(field(row, "reason").string(), "ambient nondeterminism is outside the primitive surface", "{id}"); },
        operation => panic!("{id}: unknown deterministic math operation {operation}"),
    }
}

fn execute_bigint_fixed_bytes(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string();
    assert_eq!(field(row, "operation").string(), "bigint_to_fixed_bytes", "{id}");
    let value = BigInt::from(field(row, "input").number());
    let output = bigint_to_fixed_bytes(Some(&value), field(row, "width").number() as usize).unwrap();
    assert_eq!(to_hex(&output), field(row, "output_hex").string(), "{id}");
}

fn execute_boundary(group: &str, row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string();
    match group {
        "ids" => match field(row, "kind").string() {
            "Hash32" => assert_eq!(Hash32::try_from(vec![0; field(row, "input_length").number() as usize].as_slice()).is_ok(), field(row, "accepted").boolean(), "{id}"),
            "TronAddress21" if field(row, "accepted").boolean() => { let bytes = hex(field(row, "hex").string()); assert_eq!(TronAddress21::validate(&bytes, field(row, "prefix").number() as u8).unwrap().prefix(), field(row, "prefix").number() as u8, "{id}"); }
            "TronAddress21" => { let bytes = hex(field(row, "hex").string()); let expected = field(row, "expected_prefix").number() as u8; assert!(matches!(TronAddress21::validate(&bytes, expected), Err(FixedBytesError::InvalidAddressPrefix { expected: actual_expected, actual }) if actual_expected == expected && actual == bytes[0]), "{id}"); }
            kind => panic!("{id}: unknown kind {kind}"),
        },
        "bytes_order_null" => match field(row, "operation").string() {
            "to_hex_or_empty" => { assert!(matches!(field(row, "input"), Json::Null), "{id}"); assert_eq!(to_hex_or_empty(None), field(row, "output").string(), "{id}"); },
            "from_hex" => { assert!(matches!(field(row, "input"), Json::Null), "{id}"); assert_eq!(to_hex(&from_hex(None).unwrap()), field(row, "output_hex").string(), "{id}"); },
            "utf8_from_string" => { assert!(matches!(field(row, "output"), Json::Null), "{id}"); assert!(utf8_from_string(Some(field(row, "input").string())).is_none(), "{id}"); },
            "parse_bytes" => assert_eq!(to_hex(&parse_bytes(&hex(field(row, "input_hex").string()), field(row, "offset").number() as usize, field(row, "length").number() as usize)), field(row, "output_hex").string(), "{id}"),
            "unsigned_lexicographic_cmp" => assert_eq!(unsigned_lexicographic_cmp(&hex(field(row, "left_hex").string()), &hex(field(row, "right_hex").string())), ordering(field(row, "ordering").string()), "{id}"),
            "reverse_unsigned_lexicographic_cmp" => assert_eq!(reverse_unsigned_lexicographic_cmp(&hex(field(row, "left_hex").string()), &hex(field(row, "right_hex").string())), ordering(field(row, "ordering").string()), "{id}"),
            operation @ ("locale_root_lowercase_key" | "locale_root_uppercase_key") => { let result = if operation == "locale_root_lowercase_key" { locale_root_lowercase_key(field(row, "input").string()) } else { locale_root_uppercase_key(field(row, "input").string()) }; assert_eq!(result, field(row, "output").string(), "{id}"); },
            operation @ ("signed_i64_big_endian_round_trip" | "signed_i64_little_endian_round_trip") => { let input = field(row, "input").number(); let bytes = if operation.contains("big") { i64_to_be_bytes(input) } else { i64_to_le_bytes(input) }; assert_eq!(to_hex(&bytes), field(row, "bytes_hex").string(), "{id}"); let output = if operation.contains("big") { i64_from_be_bytes(bytes) } else { i64_from_le_bytes(bytes) }; assert_eq!(output, field(row, "output").number(), "{id}"); },
            operation @ ("signed_i32_big_endian_round_trip" | "signed_i32_little_endian_round_trip") => { let input = field(row, "input").number() as i32; let bytes = if operation.contains("big") { i32_to_be_bytes(input) } else { i32_to_le_bytes(input) }; assert_eq!(to_hex(&bytes), field(row, "bytes_hex").string(), "{id}"); let output = if operation.contains("big") { i32_from_be_bytes(bytes) } else { i32_from_le_bytes(bytes) }; assert_eq!(output, field(row, "output").number() as i32, "{id}"); },
            "concat_fixed" => { let parts = field(row, "parts_hex").array().iter().map(|part| hex(part.string())).collect::<Vec<_>>(); let refs = parts.iter().map(Vec::as_slice).collect::<Vec<_>>(); match field(row, "width").number() { 4 => assert_eq!(to_hex(&concat_fixed::<4>(&refs).unwrap()), field(row, "output_hex").string(), "{id}"), 3 => assert!(matches!(concat_fixed::<3>(&refs), Err(ByteError::WidthMismatch { expected: 3, actual }) if actual == field(row, "actual").number() as usize && field(row, "error").string() == "width_mismatch"), "{id}"), width => panic!("{id}: unsupported concat width {width}") } },
            "exact_slice" => { let input = hex(field(row, "input_hex").string()); let start = field(row, "start").number() as usize; let end = field(row, "end").number() as usize; if let Some(output) = optional(row, "output_hex") { assert_eq!(to_hex(&exact_slice(&input, start, end).unwrap()), output.string(), "{id}"); } else { assert!(matches!(exact_slice(&input, start, end), Err(ByteError::InvalidRange { .. })) && field(row, "error").string() == "invalid_range", "{id}"); } },
            operation => panic!("{id}: unknown operation {operation}"),
        },
        "bigint_fixed_bytes" => execute_bigint_fixed_bytes(row),
        "deterministic_math_surface" => execute_deterministic_math(row),
        "math" => execute_math(row),
        "clocks" => match field(row, "clock").string() {
            "manual_wall" => { let clock = ManualWallClock::new(UnixMillis::new(field(row, "start_millis").number())); let result = clock.advance(field(row, "advance_millis").number()); if let Some(error) = optional(row, "error") { assert_eq!(error.string(), "overflow", "{id}"); assert!(result.is_err(), "{id}"); } else { result.unwrap(); assert_eq!(clock.now().get(), field(row, "output_millis").number(), "{id}"); } }
            "manual_monotonic" => { let clock = ManualMonotonicClock::new(MonotonicInstant::from_duration(Duration::from_nanos(field(row, "start_nanos").number() as u64))); clock.advance(Duration::from_nanos(field(row, "advance_nanos").number() as u64)).unwrap(); assert_eq!(clock.now().duration().as_nanos(), field(row, "output_nanos").number() as u128, "{id}"); }
            "consensus_time" => { assert_eq!(ConsensusTime::from_unix_millis(UnixMillis::new(field(row, "input_millis").number())).unix_millis().get(), field(row, "output_millis").number(), "{id}"); assert_eq!(field(row, "ambient_clock_reads").number(), 0, "{id}"); },
            clock => panic!("{id}: unknown clock {clock}"),
        },
        "merkle" => execute_merkle(row),
        "raw_hash_inputs" => execute_wire(row),
        "block_id_inconsistency" => execute_block_comparator(row),
        "tapos" => execute_tapos(row, "ref_block_bytes_hex", "block_id_hex", "ref_block_hash_hex"),
        "market_comparator" => execute_market(row, "case"),
        _ => panic!("{id}: unknown group {group}"),
    }
}

fn execute_math(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string();
    match field(row, "operation").string() {
        "add_i64" => { assert_eq!(field(row, "error").string(), "overflow", "{id}"); assert!(add(field(row, "left").number(), field(row, "right").number(), mode(field(row, "mode").string())).is_err(), "{id}"); },
        "subtract_i64" => { assert_eq!(field(row, "error").string(), "overflow", "{id}"); assert!(subtract(field(row, "left").number(), field(row, "right").number(), mode(field(row, "mode").string())).is_err(), "{id}"); },
        "multiply_i64" => { assert_eq!(field(row, "error").string(), "overflow", "{id}"); assert!(multiply(field(row, "left").number(), field(row, "right").number(), mode(field(row, "mode").string())).is_err(), "{id}"); },
        "floor_div_i64" => assert_eq!(floor_div_i64(field(row, "left").number(), field(row, "right").number()).unwrap(), field(row, "output").number(), "{id}"),
        "policy" => { let policy = MathPolicy { allow_strict_math: field(row, "allow_strict_math").boolean(), disable_java_lang_math: field(row, "disable_java_lang_math").boolean() }; assert_eq!(policy.arithmetic_mode(), mode(field(row, "arithmetic_mode").string()), "{id}"); let spy = PowSpy(Cell::new(None)); pow_bits(&spy, 0, 0, policy).unwrap(); assert_eq!(spy.0.get(), Some(field(row, "provider_method").string()), "{id}"); },
        operation => panic!("{id}: unknown math operation {operation}"),
    }
}

fn execute_merkle(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string(); let digest = ByteDigest::new(0xaa);
    let leaves = optional(row, "leaves_hex").or_else(|| optional(row, "leaves")).unwrap().array().iter().map(|value| { let bytes = hex(value.string()); if bytes.len() == 1 { Hash32::from_array([bytes[0]; 32]) } else { Hash32::try_from(bytes.as_slice()).unwrap() } }).collect::<Vec<_>>();
    let mut width = leaves.len(); let mut promotions = 0; while width > 1 { promotions += width % 2; width = (width + 1) / 2; }
    let root = merkle_root(&digest, &leaves).unwrap();
    assert!(matches!(field(row, "name").string(), "empty" | "single" | "single-promoted" | "odd" | "three-odd-promotion"), "{id}");
    assert_eq!(digest.calls(), field(row, "hash_calls").number() as usize, "{id}");
    assert_eq!(promotions, field(row, "odd_promotions").number() as usize, "{id}");
    if let Some(duplicates) = optional(row, "duplicates_last") { assert!(!duplicates.boolean(), "{id}"); }
    let expected_inputs = field(row, "pair_inputs_hex").array().iter().map(|value| hex(value.string())).collect::<Vec<_>>();
    assert_eq!(*digest.inputs.borrow(), expected_inputs, "{id}");
    let root_key = if row.contains_key("root_hex") { "root_hex" } else { "root" };
    assert_eq!(to_hex(root.as_bytes()), field(row, root_key).string(), "{id}");
}

fn execute_wire(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string(); let operation = field(row, "operation").string();
    match operation {
        "transaction_id" | "transaction_full_hash" => { let digest = ByteDigest::new(field(row, "digest_output_byte").number() as u8); let wire = TransactionWire::new(hex(if operation == "transaction_full_hash" { field(row, "input_hex").string() } else { field(row, "excluded_hex").string() }), hex(if operation == "transaction_id" { field(row, "input_hex").string() } else { "1122" })); let result = if operation == "transaction_id" { wire.transaction_id(&digest).unwrap().hash() } else { wire.full_hash(&digest).unwrap() }; assert_eq!(digest.inputs.borrow().as_slice(), &[hex(field(row, "input_hex").string())], "{id}"); assert_eq!(digest.calls(), field(row, "digest_calls").number() as usize, "{id}"); assert_eq!(to_hex(result.as_bytes()), field(row, "result_hex").string(), "{id}"); if operation == "transaction_full_hash" { if let Some(included) = optional(row, "included") { assert_eq!(included.string(), "signatures and results", "{id}"); } else { assert!(field(row, "includes_signatures").boolean(), "{id}"); } } },
        "block_id" => { let digest = ByteDigest::new(field(row, "digest_output_byte").number() as u8); let wire = BlockWire::new(Vec::<u8>::new(), hex(field(row, "input_hex").string()), field(row, "height").number()); let block = wire.block_id(&digest).unwrap(); assert_eq!(digest.inputs.borrow().as_slice(), &[hex(field(row, "input_hex").string())], "{id}"); assert_eq!(digest.calls(), field(row, "digest_calls").number() as usize, "{id}"); assert_eq!(block.height(), field(row, "height").number(), "{id}"); assert_eq!(to_hex(block.as_bytes()), field(row, "result_hex").string(), "{id}"); let description = optional(row, "postprocess").or_else(|| optional(row, "overlay")).unwrap().string(); assert!(description.contains("height") && (description.contains("0..8") || description.contains("digest[0..8]")), "{id}"); },
        "transaction_provider_isolation" => { let wire = TransactionWire::new(Vec::<u8>::new(), hex(field(row, "input_hex").string())); let a = ByteDigest::new(field(row, "provider_a_byte").number() as u8); let b = ByteDigest::new(field(row, "provider_b_byte").number() as u8); let result_a = wire.transaction_id(&a).unwrap(); let result_b = wire.transaction_id(&b).unwrap(); assert_eq!(result_a.as_bytes(), &[field(row, "expected_a_byte").number() as u8; 32], "{id}"); assert_eq!(result_b.as_bytes(), &[field(row, "expected_b_byte").number() as u8; 32], "{id}"); assert_eq!((a.calls(), b.calls()), (field(row, "calls_each").number() as usize, field(row, "calls_each").number() as usize), "{id}"); assert_eq!(*a.inputs.borrow(), vec![hex(field(row, "input_hex").string())], "{id}"); assert_eq!(*b.inputs.borrow(), vec![hex(field(row, "input_hex").string())], "{id}"); },
        "block_provider_isolation" => { let wire = BlockWire::new(Vec::<u8>::new(), hex(field(row, "input_hex").string()), field(row, "height").number()); let a = ByteDigest::new(field(row, "provider_a_suffix").number() as u8); let b = ByteDigest::new(field(row, "provider_b_suffix").number() as u8); let result_a = wire.block_id(&a).unwrap(); let result_b = wire.block_id(&b).unwrap(); assert_eq!(result_a.as_bytes()[31], field(row, "expected_a_suffix").number() as u8, "{id}"); assert_eq!(result_b.as_bytes()[31], field(row, "expected_b_suffix").number() as u8, "{id}"); assert_eq!(to_hex(result_a.as_bytes()), field(row, "expected_a_hex").string(), "{id}"); assert_eq!(to_hex(result_b.as_bytes()), field(row, "expected_b_hex").string(), "{id}"); assert_eq!((a.calls(), b.calls()), (field(row, "calls_each").number() as usize, field(row, "calls_each").number() as usize), "{id}"); assert_eq!(*a.inputs.borrow(), vec![hex(field(row, "input_hex").string())], "{id}"); assert_eq!(*b.inputs.borrow(), vec![hex(field(row, "input_hex").string())], "{id}"); },
        _ => panic!("{id}: unknown wire operation {operation}"),
    }
}

fn execute_block_comparator(row: &BTreeMap<String, Json>) {
    let id = field(row, "id").string(); let left_height = optional(row, "left_height").or_else(|| optional(row, "block_height")).unwrap().number(); let right_height = optional(row, "right_height").or_else(|| optional(row, "hash_height")).unwrap().number(); let left_suffix = optional(row, "left_hash_suffix").or_else(|| optional(row, "left_suffix")).or_else(|| optional(row, "block_suffix")).unwrap().number() as u8; let right_suffix = optional(row, "right_hash_suffix").or_else(|| optional(row, "right_suffix")).or_else(|| optional(row, "hash_suffix")).unwrap().number() as u8; let left = BlockId::new(left_height, hash_with_suffix(left_suffix)); let right = BlockId::new(right_height, hash_with_suffix(right_suffix));
    let actual = match field(row, "operation").string() { "height_compare" => left.height_compare(&right), "total_bytes_compare" => left.total_bytes_compare(&right), "cmp_hash" => left.cmp_hash(&right.hash()), operation => panic!("{id}: unknown comparator {operation}") }; assert_eq!(actual, ordering(field(row, "ordering").string()), "{id}"); if optional(row, "equals").is_some() { assert_eq!(left == right, field(row, "equals").boolean(), "{id}"); }
}

fn execute_tapos(row: &BTreeMap<String, Json>, bytes_key: &str, block_key: &str, hash_key: &str) {
    let id = field(row, "id").string(); if let Some(height) = optional(row, "height") { if let Some(height_hex) = optional(row, "height_hex") { assert_eq!(to_hex(&height.number().to_be_bytes()), height_hex.string(), "{id}"); } assert_eq!(to_hex(&ref_block_bytes(height.number())), field(row, bytes_key).string(), "{id}"); } else { let bytes = hex(field(row, block_key).string()); let hash = Hash32::try_from(bytes.as_slice()).unwrap(); assert_eq!(to_hex(&ref_block_hash(&hash)), field(row, hash_key).string(), "{id}"); }
}

fn execute_market(row: &BTreeMap<String, Json>, name_key: &str) {
    let id = field(row, "id").string(); match field(row, name_key).string() {
        "pair_first" | "unsigned-pair" => { let left = hex(optional(row, "left_pair_prefix_hex").or_else(|| optional(row, "left")).unwrap().string()); let right = hex(optional(row, "right_pair_prefix_hex").or_else(|| optional(row, "right")).unwrap().string()); assert_eq!(unsigned_lexicographic_cmp(&left, &right), ordering(field(row, "ordering").string()), "{id}"); }
        "both_zero_price" | "one_zero_price" => { assert_eq!(field(row, "operation").string(), "compare_price_key", "{id}"); let left = price_key(field(row, "left")); let right = price_key(field(row, "right")); assert_eq!(compare_price_key(&left, &right).unwrap(), ordering(field(row, "ordering").string()), "{id}"); }
        "checked_cross_product" | "big_integer_fallback" => assert_eq!(compare_price(price(field(row, "left")), price(field(row, "right"))), ordering(field(row, "ordering").string()), "{id}"),
        "zero-head" => { assert_eq!(field(row, "operation").string(), "compare_price_key", "{id}"); let left = price_key(field(row, "left_price")); let right = price_key(field(row, "right_price")); assert_eq!(compare_price_key(&left, &right).unwrap(), ordering(field(row, "ordering").string()), "{id}"); }
        "overflow-fallback" => { assert_eq!(field(row, "path").string(), "BigInteger", "{id}"); assert_eq!(compare_price(price(field(row, "left_price")), price(field(row, "right_price"))), ordering(field(row, "ordering").string()), "{id}"); }
        "positive_big_integer_long_truncation" | "positive-long-truncation" => assert_eq!(positive_to_i64_truncating(Some(&hex(optional(row, "bytes_hex").or_else(|| optional(row, "bytes")).unwrap().string()))), optional(row, "output").or_else(|| optional(row, "result")).unwrap().number(), "{id}"),
        "short_key" => { assert_eq!(field(row, "error").string(), "too_short", "{id}"); let bytes = vec![0; field(row, "length").number() as usize]; assert!(matches!(compare_price_key(&bytes, &bytes), Err(MarketKeyError::TooShort { .. })), "{id}"); }
        name => panic!("{id}: unknown market case {name}"),
    }
}

fn execute_fixture(group: &str, row: &BTreeMap<String, Json>) {
    match group {
        "merkle" => execute_merkle(row),
        "tapos" => execute_tapos(row, "ref_block_bytes", "block_id", "ref_block_hash"),
        "wire_hash_boundaries" => execute_wire(row),
        "arithmetic" => execute_math(row),
        "unicode_keys" => { let operation = field(row, "operation").string(); let result = if operation == "locale_root_lowercase_key" { locale_root_lowercase_key(field(row, "input").string()) } else if operation == "locale_root_uppercase_key" { locale_root_uppercase_key(field(row, "input").string()) } else { panic!("unknown Unicode casing operation") }; assert_eq!(result, field(row, "output").string()); },
        "block_id_comparators" => execute_block_comparator(row),
        "market" => execute_market(row, "name"),
        "bigint_fixed_bytes" => execute_bigint_fixed_bytes(row),
        _ => panic!("unknown fixture group {group}"),
    }
}

fn execute_manifest(input: &str, fixture: bool) -> usize {
    let root = Parser::parse(input); let groups = field(root.object(), "vectors").object(); let mut count = 0;
    for (group, rows) in groups { for value in rows.array() { let row = value.object(); assert_row_schema(group, row); if fixture { execute_fixture(group, row); } else { execute_boundary(group, row); } count += 1; } }
    count
}

#[test]
fn every_java_boundary_vector_is_deserialized_and_executed() {
    assert_eq!(execute_manifest(include_str!("../../../../docs/oracles/c002-java-boundary-vectors.v1.json"), false), 83);
}

#[test]
fn every_primitive_fixture_is_deserialized_and_executed() {
    assert_eq!(execute_manifest(include_str!("../../../../docs/oracles/c002-primitives-fixtures.v1.json"), true), 41);
}
