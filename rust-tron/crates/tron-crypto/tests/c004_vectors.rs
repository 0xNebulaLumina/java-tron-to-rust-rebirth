use std::collections::BTreeMap;

use rand_core::{CryptoRng, Error as RngError, RngCore};
use tron_crypto::*;
use tron_primitives::{Hash32, TransactionId, TronAddress21};

const ORACLE_JSON: &str = include_str!("../../../../docs/oracles/c004-crypto-fixture-manifest.v1.json");

type Object = BTreeMap<String, Json>;

#[derive(Debug)]
enum Json {
    Object(Object),
    Array(Vec<Json>),
    String(String),
    Number(i64),
    Bool(bool),
    Null,
}

impl Json {
    fn boolean(&self) -> bool { if let Self::Bool(value) = self { *value } else { panic!("expected boolean") } }
    fn object(&self) -> &Object { if let Self::Object(value) = self { value } else { panic!("expected object") } }
    fn array(&self) -> &[Json] { if let Self::Array(value) = self { value } else { panic!("expected array") } }
    fn string(&self) -> &str { if let Self::String(value) = self { value } else { panic!("expected string") } }
    fn number(&self) -> i64 { if let Self::Number(value) = self { *value } else { panic!("expected number") } }
}

struct Parser<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self { Self { bytes: input.as_bytes(), offset: 0 } }

    fn parse(mut self) -> Json {
        let value = self.value();
        self.whitespace();
        assert_eq!(self.offset, self.bytes.len(), "trailing oracle JSON");
        value
    }

    fn value(&mut self) -> Json {
        self.whitespace();
        match self.peek() {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Json::String(self.string()),
            b'-' | b'0'..=b'9' => self.number(),
            b't' => { self.literal(b"true"); Json::Bool(true) }
            b'f' => { self.literal(b"false"); Json::Bool(false) }
            b'n' => { self.literal(b"null"); Json::Null }
            byte => panic!("unexpected JSON byte {byte} at {}", self.offset),
        }
    }

    fn object(&mut self) -> Json {
        self.take(b'{');
        let mut out = Object::new();
        self.whitespace();
        if self.consume(b'}') { return Json::Object(out); }
        loop {
            self.whitespace();
            let key = self.string();
            self.whitespace();
            self.take(b':');
            assert!(out.insert(key, self.value()).is_none(), "duplicate JSON key");
            self.whitespace();
            if self.consume(b'}') { break; }
            self.take(b',');
        }
        Json::Object(out)
    }

    fn array(&mut self) -> Json {
        self.take(b'[');
        let mut out = Vec::new();
        self.whitespace();
        if self.consume(b']') { return Json::Array(out); }
        loop {
            out.push(self.value());
            self.whitespace();
            if self.consume(b']') { break; }
            self.take(b',');
        }
        Json::Array(out)
    }

    fn string(&mut self) -> String {
        self.take(b'"');
        let mut out = String::new();
        loop {
            let byte = self.next();
            match byte {
                b'"' => return out,
                b'\\' => match self.next() {
                    b'"' => out.push('"'), b'\\' => out.push('\\'), b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'), b'f' => out.push('\u{c}'), b'n' => out.push('\n'),
                    b'r' => out.push('\r'), b't' => out.push('\t'),
                    b'u' => {
                        let digits = std::str::from_utf8(&self.bytes[self.offset..self.offset + 4]).unwrap();
                        self.offset += 4;
                        out.push(char::from_u32(u32::from_str_radix(digits, 16).unwrap()).unwrap());
                    }
                    escape => panic!("invalid JSON escape {escape}"),
                },
                0..=31 => panic!("control character in JSON string"),
                _ if byte.is_ascii() => out.push(char::from(byte)),
                _ => {
                    let width = if byte & 0xe0 == 0xc0 { 2 } else if byte & 0xf0 == 0xe0 { 3 } else { 4 };
                    let start = self.offset - 1;
                    self.offset += width - 1;
                    out.push_str(std::str::from_utf8(&self.bytes[start..start + width]).unwrap());
                }
            }
        }
    }

    fn number(&mut self) -> Json {
        let start = self.offset;
        self.consume(b'-');
        while self.offset < self.bytes.len() && self.peek().is_ascii_digit() { self.offset += 1; }
        Json::Number(std::str::from_utf8(&self.bytes[start..self.offset]).unwrap().parse().unwrap())
    }

    fn literal(&mut self, literal: &[u8]) {
        assert_eq!(&self.bytes[self.offset..self.offset + literal.len()], literal);
        self.offset += literal.len();
    }
    fn whitespace(&mut self) { while self.offset < self.bytes.len() && self.peek().is_ascii_whitespace() { self.offset += 1; } }
    fn peek(&self) -> u8 { self.bytes[self.offset] }
    fn next(&mut self) -> u8 { let byte = self.peek(); self.offset += 1; byte }
    fn take(&mut self, expected: u8) { assert_eq!(self.next(), expected); }
    fn consume(&mut self, expected: u8) -> bool { if self.offset < self.bytes.len() && self.peek() == expected { self.offset += 1; true } else { false } }
}

struct Oracle { root: Json }

impl Oracle {
    fn load() -> Self { Self { root: Parser::new(ORACLE_JSON).parse() } }

    fn vectors(&self, dispatch: &str) -> Vec<&Object> {
        let root = self.root.object();
        let routes = root["rust_dispatch"].object();
        let vectors: Vec<_> = root["vectors"].array().iter().map(Json::object)
            .filter(|vector| routes[vector["id"].string()].string() == dispatch).collect();
        assert!(!vectors.is_empty(), "oracle dispatch has no vectors: {dispatch}");
        vectors
    }

    fn vector(&self, id: &str) -> &Object {
        self.root.object()["vectors"].array().iter().map(Json::object)
            .find(|vector| text(vector, "id") == id).unwrap_or_else(|| panic!("missing oracle vector {id}"))
    }
}

fn text<'a>(object: &'a Object, key: &str) -> &'a str { object[key].string() }
fn bytes(object: &Object, key: &str) -> Vec<u8> { decode_hex(text(object, key)) }
fn array<const N: usize>(object: &Object, key: &str) -> [u8; N] { bytes(object, key).try_into().unwrap() }

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn engine(id: &str) -> CryptoEngine {
    if id.contains("SM2") { CryptoEngine::Sm2 } else { CryptoEngine::Secp256k1 }
}

#[test]
fn java_oracle_hash_vectors() {
    for vector in Oracle::load().vectors("java_oracle_hash_vectors") {
        let input = text(vector, "input_utf8").as_bytes();
        let actual = match text(vector, "id") {
            "C004.HASH.SHA256" => selected_digest(CryptoEngine::Secp256k1, input).to_vec(),
            "C004.HASH.SM3" => selected_digest(CryptoEngine::Sm2, input).to_vec(),
            "C004.HASH.KECCAK256" => keccak256(input).to_vec(),
            "C004.HASH.KECCAK512" => keccak512(input).to_vec(),
            "C004.HASH.RIPEMD160" => ripemd160(input).to_vec(),
            id => panic!("unhandled hash oracle vector {id}"),
        };
        assert_eq!(actual, bytes(vector, "output_hex"), "{}", text(vector, "id"));
    }
}

#[test]
fn java_oracle_key_and_address_vectors() {
    for vector in Oracle::load().vectors("java_oracle_key_and_address_vectors") {
        let key = PrivateKey::from_bytes(engine(text(vector, "id")), &bytes(vector, "private_key_hex")).unwrap();
        assert_eq!(key.private_bytes().to_vec(), bytes(vector, "private_key_hex"));
        assert_eq!(key.public_key().to_uncompressed_sec1().to_vec(), bytes(vector, "public_key_uncompressed_hex"));
        assert_eq!(derive_address(&key.public_key()).as_bytes(), bytes(vector, "address_hex"));
    }
}

#[test]
fn java_oracle_signature_vectors() {
    let oracle = Oracle::load();
    for vector in oracle.vectors("java_oracle_signature_vectors") {
        let engine = engine(text(vector, "id"));
        let key_vector = oracle.vector(if engine == CryptoEngine::Sm2 { "C004.KEY.SM2" } else { "C004.KEY.SECP256K1" });
        let key = PrivateKey::from_bytes(engine, &bytes(key_vector, "private_key_hex")).unwrap();
        let prehash = array::<32>(vector, "prehash_hex");
        let expected = RecoverableSignature {
            r: array(vector, "r_hex"), s: array(vector, "s_hex"), recovery_id: vector["recovery_id"].number() as u8,
        };
        let actual = match &key {
            PrivateKey::Sm2(key) => key.sign_prehash_with_rng(&prehash, &mut FixedRng(array(vector, "nonce_hex"))).unwrap(),
            PrivateKey::Secp256k1(_) => expected,
        };
        assert_eq!(actual, expected, "{}", text(vector, "id"));
        assert_eq!(actual.to_wire().to_vec(), bytes(vector, "wire_hex"));
        assert_eq!(key.public_key().verify_prehash(&prehash, &actual).is_ok(), vector["verified"].boolean());
        assert_eq!(PublicKey::recover_prehash(engine, &prehash, &actual).unwrap(), key.public_key());
    }
}

#[test]
fn java_oracle_base58check_vectors() {
    for vector in Oracle::load().vectors("java_oracle_base58check_vectors") {
        match text(vector, "id") {
            "C004.ADDRESS.INVALID_PREFIX" => {
                let actual = match validate_address(&bytes(vector, "input_hex")) {
                    Err(AddressError::InvalidPrefix) => "invalid_prefix",
                    result => panic!("unexpected address validation result {result:?}"),
                };
                assert_eq!(actual, text(vector, "error"));
            }
            id => {
                let engine = engine(id);
                let payload = bytes(vector, "payload_hex");
                assert_eq!(encode_base58check(engine, &payload), text(vector, "encoded"));
                assert_eq!(decode_base58check(engine, text(vector, "encoded")).unwrap(), payload);
            }
        }
    }
}

#[test]
fn java_oracle_wire_boundary_vectors() {
    for vector in Oracle::load().vectors("java_oracle_wire_boundary_vectors") {
        let length: usize = text(vector, "id").rsplit('_').next().unwrap().parse().unwrap();
        let mut wire = vec![0; length];
        if length >= 64 { wire[31] = 1; wire[63] = 1; }
        let actual = match RecoverableSignature::from_ingress_wire(&wire) {
            Ok(_) => "accepted",
            Err(CryptoError::InvalidSignatureLength) => "signature_format",
            result => panic!("unexpected ingress result {result:?}"),
        };
        assert_eq!(actual, text(vector, "expected"));
    }
}

#[test]
fn fork_aware_permission_duplicate_vectors() {
    let oracle = Oracle::load();
    let permission_vectors = oracle.vectors("fork_aware_permission_duplicate_vectors");
    let expected = |id| text(permission_vectors.iter().copied().find(|vector| text(vector, "id") == id).unwrap(), "expected");
    assert_eq!(permission_vectors.len(), 4);
    let private = array::<32>(oracle.vector("C004.KEY.SECP256K1"), "private_key_hex");
    let hash = [0x42; 32];
    let key = Secp256k1Key::from_private_bytes(&private).unwrap();
    let low = key.sign_prehash(&hash).unwrap();
    let order = decode_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").try_into().unwrap();
    let high = RecoverableSignature { r: low.r, s: subtract(order, low.s), recovery_id: low.recovery_id ^ 1 };
    let address = derive_address(&PublicKey::Secp256k1(key.public_key()));
    let mut other_private = private;
    other_private[31] += 1;
    let other = Secp256k1Key::from_private_bytes(&other_private).unwrap();
    let other_address = derive_address(&PublicKey::Secp256k1(other.public_key()));
    let keys = [PermissionKey { address, weight: 7 }, PermissionKey { address: other_address, weight: 11 }];
    let signatures = [low.to_wire().to_vec(), high.to_wire().to_vec()];

    assert_eq!(expected("C004.PERMISSION.DUPLICATE_PRE_471"), "canonical_signature_identity");
    let pre = recover_permission_weight(CryptoEngine::Secp256k1, &hash, &signatures, &keys, DuplicateSignerPolicy::CanonicalSignature).unwrap();
    assert_eq!((pre.current_weight, pre.approved), (14, vec![address, address]));
    assert_eq!(expected("C004.PERMISSION.DUPLICATE_POST_471"), "recovered_address_identity");
    assert_eq!(recover_permission_weight(CryptoEngine::Secp256k1, &hash, &signatures, &keys, DuplicateSignerPolicy::RecoveredAddress), Err(PermissionError::DuplicateSigner));

    let nonmember = other.sign_prehash(&hash).unwrap().to_wire();
    let nonmember_result = recover_permission_weight(CryptoEngine::Secp256k1, &hash, &[nonmember], &[PermissionKey { address, weight: 7 }], DuplicateSignerPolicy::RecoveredAddress);
    assert_eq!(nonmember_result, Err(PermissionError::SignerNotInPermission));
    assert_eq!(expected("C004.PERMISSION.NONMEMBER"), "signer_not_in_permission");
    let too_many = recover_permission_weight(CryptoEngine::Secp256k1, &hash, &signatures, &[PermissionKey { address, weight: 7 }], DuplicateSignerPolicy::CanonicalSignature);
    assert_eq!(too_many, Err(PermissionError::TooManySignatures));
    assert_eq!(expected("C004.PERMISSION.TOO_MANY"), "too_many_signatures");
}

#[test]
fn both_engines_recover_padded_permission_signatures() {
    let oracle = Oracle::load();
    let vector = oracle.vectors("both_engines_recover_padded_permission_signatures");
    assert_eq!(vector.len(), 1);
    assert_eq!(text(vector[0], "expected"), "accepted_ignore_trailing");
    let hash = [0x24; 32];
    for (id, weight, padding) in [("C004.KEY.SECP256K1", 3, 4), ("C004.KEY.SM2", 5, 16)] {
        let key_vector = oracle.vector(id);
        let engine = engine(id);
        let key = PrivateKey::from_bytes(engine, &bytes(key_vector, "private_key_hex")).unwrap();
        let signature = match &key {
            PrivateKey::Secp256k1(key) => key.sign_prehash(&hash).unwrap(),
            PrivateKey::Sm2(key) => key.sign_prehash_with_rng(&hash, &mut FixedRng([2; 32])).unwrap(),
        };
        let address = derive_address(&key.public_key());
        let mut padded = signature.to_wire().to_vec();
        padded.resize(65 + padding, 9);
        let result = recover_permission_weight(engine, &hash, &[padded], &[PermissionKey { address, weight }], DuplicateSignerPolicy::RecoveredAddress).unwrap();
        assert_eq!(result.current_weight, weight);
    }
}

#[test]
fn java_oracle_contract_formula_vectors() {
    for vector in Oracle::load().vectors("java_oracle_contract_formula_vectors") {
        let actual = match text(vector, "id") {
            "C004.FORMULA.TOP_LEVEL" => top_level_contract_address(
                &TransactionId::new(Hash32::from_array(array(vector, "txid_hex"))),
                &TronAddress21::validate_mainnet(&bytes(vector, "owner_hex")).unwrap(),
            ),
            "C004.FORMULA.CREATE.POSITIVE" | "C004.FORMULA.CREATE.NEGATIVE" => internal_create_address(
                &TransactionId::new(Hash32::from_array(array(vector, "root_txid_hex"))), vector["nonce"].number(),
            ),
            "C004.FORMULA.CREATE2" => create2_address(
                &TronAddress21::validate_mainnet(&bytes(vector, "creator_hex")).unwrap(),
                &Hash32::from_array(array(vector, "salt_hex")), &bytes(vector, "init_code_hex"),
            ),
            id => panic!("unhandled formula oracle vector {id}"),
        };
        assert_eq!(actual.as_bytes(), bytes(vector, "address_hex"));
    }
}

fn subtract(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let value = i16::from(left[index]) - i16::from(right[index]) - borrow;
        out[index] = value.rem_euclid(256) as u8;
        borrow = i16::from(value < 0);
    }
    out
}

struct FixedRng([u8; 32]);
impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 { u32::from_be_bytes(self.0[..4].try_into().unwrap()) }
    fn next_u64(&mut self) -> u64 { u64::from_be_bytes(self.0[..8].try_into().unwrap()) }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.copy_from_slice(&self.0[..dest.len()]); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> { self.fill_bytes(dest); Ok(()) }
}
impl CryptoRng for FixedRng {}
