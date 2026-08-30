use rand_core::{CryptoRng, OsRng, RngCore};
use sm2::{EncodedPoint, FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
use sm2::elliptic_curve::PrimeField;
use sm2::elliptic_curve::group::Group;
use sm2::elliptic_curve::ops::{MulByGenerator, Reduce};
use sm2::elliptic_curve::point::AffineCoordinates;
use sm2::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use sm3::{Digest, Sm3};

use crate::signature::{CryptoError, RecoverableSignature, prehash};

const MAX_NONCE_ATTEMPTS: usize = 128;

#[derive(Clone)]
pub struct Sm2Key { secret: SecretKey }

impl Sm2Key {
    pub fn generate() -> Self { Self { secret: SecretKey::random(&mut OsRng) } }

    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        SecretKey::from_slice(bytes).map(|secret| Self { secret }).map_err(|_| CryptoError::InvalidPrivateKey)
    }

    pub fn private_bytes(&self) -> [u8; 32] { self.secret.to_bytes().into() }

    pub(crate) fn with_private_bytes<T>(&self, use_bytes: impl FnOnce(&[u8]) -> T) -> T {
        let bytes = zeroize::Zeroizing::new(self.secret.to_bytes());
        use_bytes(bytes.as_slice())
    }

    pub fn public_key(&self) -> Sm2PublicKey { Sm2PublicKey(self.secret.public_key()) }

    pub fn sign_prehash(&self, hash: &[u8]) -> Result<RecoverableSignature, CryptoError> {
        self.sign_prehash_with_rng(hash, &mut OsRng)
    }

    pub fn sign_prehash_with_rng<R: RngCore + CryptoRng>(&self, hash: &[u8], rng: &mut R) -> Result<RecoverableSignature, CryptoError> {
        let hash = prehash(hash)?;
        let e = Scalar::reduce_bytes(FieldBytes::from_slice(hash));
        let d = *self.secret.to_nonzero_scalar().as_ref();
        let d_plus_one_inv = Option::<Scalar>::from((d + Scalar::ONE).invert())
            .ok_or(CryptoError::InvalidPrivateKey)?;

        for _ in 0..MAX_NONCE_ATTEMPTS {
            let mut nonce_bytes = [0; 32];
            rng.try_fill_bytes(&mut nonce_bytes).map_err(|_| CryptoError::RandomnessExhausted)?;
            let Some(k) = Option::<Scalar>::from(Scalar::from_repr(nonce_bytes.into())) else { continue };
            if bool::from(k.is_zero()) { continue; }
            let point = ProjectivePoint::mul_by_generator(&k).to_affine();
            let r = e + Scalar::reduce_bytes(&point.x());
            if bool::from(r.is_zero()) || r + k == Scalar::ZERO { continue; }
            let s = d_plus_one_inv * (k - r * d);
            if bool::from(s.is_zero()) { continue; }
            let mut candidate = RecoverableSignature {
                r: r.to_repr().into(),
                s: s.to_repr().into(),
                recovery_id: u8::from(bool::from(point.y_is_odd())),
            };
            // Java emits only v=27/28. Confirm the parity candidate recovers this key.
            if Sm2PublicKey::recover_prehash(hash, &candidate).as_ref() == Ok(&self.public_key()) {
                return Ok(candidate);
            }
            candidate.recovery_id ^= 1;
            if Sm2PublicKey::recover_prehash(hash, &candidate).as_ref() == Ok(&self.public_key()) {
                return Ok(candidate);
            }
        }
        Err(CryptoError::RandomnessExhausted)
    }

    /// Java-compatible message path: SM3(Z || message), where Z deliberately
    /// omits the distinguishing user ID used by standard SM2 APIs.
    pub fn sign_message_with_rng<R: RngCore + CryptoRng>(&self, message: &[u8], rng: &mut R) -> Result<RecoverableSignature, CryptoError> {
        let hash = self.public_key().message_prehash_without_user_id(message);
        self.sign_prehash_with_rng(&hash, rng)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sm2PublicKey(PublicKey);

impl Sm2PublicKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        PublicKey::from_sec1_bytes(bytes).map(Self).map_err(|_| CryptoError::InvalidPublicKey)
    }

    pub fn from_node_id(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 { return Err(CryptoError::InvalidNodeId); }
        let mut encoded = [0; 65];
        encoded[0] = 4;
        encoded[1..].copy_from_slice(bytes);
        Self::from_sec1_bytes(&encoded).map_err(|_| CryptoError::InvalidNodeId)
    }

    pub fn to_uncompressed_sec1(&self) -> [u8; 65] {
        self.0.to_encoded_point(false).as_bytes().try_into().expect("uncompressed sec1 length")
    }

    pub fn to_compressed_sec1(&self) -> [u8; 33] {
        self.0.to_encoded_point(true).as_bytes().try_into().expect("compressed sec1 length")
    }

    pub fn node_id(&self) -> [u8; 64] { self.to_uncompressed_sec1()[1..].try_into().expect("node id length") }

    pub fn verify_prehash(&self, hash: &[u8], signature: &RecoverableSignature) -> Result<(), CryptoError> {
        let hash = prehash(hash)?;
        let (r, s) = signature_scalars(signature)?;
        let t = r + s;
        if bool::from(t.is_zero()) { return Err(CryptoError::InvalidSignature); }
        let point = ProjectivePoint::mul_by_generator(&s) + ProjectivePoint::from(*self.0.as_affine()) * t;
        if bool::from(point.is_identity()) { return Err(CryptoError::InvalidSignature); }
        let calculated = Scalar::reduce_bytes(&point.to_affine().x()) + Scalar::reduce_bytes(FieldBytes::from_slice(hash));
        if calculated == r { Ok(()) } else { Err(CryptoError::InvalidSignature) }
    }

    pub fn recover_prehash(hash: &[u8], signature: &RecoverableSignature) -> Result<Self, CryptoError> {
        let hash = prehash(hash)?;
        if signature.recovery_id > 3 { return Err(CryptoError::InvalidRecoveryId); }
        let (r, s) = signature_scalars(signature)?;
        let e = Scalar::reduce_bytes(FieldBytes::from_slice(hash));
        let x = r - e;
        // The high recovery bit adds the group order before point decompression.
        let mut x_bytes: [u8; 32] = x.to_repr().into();
        if signature.recovery_id >= 2 {
            x_bytes = add_order(x_bytes).ok_or(CryptoError::RecoveryFailed)?;
        }
        if x_bytes >= SM2_FIELD_MODULUS { return Err(CryptoError::RecoveryFailed); }
        let mut compressed = [0; 33];
        compressed[0] = 2 + (signature.recovery_id & 1);
        compressed[1..].copy_from_slice(&x_bytes);
        let encoded = EncodedPoint::from_bytes(compressed).map_err(|_| CryptoError::RecoveryFailed)?;
        let affine: sm2::AffinePoint = Option::from(sm2::AffinePoint::from_encoded_point(&encoded))
            .ok_or(CryptoError::RecoveryFailed)?;
        let denominator = r + s;
        let inverse = Option::<Scalar>::from(denominator.invert()).ok_or(CryptoError::RecoveryFailed)?;
        let public = (ProjectivePoint::from(affine) - ProjectivePoint::mul_by_generator(&s)) * inverse;
        if bool::from(public.is_identity()) { return Err(CryptoError::RecoveryFailed); }
        PublicKey::from_affine(public.to_affine()).map(Self).map_err(|_| CryptoError::RecoveryFailed)
    }

    pub fn message_prehash_without_user_id(&self, message: &[u8]) -> [u8; 32] {
        const PARAMETERS: [u8; 128] = hex_parameters();
        let public = self.node_id();
        let mut z = Sm3::new();
        z.update(PARAMETERS);
        z.update(public);
        let z: [u8; 32] = z.finalize().into();
        let mut digest = Sm3::new();
        digest.update(z);
        digest.update(message);
        digest.finalize().into()
    }

    pub fn verify_message_without_user_id(&self, message: &[u8], signature: &RecoverableSignature) -> Result<(), CryptoError> {
        self.verify_prehash(&self.message_prehash_without_user_id(message), signature)
    }
}

fn signature_scalars(signature: &RecoverableSignature) -> Result<(Scalar, Scalar), CryptoError> {
    if signature.recovery_id > 3 { return Err(CryptoError::InvalidRecoveryId); }
    let r = Option::<Scalar>::from(Scalar::from_repr(signature.r.into())).ok_or(CryptoError::InvalidSignature)?;
    let s = Option::<Scalar>::from(Scalar::from_repr(signature.s.into())).ok_or(CryptoError::InvalidSignature)?;
    if bool::from(r.is_zero() | s.is_zero()) { return Err(CryptoError::InvalidSignature); }
    Ok((r, s))
}

const SM2_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23,
];
const SM2_FIELD_MODULUS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn add_order(mut value: [u8; 32]) -> Option<[u8; 32]> {
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = u16::from(value[index]) + u16::from(SM2_ORDER[index]) + carry;
        value[index] = sum as u8;
        carry = sum >> 8;
    }
    if carry == 0 { Some(value) } else { None }
}

const fn hex_parameters() -> [u8; 128] {
    // a || b || Gx || Gy; parsed at compile time without an extra dependency.
    const HEX: &[u8; 256] = b"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E9332C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = (hex_nibble(HEX[i * 2]) << 4) | hex_nibble(HEX[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(value: u8) -> u8 {
    match value { b'0'..=b'9' => value - b'0', b'A'..=b'F' => value - b'A' + 10, _ => 0 }
}
