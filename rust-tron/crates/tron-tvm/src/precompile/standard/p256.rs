use p256::{EncodedPoint, FieldBytes};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::ecdsa::signature::hazmat::PrehashVerifier;

pub(super) fn verify(input:&[u8])->Vec<u8>{
    if input.len()!=160{return Vec::new()}
    let Ok(signature)=Signature::from_scalars(FieldBytes::clone_from_slice(&input[32..64]),FieldBytes::clone_from_slice(&input[64..96]))else{return Vec::new()};
    let mut sec1=[0u8;65];sec1[0]=4;sec1[1..33].copy_from_slice(&input[96..128]);sec1[33..].copy_from_slice(&input[128..160]);
    let Ok(point)=EncodedPoint::from_bytes(sec1)else{return Vec::new()};
    let Ok(key)=VerifyingKey::from_encoded_point(&point)else{return Vec::new()};
    if key.verify_prehash(&input[..32],&signature).is_err(){return Vec::new()}
    let mut out=vec![0;32];out[31]=1;out
}
