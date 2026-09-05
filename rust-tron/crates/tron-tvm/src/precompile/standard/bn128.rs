use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G1, G2, Group, pairing};

fn pad(input:&[u8],start:usize)->[u8;32]{let mut out=[0;32];if start<input.len(){let n=32.min(input.len()-start);out[..n].copy_from_slice(&input[start..start+n]);}out}
fn fq(bytes:[u8;32])->Option<Fq>{Fq::from_slice(&bytes).ok()}
fn g1(input:&[u8],off:usize)->Option<G1>{let x=fq(pad(input,off))?;let y=fq(pad(input,off+32))?;if x==Fq::zero()&&y==Fq::zero(){Some(G1::zero())}else{AffineG1::new(x,y).map(G1::from).ok()}}
fn encode(p:G1)->Vec<u8>{if p==G1::zero(){return vec![0;64]}let a=AffineG1::from_jacobian(p).expect("nonzero");let mut out=vec![0;64];a.x().to_big_endian(&mut out[..32]).expect("fixed");a.y().to_big_endian(&mut out[32..]).expect("fixed");out}
pub(super) fn add(input:&[u8])->(bool,Vec<u8>){let Some(a)=g1(input,0)else{return (false,Vec::new())};let Some(b)=g1(input,64)else{return (false,Vec::new())};(true,encode(a+b))}
pub(super) fn mul(input:&[u8])->(bool,Vec<u8>){let Some(a)=g1(input,0)else{return (false,Vec::new())};let Ok(s)=Fr::from_slice(&pad(input,64))else{return (false,Vec::new())};(true,encode(a*s))}
fn g2(input:&[u8],off:usize)->Option<G2>{let bx=fq(pad(input,off))?;let ax=fq(pad(input,off+32))?;let by=fq(pad(input,off+64))?;let ay=fq(pad(input,off+96))?;let x=Fq2::new(ax,bx);let y=Fq2::new(ay,by);if x==Fq2::zero()&&y==Fq2::zero(){Some(G2::zero())}else{AffineG2::new(x,y).map(G2::from).ok()}}
pub(super) fn pair(input:&[u8])->(bool,Vec<u8>){if input.len()%192!=0{return (false,Vec::new())}let mut acc=substrate_bn::Gt::one();for chunk in input.chunks_exact(192){let Some(a)=g1(chunk,0)else{return (false,Vec::new())};let Some(b)=g2(chunk,64)else{return (false,Vec::new())};acc=acc*pairing(a,b);}let mut out=vec![0;32];if acc==substrate_bn::Gt::one(){out[31]=1}(true,out)}
