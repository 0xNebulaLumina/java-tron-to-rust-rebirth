use tron_shielded::{IncrementalMerkleTree,IncrementalMerkleVoucher,IncrementalWitness,JavaMerklePath,empty_root};

fn strings(name:&str)->Vec<String>{serde_json::from_str(match name{"commitments"=>include_str!("fixtures/merkle_commitments_sapling.json"),"roots"=>include_str!("fixtures/merkle_roots_sapling.json"),"paths"=>include_str!("fixtures/merkle_path_sapling.json"),"empty"=>include_str!("fixtures/merkle_roots_empty_sapling.json"),_=>unreachable!()}).unwrap()}
fn bytes<const N:usize>(s:&str)->[u8;N]{hex::decode(s).unwrap().try_into().unwrap()}

#[test]
fn java_merkle_roots_and_paths_match(){
 let commitments=strings("commitments");let roots=strings("roots");let expected_paths=strings("paths");let mut tree=IncrementalMerkleTree::new(4).unwrap();let mut witnesses:Vec<IncrementalWitness>=Vec::new();let mut path_index=0;
 for (i,encoded) in commitments.iter().enumerate(){let mut cm=bytes::<32>(encoded);cm.reverse();for witness in &mut witnesses{witness.append(cm).unwrap();}tree.append(cm).unwrap();assert_eq!(tree.root().unwrap(),bytes::<32>(&roots[i]));witnesses.push(tree.witness().unwrap());for witness in &witnesses[..witnesses.len()-1]{let encoded=witness.path().unwrap().encode().unwrap();assert_eq!(hex::encode(encoded),expected_paths[path_index]);path_index+=1}}
 assert_eq!(path_index,120);assert!(tree.append([1;32]).is_err());
}
#[test]
fn all_java_empty_roots_match(){for (depth,expected) in strings("empty").iter().enumerate(){assert_eq!(empty_root(depth as u8).unwrap(),bytes::<32>(expected));}}
#[test]
fn java_path_markers_endian_and_round_trip(){for encoded in strings("paths"){let raw=hex::decode(encoded).unwrap();let path=JavaMerklePath::decode(&raw).unwrap();assert_eq!(path.encode().unwrap(),raw);assert_eq!(&raw[raw.len()-8..],&path.position.to_le_bytes());}let mut bad=hex::decode(&strings("paths")[0]).unwrap();bad[1]=31;assert!(JavaMerklePath::decode(&bad).is_err());}

#[test]
fn java_voucher_decode_preserves_path_and_appends(){
 let fixture:serde_json::Value=serde_json::from_str(include_str!("fixtures/merkle_voucher_java.json")).unwrap();
 let field=|name:&str|fixture[name].as_str().unwrap();
 let mut element=bytes::<32>(field("element"));element.reverse();
 let encoded=hex::decode(field("path")).unwrap();
 let mut voucher=IncrementalMerkleVoucher::decode_java(element,&encoded).unwrap();
 assert_eq!(voucher.element(),element);assert_eq!(voucher.position(),fixture["position"].as_u64().unwrap());
 assert_eq!(voucher.encode_java().unwrap(),encoded);assert_eq!(voucher.root().unwrap(),bytes::<32>(field("root")));
 let mut appended=bytes::<32>(field("append"));appended.reverse();voucher.append(appended).unwrap();
 assert_eq!(voucher.root().unwrap(),bytes::<32>(field("root_after_append")));
 assert_eq!(voucher.path().unwrap().root(element).unwrap(),voucher.root().unwrap());
}
