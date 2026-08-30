use crate::{Result, ShieldedError, primitives::{empty_root, merkle_hash, parse_node}};

#[derive(Clone,Debug,Eq,PartialEq)] pub struct JavaMerklePath { pub siblings:Vec<[u8;32]>, pub position:u64 }
impl JavaMerklePath {
    pub fn encode(&self)->Result<Vec<u8>> { if self.siblings.len()>252{return Err(ShieldedError::InvalidParameter("authentication path is too deep".into()))} let mut out=Vec::with_capacity(1+self.siblings.len()*33+8); out.push(self.siblings.len() as u8); for sibling in self.siblings.iter().rev(){out.push(0x20);out.extend_from_slice(sibling)} out.extend_from_slice(&self.position.to_le_bytes()); Ok(out) }
    pub fn decode(bytes:&[u8])->Result<Self> { if bytes.is_empty(){return Err(ShieldedError::InvalidEncoding("Merkle path"))} let depth=bytes[0] as usize; let expected=1+depth*33+8; if bytes.len()!=expected{return Err(ShieldedError::InvalidParameter(format!("param length must be {expected}")))} let mut top_down=Vec::with_capacity(depth); for i in 0..depth { let start=1+i*33; if bytes[start]!=0x20{return Err(ShieldedError::InvalidParameter(format!("param {} not equals:32",bytes[start] as i8)))} let node:[u8;32]=bytes[start+1..start+33].try_into().expect("fixed slice"); parse_node(&node)?; top_down.push(node); } let position=u64::from_le_bytes(bytes[1+depth*33..].try_into().expect("fixed slice")); top_down.reverse(); Ok(Self{siblings:top_down,position}) }
    pub fn root(&self,leaf:[u8;32])->Result<[u8;32]> { let mut root=leaf; for (depth,sibling) in self.siblings.iter().enumerate(){root=if (self.position>>depth)&1==0{merkle_hash(depth,root,*sibling)?}else{merkle_hash(depth,*sibling,root)?};} Ok(root) }
}

#[derive(Clone,Debug)] pub struct IncrementalMerkleTree { depth:u8, leaves:Vec<[u8;32]> }
impl IncrementalMerkleTree {
    pub fn new(depth:u8)->Result<Self>{if depth==0||depth>32{return Err(ShieldedError::InvalidParameter("tree depth must be between 1 and 32".into()))}Ok(Self{depth,leaves:Vec::new()})}
    pub fn depth(&self)->u8{self.depth} pub fn len(&self)->usize{self.leaves.len()} pub fn is_empty(&self)->bool{self.leaves.is_empty()} pub fn is_full(&self)->bool{(self.leaves.len() as u64)==(1u64<<self.depth)}
    pub fn append(&mut self,node:[u8;32])->Result<()> {parse_node(&node)?;if self.is_full(){return Err(ShieldedError::TreeFull)}self.leaves.push(node);Ok(())}
    pub fn last(&self)->Result<[u8;32]>{self.leaves.last().copied().ok_or(ShieldedError::EmptyTree)}
    pub fn root(&self)->Result<[u8;32]>{root_for(&self.leaves,self.depth)}
    pub fn witness(&self)->Result<IncrementalWitness>{if self.is_empty(){return Err(ShieldedError::InvalidParameter("can't create an authentication path for the beginning of the tree".into()))}Ok(IncrementalWitness{depth:self.depth,position:(self.leaves.len()-1) as u64,leaves:self.leaves.clone()})}
    pub fn encode_java(&self)->Vec<u8>{let mut out=Vec::with_capacity(2+self.leaves.len()*33);out.push(self.depth);out.push(self.leaves.len() as u8);for n in &self.leaves{out.push(0x20);out.extend_from_slice(n)}out}
    pub fn decode_java(bytes:&[u8])->Result<Self>{if bytes.len()<2{return Err(ShieldedError::InvalidEncoding("Merkle tree"))}let depth=bytes[0];let count=bytes[1] as usize;if bytes.len()!=2+count*33{return Err(ShieldedError::InvalidEncoding("Merkle tree"))}let mut tree=Self::new(depth)?;for i in 0..count{let p=2+i*33;if bytes[p]!=0x20{return Err(ShieldedError::InvalidParameter(format!("param {} not equals:32",bytes[p] as i8)))}tree.append(bytes[p+1..p+33].try_into().expect("fixed slice"))?}Ok(tree)}
}
#[derive(Clone,Debug)] pub struct IncrementalWitness { depth:u8,position:u64,leaves:Vec<[u8;32]> }
impl IncrementalWitness {
    pub fn append(&mut self,node:[u8;32])->Result<()> {if (self.leaves.len() as u64)==(1u64<<self.depth){return Err(ShieldedError::TreeFull)}parse_node(&node)?;self.leaves.push(node);Ok(())}
    pub fn position(&self)->u64{self.position}
    pub fn element(&self)->[u8;32]{self.leaves[self.position as usize]}
    pub fn root(&self)->Result<[u8;32]>{root_for(&self.leaves,self.depth)}
    pub fn path(&self)->Result<JavaMerklePath>{path_for(&self.leaves,self.depth,self.position as usize)}
    pub fn to_voucher(&self)->IncrementalMerkleVoucher{
        let next_position=self.leaves.len() as u64;
        let (cursor_depth,cursor)=if next_position>self.position+1 {
            let level=(63-(self.position^(next_position-1)).leading_zeros()) as usize;
            let start=((self.position>>(level+1))<<(level+1))+(1u64<<level);
            (Some(level),self.leaves[start as usize..].to_vec())
        } else {(None,Vec::new())};
        IncrementalMerkleVoucher{element:self.element(),path:self.path().expect("valid witness path"),next_position,cursor_depth,cursor}
    }
}
#[derive(Clone,Debug)]
pub struct IncrementalMerkleVoucher {
    element:[u8;32],
    path:JavaMerklePath,
    next_position:u64,
    cursor_depth:Option<usize>,
    cursor:Vec<[u8;32]>,
}
impl IncrementalMerkleVoucher {
    pub fn append(&mut self,node:[u8;32])->Result<()> {
        parse_node(&node)?;
        let depth=self.path.siblings.len();
        if depth>=64 || self.next_position >= (1u64<<depth) { return Err(ShieldedError::TreeFull); }
        let differing=self.path.position^self.next_position;
        let cursor_depth=(63-differing.leading_zeros()) as usize;
        if cursor_depth>=depth || ((self.path.position>>cursor_depth)&1)!=0 { return Err(ShieldedError::TreeFull); }
        if self.cursor_depth!=Some(cursor_depth) { self.cursor.clear(); self.cursor_depth=Some(cursor_depth); }
        self.cursor.push(node);
        self.path.siblings[cursor_depth]=root_for(&self.cursor,cursor_depth as u8)?;
        self.next_position+=1;
        Ok(())
    }
    pub fn root(&self)->Result<[u8;32]>{self.path.root(self.element)}
    pub fn path(&self)->Result<JavaMerklePath>{Ok(self.path.clone())}
    pub fn element(&self)->[u8;32]{self.element}
    pub fn position(&self)->u64{self.path.position}
    pub fn encode_java(&self)->Result<Vec<u8>>{self.path.encode()}
    pub fn decode_java(element:[u8;32],bytes:&[u8])->Result<Self>{
        parse_node(&element)?;
        let path=JavaMerklePath::decode(bytes)?;
        let depth=path.siblings.len();
        let position=path.position;
        if depth>=64 || position >= (1u64<<depth) { return Err(ShieldedError::InvalidParameter("Merkle path position exceeds its depth".into())); }
        let mut next_position=position+1;
        for (level,sibling) in path.siblings.iter().enumerate() {
            if ((position>>level)&1)==0 && *sibling!=empty_root(level as u8)? && next_position%(1u64<<(level+1))!=0 { next_position=(next_position+(1u64<<(level+1))-1)&!((1u64<<(level+1))-1); }
        }
        Ok(Self{element,path,next_position,cursor_depth:None,cursor:Vec::new()})
    }
}
fn root_for(leaves:&[[u8;32]],depth:u8)->Result<[u8;32]>{if leaves.is_empty(){return empty_root(depth)}let mut level=leaves.to_vec();for d in 0..depth as usize{if level.len()%2==1{level.push(empty_root(d as u8)?)}level=level.chunks_exact(2).map(|p|merkle_hash(d,p[0],p[1])).collect::<Result<Vec<_>>>()?;}Ok(level[0])}
fn path_for(leaves:&[[u8;32]],depth:u8,position:usize)->Result<JavaMerklePath>{if position>=leaves.len(){return Err(ShieldedError::EmptyTree)}let mut idx=position;let mut level=leaves.to_vec();let mut siblings=Vec::with_capacity(depth as usize);for d in 0..depth as usize{let sibling=if idx^1<level.len(){level[idx^1]}else{empty_root(d as u8)?};siblings.push(sibling);if level.len()%2==1{level.push(empty_root(d as u8)?)}level=level.chunks_exact(2).map(|p|merkle_hash(d,p[0],p[1])).collect::<Result<Vec<_>>>()?;idx>>=1;}Ok(JavaMerklePath{siblings,position:position as u64})}
