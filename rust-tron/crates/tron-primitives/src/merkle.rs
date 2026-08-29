use crate::types::{DigestProvider, Hash32};

/// Computes the Java `MerkleTree` root using an injected digest engine.
///
/// An empty tree has the all-zero root. An unpaired node is promoted unchanged;
/// paired nodes are hashed as the exact 64-byte `left || right` sequence.
pub fn merkle_root<D: DigestProvider>(digest: &D, leaves: &[Hash32]) -> Result<Hash32, D::Error> {
    if leaves.is_empty() {
        return Ok(Hash32::ZERO);
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut parents = Vec::with_capacity((level.len() + 1) / 2);
        let mut pairs = level.chunks_exact(2);
        for pair in &mut pairs {
            parents.push(digest.digest_pair(&pair[0], &pair[1])?);
        }
        if let Some(last) = pairs.remainder().first() {
            parents.push(*last);
        }
        level = parents;
    }
    Ok(level[0])
}
