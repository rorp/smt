use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Compute SHA-256 of arbitrary bytes and return a 32-byte array.
fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    out.into()
}

/// Hash a pair of child hashes in the canonical left-right order.
fn hash_concat(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Convert a big-endian byte slice into a big-endian bit vector of length `depth`.
fn bits_from_bytes_be(bytes: &[u8], depth: usize) -> Vec<bool> {
    let mut out = Vec::with_capacity(depth);
    for &b in bytes {
        for i in (0..8).rev() {
            out.push(((b >> i) & 1) == 1);
            if out.len() == depth {
                return out;
            }
        }
    }
    while out.len() < depth {
        out.push(false);
    }
    out
}

#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    depth: usize,
    /// Map from (depth, index) -> node hash
    nodes: std::collections::HashMap<(usize, u128), Hash>,
    /// Precomputed zero hashes per level: zero_hashes[0] is leaf-zero
    zero_hashes: Vec<Hash>,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree.
    ///
    /// - `depth` is the number of bits in a key (e.g. 256 for 256-bit keys).
    /// - All absent nodes are implicitly zero, defined by `zero_hashes`.
    pub fn new(depth: usize) -> Self {
        let zero_leaf = sha256(&[]);
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        zero_hashes.push(zero_leaf);
        for i in 1..=depth {
            let prev = zero_hashes[i - 1];
            zero_hashes.push(hash_concat(&prev, &prev));
        }
        Self {
            depth,
            nodes: std::collections::HashMap::new(),
            zero_hashes,
        }
    }

    /// Compute the current root hash.
    pub fn root(&self) -> Hash {
        self.nodes
            .get(&(self.depth, 0u128))
            .copied()
            .unwrap_or(self.zero_hashes[self.depth])
    }

    /// Update a single key's leaf to `value_hash` (already hashed value) and recompute path.
    ///
    /// `key_bits` is a big-endian bitstring of length `self.depth` selecting the path
    /// from root to leaf (most significant bit first).
    fn update_hashed_value(&mut self, key_bits: &[bool], value_hash: Hash) {
        assert_eq!(key_bits.len(), self.depth);

        // Leaf index as u128 (supports up to 128-bit depth; for deeper trees we'd use BigUint)
        let mut idx: u128 = 0;
        for &bit in key_bits {
            idx = (idx << 1) | if bit { 1 } else { 0 };
        }

        // Set leaf
        let mut current = value_hash;
        self.set_node(0, idx, current);

        // Climb upwards
        let mut index_at_level = idx;
        for level in 0..self.depth {
            let is_right = (index_at_level & 1) == 1;
            let parent_index = index_at_level >> 1;
            let sibling_index = if is_right {
                index_at_level - 1
            } else {
                index_at_level + 1
            };

            let sibling = self.get_node(level, sibling_index);
            let (left, right) = if is_right {
                (sibling, current)
            } else {
                (current, sibling)
            };
            let parent = hash_concat(&left, &right);

            current = parent;
            self.set_node(level + 1, parent_index, parent);
            index_at_level = parent_index;
        }
    }

    /// Derive key bits as SHA-256(value) and set leaf to SHA-256(value).
    pub fn update(&mut self, value: &[u8]) {
        let value_hash = sha256(value);
        let key_bits = bits_from_bytes_be(&value_hash, self.depth);
        self.update_hashed_value(&key_bits, value_hash);
    }

    fn get_node(&self, level: usize, index: u128) -> Hash {
        if let Some(h) = self.nodes.get(&(level, index)) {
            *h
        } else {
            self.zero_hashes[level]
        }
    }

    fn set_node(&mut self, level: usize, index: u128, hash: Hash) {
        if hash == self.zero_hashes[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), hash);
        }
    }

    /// Generate a Merkle membership proof for `key_bits`.
    ///
    /// Returns a vector of sibling hashes from leaf level up to (but not including) the root.
    fn prove_by_key_bits(&self, key_bits: &[bool]) -> Vec<Hash> {
        assert_eq!(key_bits.len(), self.depth);
        let mut idx: u128 = 0;
        for &bit in key_bits {
            idx = (idx << 1) | if bit { 1 } else { 0 };
        }
        let mut proof = Vec::with_capacity(self.depth);
        let mut index_at_level = idx;
        for level in 0..self.depth {
            let is_right = (index_at_level & 1) == 1;
            let sibling_index = if is_right {
                index_at_level - 1
            } else {
                index_at_level + 1
            };
            let sibling = self.get_node(level, sibling_index);
            proof.push(sibling);
            index_at_level >>= 1;
        }
        proof
    }

    /// Generate a membership proof for a `value`, deriving key bits from SHA-256(value).
    pub fn prove(&self, value: &[u8]) -> Vec<Hash> {
        let value_hash = sha256(value);
        let key_bits = bits_from_bytes_be(&value_hash, self.depth);
        self.prove_by_key_bits(&key_bits)
    }

    /// Verify a Merkle membership proof.
    ///
    /// `proof` must have length `depth` and contain siblings from leaf to root order.
    fn verify_hashed_value(&self, key_bits: &[bool], value_hash: &Hash, proof: &[Hash]) -> bool {
        if key_bits.len() != self.depth || proof.len() != self.depth {
            return false;
        }
        let mut current = *value_hash;
        for (bit, sibling) in key_bits.iter().rev().zip(proof.iter()) {
            let (left, right) = if *bit {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = hash_concat(&left, &right);
        }
        &current == &self.root()
    }

    /// Verify a membership proof using only the raw value.
    /// Key bits are derived from SHA-256(value) and the leaf is SHA-256(value).
    pub fn verify(&self, value: &[u8], proof: &[Hash]) -> bool {
        let value_hash = sha256(value);
        let key_bits = bits_from_bytes_be(&value_hash, self.depth);
        self.verify_hashed_value(&key_bits, &value_hash, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::RngCore;

    #[test]
    fn empty_tree_root_is_zero_hash_at_depth() {
        let depth = 16;
        let t = SparseMerkleTree::new(depth);
        // recompute zero hashes similarly to constructor
        let zero_leaf = sha256(&[]);
        let mut zero_hashes = vec![zero_leaf];
        for i in 1..=depth {
            let prev = zero_hashes[i - 1];
            zero_hashes.push(hash_concat(&prev, &prev));
        }
        assert_eq!(t.root(), zero_hashes[depth]);
    }

    #[test]
    fn single_update_changes_root_and_proof_verifies() {
        let depth = 8;
        let mut t = SparseMerkleTree::new(depth);
        let value = b"hello";
        t.update(value);
        let proof = t.prove(value);
        assert!(t.verify(value, &proof));
    }

    #[test]
    fn different_keys_do_not_collide() {
        let depth = 8;
        let mut t = SparseMerkleTree::new(depth);
        t.update(b"a");
        let root1 = t.root();
        t.update(b"b");
        let root2 = t.root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn membership_positive() {
        let depth = 16;
        let mut t = SparseMerkleTree::new(depth);
        let v1 = b"member-1";
        let v2 = b"member-2";
        t.update(v1);
        t.update(v2);
        let proof1 = t.prove(v1);
        let proof2 = t.prove(v2);
        assert!(t.verify(v1, &proof1));
        assert!(t.verify(v2, &proof2));
    }

    #[test]
    fn non_membership_negative() {
        let depth = 16;
        let mut t = SparseMerkleTree::new(depth);
        let present = b"present";
        let absent = b"absent";
        t.update(present);
        let proof_absent = t.prove(absent);
        assert!(!t.verify(absent, &proof_absent));
        // Also ensure a random value not inserted fails
        let proof_present = t.prove(present);
        assert!(t.verify(present, &proof_present));
    }

    proptest! {
        #[test]
        fn random_updates_and_proofs(depth in 4usize..10) {
            let mut t = SparseMerkleTree::new(depth);
            let mut rng = rand::thread_rng();
            use std::collections::HashMap;
            let mut last_value_for_key: HashMap<Vec<bool>, [u8; 32]> = HashMap::new();
            for _ in 0..32 {
                let mut val = [0u8; 32];
                rng.fill_bytes(&mut val);
                t.update(&val);
                let key_bits = bits_from_bytes_be(&sha256(&val), depth);
                last_value_for_key.insert(key_bits, val);
            }
            for (_key_bits, val) in last_value_for_key.into_iter() {
                let proof = t.prove(&val);
                prop_assert!(t.verify(&val, &proof));
            }
        }
    }
}
