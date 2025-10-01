## Sparse Merkle Tree (Rust, SHA-256)

This crate provides a simple, pragmatic implementation of a Sparse Merkle Tree (SMT) using SHA-256. It is optimized for clarity and correctness over storage efficiency and is suitable for educational purposes, experimentation, and use-cases where an in-memory map-backed SMT is appropriate.

### Key ideas
- The tree is sparse: absent nodes are treated as zero, derived from a precomputed chain of "zero hashes" (the leaf zero is `SHA256("")`, each upper level is `SHA256(zero, zero)`).
- The tree depth is fixed at construction. The code uses an internal `(level, index)` map to store only non-zero nodes.
- This crate uses a value-derived key: the key path for a value is `SHA256(value)` interpreted as a big-endian bitstring. The leaf stored is also `SHA256(value)`.

Note: Internally we convert the bit path to a `u128` index at each level. To avoid integer overflow, you should keep `depth <= 128` for this implementation.

---

## API overview

```rust
use SparseMerkleTree;

// Create a tree with a chosen depth (e.g., 128 or 256; this implementation supports up to 128 safely)
let mut t = SparseMerkleTree::new(128);

// Insert/update a value (key is derived as SHA256(value), leaf is SHA256(value))
t.update(b"my value");

// Get the current root
let root = t.root();

// Generate a membership proof for the value
let proof = t.prove(b"my value");

// Verify the proof (instance method; uses self.depth and self.root())
assert!(t.verify(b"my value", &proof));

// Non-membership: proof generated for a value not present should not verify
let absent = b"not present";
let proof_absent = t.prove(absent);
assert!(!t.verify(absent, &proof_absent));
```

### Public methods
- `SparseMerkleTree::new(depth: usize) -> Self`
- `SparseMerkleTree::root(&self) -> [u8; 32]`
- `SparseMerkleTree::update(&mut self, value: &[u8])`
- `SparseMerkleTree::prove(&self, value: &[u8]) -> Vec<[u8; 32]>`
- `SparseMerkleTree::verify(&self, value: &[u8], proof: &[[u8; 32]]) -> bool`

All methods use SHA-256 as the hashing function.

---

## Design details

### Hashing
- `Hash = [u8; 32]`
- Leaf hash: `H(value) = SHA256(value)`
- Internal node hash: `H(left, right) = SHA256(left || right)` (concatenation)
- Zero hashes: `zero[0] = SHA256("")`, and for level `i>0`: `zero[i] = H(zero[i-1], zero[i-1])`

### Key derivation and path
- Key bits are derived from the big-endian bit representation of `SHA256(value)`.
- The most-significant bit selects the left/right child at the root; subsequent bits select deeper levels.

### Storage model
- We store only non-zero nodes in `HashMap<(level, index), Hash>`.
- A node equal to the level’s zero hash is removed to keep the structure sparse.

### Proof format
- `prove(value)` returns sibling hashes from the leaf level up to (but not including) the root.
- `verify(value, proof)` walks upward from the leaf hash using the derived key bits to reconstruct the root and compares it to `self.root()`.

### Membership vs. non-membership
- Membership: For a value previously inserted via `update`, `verify(value, prove(value))` returns `true`.
- Non-membership: For a value that was not inserted, `verify(value, prove(value))` returns `false`.

Note on collisions: With small depths (e.g., 4–16), two different values can derive the same key path, meaning the newer update overwrites the older at that leaf. For production use, set a sufficiently large depth (commonly 256) and persist the map in a suitable storage.

---

## Complexity
- Update: `O(depth)`
- Prove: `O(depth)` siblings
- Verify: `O(depth)`

Memory scales with the number of non-zero nodes that diverge from the zero-hash defaults.

---

## Limitations and notes
- Depth should be `<= 128` in this implementation due to the `u128` index used for paths.
- This is an in-memory structure. For persistence or very large trees, you may want a database-backed storage for the node map and consider incremental hashing strategies.
- This implementation focuses on membership proofs. Non-membership proofs in classic SMTs may include additional data (e.g., neighbor leaf and its path); this crate treats non-membership as the failure of a membership verification for the given value.

---

## Example end-to-end

```rust
use SparseMerkleTree;

fn main() {
    let mut t = SparseMerkleTree::new(128);

    // Insert two values
    t.update(b"alice");
    t.update(b"bob");

    // Query root
    let root_before = t.root();

    // Prove membership for alice
    let proof_alice = t.prove(b"alice");
    assert!(t.verify(b"alice", &proof_alice));

    // Non-membership for charlie
    let proof_charlie = t.prove(b"charlie");
    assert!(!t.verify(b"charlie", &proof_charlie));

    // Update again and see the root change
    t.update(b"charlie");
    let root_after = t.root();
    assert_ne!(root_before, root_after);
}
```

---



