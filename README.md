## Sparse Merkle Tree

### Purpose of Sparse Merkle Trees

Sparse Merkle Tree (SMT) is a cryptographic data structure that extends the Merkle Tree concept to efficiently
handle sparse key-value mappings. Its key innovation is the ability to prove both the presence and absence of values

##### Structure:

* Fixed-depth binary tree (typically 256 levels for 256-bit hashes)
* Each leaf position represents a possible key in the key space
* Non-empty leaves store actual values; empty leaves contain a default value

##### Key Features:

**Sparseness**: Can represent a huge key space (2^256) while storing only populated entries

**Default Optimization**: Uses pre-computed default node hashes to avoid storing empty subtrees

**Non-inclusion Proofs**: Can cryptographically prove that a key is not in the tree

**Deterministic**: Same key-value pairs always produce identical root hashes

**Key-Value Storage**: Each leaf represents a key-value pair where:
* key determines the path from root to leaf
* value is stored at the leaf

##### Advantages over Regular Merkle Trees:

* More efficient for sparse datasets
* Native support for non-existence proofs

### List of Required Functionality

The library should include:

1. Core Features:
    * Insert key-value pairs
    * Generate merkle proofs
    * Verify proofs

2. Optimizations:
    * Pre-computed empty nodes
    * Path-based node addressing

3. Security:
    * SHA-256 for hashing
    * Fixed tree depth

4. Additional Features (optional):
    * Batch updates
    * Serialization/deserialization
    * Iterator over entries
    * Deletion support

### Testing Strategy

The library should include unit tests and benchmark suite using built in Rust testing tools.

The test suite should test:

1. Basic Functionality
   * Single insertion and verification
   * Multiple insertions
   * Updating existing keys
   * Non-existent key proofs
2. Edge Cases
   * Empty keys and values
   * Invalid proof lengths
   * Large values
   * Wrong keys/values
3. Consistency
   * Root hash consistency
   * Deterministic behavior
4. Performance
   * Insertion
   * Proof verification

### Proposed Architecture

For hashing should be used `sha2` crate, which provides SHA256 implementation.

The library should store the SMT as a prefix tree of SHA256 hashes.

The key value store should be implemented as a `HashMap` from the Rust standard library. 


