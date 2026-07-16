//! A keccak256 Merkle tree with sorted, deduplicated leaves.
//!
//! ## Construction
//!
//! Leaves are sorted ascending and deduplicated first, so the root and proofs are
//! independent of insertion order and repeated leaves. Build from an iterator via
//! [`MerkleTree::from_leaves`], or incrementally with a [`MerkleTreeBuilder`]
//! ([`MerkleTree::builder`] then [`MerkleTreeBuilder::commit`]).
//!
//! ## Hashing scheme
//!
//! Internal nodes use [`hash_pair`]: the two child hashes are concatenated in
//! ascending byte order and keccak256'd. This matches OpenZeppelin's sorted-pair
//! `MerkleProof`, so roots and proofs verify unchanged in Solidity. An odd
//! trailing node is paired with itself.
//!
//! Leaves are double-hashed: a [`LeafHash`] is `keccak256(keccak256(preimage))`,
//! as in OpenZeppelin's `StandardMerkleTree`.
//!
//! ## Second-preimage safety
//!
//! In a plain sorted-pair tree, leaves and internal nodes are indistinguishable
//! 32-byte values, so an interior node value can be presented where a leaf is
//! expected and still fold up to a valid root. Double-hashing separates the two
//! by hash-input width: an internal node is keccak256 of a 64-byte input
//! (`left || right`), a leaf is keccak256 of a 32-byte inner digest. The widths
//! are disjoint, so short of a collision no leaf can equal a node. Any preimage
//! length is safe, since the inner hash normalizes it to 32 bytes first.
//!
//! The type system holds the boundary: every leaf entry point takes a
//! [`LeafHash`], never a raw [`B256`], and a `LeafHash` comes only from
//! [`LeafHash::from_preimage`] — so a bare hash (e.g. an interior node read off
//! the tree) can never enter as a leaf.
//!
//! ## Proofs
//!
//! [`MerkleTree::proof`] returns the sibling hashes that recompute the root from
//! a leaf; [`verify_proof`] (or OpenZeppelin's `MerkleProof.verify`) checks one.

use std::collections::BTreeSet;

use alloy::primitives::{B256, keccak256};

/// Hash two child nodes into their parent: keccak256 of the two hashes
/// concatenated in ascending byte order, so the result is order-independent.
pub fn hash_pair(a: B256, b: B256) -> B256 {
    const HALF: usize = NODE_PREIMAGE_LEN / 2;
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut encoded = [0u8; NODE_PREIMAGE_LEN];
    encoded[..HALF].copy_from_slice(left.as_slice());
    encoded[HALF..].copy_from_slice(right.as_slice());
    keccak256(encoded)
}

/// Byte width of an internal-node preimage (two concatenated child hashes).
const NODE_PREIMAGE_LEN: usize = 2 * size_of::<B256>();

/// A double-hashed Merkle leaf value, `keccak256(keccak256(preimage))`.
///
/// The only value accepted as a tree leaf, constructible only via
/// [`LeafHash::from_preimage`]; see the module docs on second-preimage safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafHash(B256);

impl LeafHash {
    /// Derive a leaf value, `keccak256(keccak256(preimage))`. Accepts a preimage
    /// of any length.
    pub fn from_preimage(preimage: &[u8]) -> Self {
        Self(keccak256(keccak256(preimage)))
    }

    /// The underlying value, for use as a raw tree node.
    pub fn hash(self) -> B256 {
        self.0
    }
}

/// Verify that `proof` reconstructs `root` from `leaf`.
///
/// Folds each proof element into the running hash with [`hash_pair`]; the result
/// must equal `root`. Compatible with OpenZeppelin's `MerkleProof.verify`.
pub fn verify_proof(proof: &[B256], root: B256, leaf: LeafHash) -> bool {
    let computed = proof.iter().fold(leaf.hash(), |computed, sibling| {
        hash_pair(computed, *sibling)
    });
    computed == root
}

/// Incrementally collects leaves before committing them into a [`MerkleTree`].
#[derive(Debug, Clone, Default)]
pub struct MerkleTreeBuilder {
    leaves: BTreeSet<B256>,
}

impl MerkleTreeBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single leaf. Returns `true` if the leaf was not already present.
    pub fn insert(&mut self, leaf: LeafHash) -> bool {
        self.leaves.insert(leaf.hash())
    }

    /// Add many leaves at once.
    pub fn extend(&mut self, leaves: impl IntoIterator<Item = LeafHash>) {
        self.leaves.extend(leaves.into_iter().map(LeafHash::hash));
    }

    /// Number of distinct leaves added so far.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether no leaves have been added yet.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Finalize the builder, computing the tree levels and root.
    pub fn commit(self) -> MerkleTree {
        MerkleTree::from_sorted(self.leaves.into_iter().collect())
    }
}

/// A committed keccak256 Merkle tree over sorted, deduplicated leaves.
///
/// The node levels are precomputed at construction time, so [`MerkleTree::root`]
/// is `O(1)` and [`MerkleTree::proof`] only walks the height of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// Node levels, bottom-up: `levels[0]` are the sorted leaves and the last
    /// level holds the single root. Empty when the tree has no leaves.
    levels: Vec<Vec<B256>>,
}

impl MerkleTree {
    /// Build a tree from an iterator of leaves; sorted and deduplicated first.
    pub fn from_leaves(leaves: impl IntoIterator<Item = LeafHash>) -> Self {
        let sorted: Vec<B256> = leaves
            .into_iter()
            .map(LeafHash::hash)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self::from_sorted(sorted)
    }

    /// Start building a tree incrementally.
    pub fn builder() -> MerkleTreeBuilder {
        MerkleTreeBuilder::new()
    }

    /// Build the node levels from leaves that are already sorted and deduplicated.
    fn from_sorted(leaves: Vec<B256>) -> Self {
        if leaves.is_empty() {
            return Self { levels: Vec::new() };
        }

        let mut levels = vec![leaves];
        while levels
            .last()
            .expect("levels is non-empty by construction")
            .len()
            > 1
        {
            let level = levels.last().expect("checked non-empty above");
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                // Odd trailing node is paired with itself.
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                next.push(hash_pair(left, right));
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// The Merkle root, or [`B256::ZERO`] for an empty tree.
    pub fn root(&self) -> B256 {
        match self.levels.last() {
            Some(top) => top[0],
            None => B256::ZERO,
        }
    }

    /// The sorted, deduplicated leaves backing this tree.
    pub fn leaves(&self) -> &[B256] {
        self.levels.first().map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether `leaf` is one of the tree's leaves.
    pub fn contains(&self, leaf: LeafHash) -> bool {
        // Leaves are sorted, so a binary search is sufficient.
        self.leaves().binary_search(&leaf.hash()).is_ok()
    }

    /// Number of distinct leaves.
    pub fn len(&self) -> usize {
        self.leaves().len()
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }

    /// Produce a Merkle proof for `leaf`, or `None` if it is not in the tree.
    ///
    /// The returned siblings, folded with [`hash_pair`] starting from the leaf
    /// hash, reconstruct [`MerkleTree::root`]; see [`verify_proof`].
    pub fn proof(&self, leaf: LeafHash) -> Option<Vec<B256>> {
        let leaf = leaf.hash();
        let mut index = self.leaves().iter().position(|l| *l == leaf)?;
        let mut proof = Vec::with_capacity(self.levels.len().saturating_sub(1));

        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }
            let sibling = if index % 2 == 0 {
                // Even index: sibling is to the right, or self when trailing/odd.
                if index + 1 < level.len() {
                    index + 1
                } else {
                    index
                }
            } else {
                index - 1
            };
            proof.push(level[sibling]);
            index /= 2;
        }

        Some(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// An arbitrary 32-byte value, for exercising the raw-`B256` node helpers
    /// ([`hash_pair`]) that operate below the [`LeafHash`] layer.
    fn leaf(byte: u8) -> B256 {
        keccak256([byte])
    }

    /// A one-byte leaf as a [`LeafHash`], the type the tree and [`verify_proof`]
    /// accept. Its value is the double hash `keccak256(keccak256([byte]))`.
    fn leaf_hash(byte: u8) -> LeafHash {
        LeafHash::from_preimage(&[byte])
    }

    #[test]
    fn empty_tree_has_zero_root_and_no_proofs() {
        let tree = MerkleTree::from_leaves(Vec::<LeafHash>::new());
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root(), B256::ZERO);
        assert_eq!(tree.proof(leaf_hash(1)), None);
    }

    #[test]
    fn single_leaf_tree_is_its_own_root() {
        let only = leaf_hash(7);
        let tree = MerkleTree::from_leaves([only]);
        assert_eq!(tree.root(), only.hash());
        // A lone leaf needs no siblings to reach the root.
        assert_eq!(tree.proof(only), Some(Vec::new()));
        assert!(verify_proof(&[], tree.root(), only));
    }

    #[test]
    fn root_is_order_independent() {
        let a = leaf_hash(1);
        let b = leaf_hash(2);
        let c = leaf_hash(3);
        assert_eq!(
            MerkleTree::from_leaves([a, b, c]).root(),
            MerkleTree::from_leaves([c, a, b]).root(),
        );
    }

    #[test]
    fn duplicate_leaves_are_deduplicated() {
        let a = leaf_hash(1);
        let b = leaf_hash(2);
        assert_eq!(
            MerkleTree::from_leaves([a, b]).root(),
            MerkleTree::from_leaves([a, b, a, b, a]).root(),
        );
        assert_eq!(MerkleTree::from_leaves([a, a, a]).len(), 1);
    }

    #[test]
    fn builder_matches_from_leaves() {
        let leaves = [leaf_hash(5), leaf_hash(9), leaf_hash(1), leaf_hash(5)];
        let mut builder = MerkleTree::builder();
        for l in leaves {
            builder.insert(l);
        }
        assert_eq!(builder.len(), 3);
        let built = builder.commit();
        assert_eq!(built, MerkleTree::from_leaves(leaves));
    }

    #[test]
    fn builder_extend_matches_inserts() {
        let leaves = [leaf_hash(8), leaf_hash(2), leaf_hash(4)];
        let mut by_insert = MerkleTree::builder();
        for l in leaves {
            by_insert.insert(l);
        }
        let mut by_extend = MerkleTree::builder();
        by_extend.extend(leaves);
        assert_eq!(by_insert.commit(), by_extend.commit());
    }

    #[test]
    fn hash_pair_is_commutative() {
        let a = leaf(1);
        let b = leaf(2);
        assert_eq!(hash_pair(a, b), hash_pair(b, a));
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        // Use an odd leaf count to exercise the self-pairing branch.
        let leaves: Vec<LeafHash> = (0u8..5).map(leaf_hash).collect();
        let tree = MerkleTree::from_leaves(leaves.clone());
        let root = tree.root();
        for byte in 0u8..5 {
            let l = leaf_hash(byte);
            let proof = tree.proof(l).expect("leaf is in the tree");
            assert!(
                verify_proof(&proof, root, l),
                "proof failed for byte {byte}"
            );
        }
    }

    #[test]
    fn proof_for_absent_leaf_is_none() {
        let tree = MerkleTree::from_leaves([leaf_hash(1), leaf_hash(2)]);
        assert_eq!(tree.proof(leaf_hash(99)), None);
    }

    #[test]
    fn contains_reports_membership() {
        let tree = MerkleTree::from_leaves([leaf_hash(1), leaf_hash(2)]);
        assert!(tree.contains(leaf_hash(1)));
        assert!(!tree.contains(leaf_hash(3)));
    }

    #[test]
    fn proof_does_not_verify_against_wrong_root() {
        let tree = MerkleTree::from_leaves([leaf_hash(1), leaf_hash(2), leaf_hash(3)]);
        let target = leaf_hash(2);
        let proof = tree.proof(target).unwrap();
        let wrong_root =
            B256::from_str("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert!(!verify_proof(&proof, wrong_root, target));
    }

    #[test]
    fn leaf_domain_is_disjoint_from_internal_node_domain() {
        // A four-leaf tree has a genuine internal node at level 1. Its value is a
        // keccak256 of a 64-byte input (left || right); the double-hashed leaves
        // are keccak256 of a 32-byte input. The domains cannot overlap.
        let tree = MerkleTree::from_leaves((0u8..4).map(leaf_hash));
        let internal_node = tree.levels[1][0];

        // Reconstruct that node's exact 64-byte preimage from its two children
        // (levels[0] is sorted ascending, so this matches hash_pair's ordering).
        let (l, r) = (tree.levels[0][0], tree.levels[0][1]);
        let mut node_preimage = [0u8; NODE_PREIMAGE_LEN];
        node_preimage[..32].copy_from_slice(l.as_slice());
        node_preimage[32..].copy_from_slice(r.as_slice());
        assert_eq!(internal_node, keccak256(node_preimage), "sanity: real node");
        assert_eq!(internal_node, hash_pair(l, r));

        // Feeding the node's own 64-byte preimage through LeafHash double-hashes
        // its 32-byte digest, landing in the leaf domain, not on `internal_node`.
        assert_ne!(
            LeafHash::from_preimage(&node_preimage).hash(),
            internal_node
        );
    }

    #[test]
    fn from_preimage_double_hashes_any_width() {
        // Every width yields the OZ double hash, including the 64-byte case.
        for len in [0usize, 32, 63, 64, 65, 224] {
            let preimage = vec![0xABu8; len];
            assert_eq!(
                LeafHash::from_preimage(&preimage).hash(),
                keccak256(keccak256(&preimage)),
                "double hash mismatch at width {len}",
            );
        }
    }
}
