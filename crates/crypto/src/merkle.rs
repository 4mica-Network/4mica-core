//! A keccak256 Merkle tree with sorted, deduplicated leaves.
//!
//! The tree is intentionally domain-agnostic: it operates purely on [`B256`]
//! leaf hashes and knows nothing about what those hashes represent. Callers are
//! responsible for deriving leaf hashes for their own domain.
//!
//! ## Construction
//!
//! Leaves are sorted ascending and deduplicated before the tree is built, so the
//! resulting root and proofs are independent of insertion order and of repeated
//! leaves. Build a tree either from an iterator of leaves via
//! [`MerkleTree::from_leaves`], or incrementally with a [`MerkleTreeBuilder`]
//! (see [`MerkleTree::builder`]) and finish with [`MerkleTreeBuilder::commit`].
//!
//! ## Hashing scheme
//!
//! Internal nodes are computed with [`hash_pair`], which concatenates the two
//! child hashes in ascending byte order before applying keccak256. This matches
//! OpenZeppelin's `MerkleProof` sorted-pair verification, so roots and proofs
//! produced here verify directly in Solidity. When a level has an odd number of
//! nodes, the final node is paired with itself.
//!
//! ## Proofs
//!
//! [`MerkleTree::proof`] returns the sibling hashes needed to recompute the root
//! from a single leaf. [`verify_proof`] (or OpenZeppelin's `MerkleProof.verify`
//! on-chain) checks such a proof against a known root.

use std::collections::BTreeSet;

use alloy::primitives::{B256, keccak256};

/// Hash two nodes into their parent using keccak256 over the ascending-ordered
/// concatenation of the two hashes.
///
/// Sorting the pair before hashing makes the result independent of left/right
/// ordering, matching OpenZeppelin's sorted-pair Merkle verification.
pub fn hash_pair(a: B256, b: B256) -> B256 {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(left.as_slice());
    encoded[32..].copy_from_slice(right.as_slice());
    keccak256(encoded)
}

/// Verify that `proof` reconstructs `root` starting from `leaf`.
///
/// This mirrors OpenZeppelin's `MerkleProof.verify`: each proof element is folded
/// into the running hash with [`hash_pair`], and the final hash must equal `root`.
pub fn verify_proof(proof: &[B256], root: B256, leaf: B256) -> bool {
    let computed = proof
        .iter()
        .fold(leaf, |computed, sibling| hash_pair(computed, *sibling));
    computed == root
}

/// Incrementally collects leaves before committing them into a [`MerkleTree`].
///
/// Leaves are stored in a [`BTreeSet`], so insertion order does not matter and
/// duplicates are dropped automatically.
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
    pub fn insert(&mut self, leaf: B256) -> bool {
        self.leaves.insert(leaf)
    }

    /// Add many leaves at once.
    pub fn extend(&mut self, leaves: impl IntoIterator<Item = B256>) {
        self.leaves.extend(leaves);
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
    /// Build a tree from an iterator of leaves.
    ///
    /// Leaves are sorted ascending and deduplicated before the tree is built.
    pub fn from_leaves(leaves: impl IntoIterator<Item = B256>) -> Self {
        let sorted: Vec<B256> = leaves
            .into_iter()
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
    pub fn contains(&self, leaf: B256) -> bool {
        // Leaves are sorted, so a binary search is sufficient.
        self.leaves().binary_search(&leaf).is_ok()
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
    /// The returned siblings, folded with [`hash_pair`] starting from `leaf`,
    /// reconstruct [`MerkleTree::root`]; see [`verify_proof`].
    pub fn proof(&self, leaf: B256) -> Option<Vec<B256>> {
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

    fn leaf(byte: u8) -> B256 {
        keccak256([byte])
    }

    #[test]
    fn empty_tree_has_zero_root_and_no_proofs() {
        let tree = MerkleTree::from_leaves(Vec::<B256>::new());
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root(), B256::ZERO);
        assert_eq!(tree.proof(leaf(1)), None);
    }

    #[test]
    fn single_leaf_tree_is_its_own_root() {
        let only = leaf(7);
        let tree = MerkleTree::from_leaves([only]);
        assert_eq!(tree.root(), only);
        // A lone leaf needs no siblings to reach the root.
        assert_eq!(tree.proof(only), Some(Vec::new()));
        assert!(verify_proof(&[], tree.root(), only));
    }

    #[test]
    fn root_is_order_independent() {
        let a = leaf(1);
        let b = leaf(2);
        let c = leaf(3);
        assert_eq!(
            MerkleTree::from_leaves([a, b, c]).root(),
            MerkleTree::from_leaves([c, a, b]).root(),
        );
    }

    #[test]
    fn duplicate_leaves_are_deduplicated() {
        let a = leaf(1);
        let b = leaf(2);
        assert_eq!(
            MerkleTree::from_leaves([a, b]).root(),
            MerkleTree::from_leaves([a, b, a, b, a]).root(),
        );
        assert_eq!(MerkleTree::from_leaves([a, a, a]).len(), 1);
    }

    #[test]
    fn builder_matches_from_leaves() {
        let leaves = [leaf(5), leaf(9), leaf(1), leaf(5)];
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
        let leaves = [leaf(8), leaf(2), leaf(4)];
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
        let leaves: Vec<B256> = (0u8..5).map(leaf).collect();
        let tree = MerkleTree::from_leaves(leaves.clone());
        let root = tree.root();
        for l in leaves {
            let proof = tree.proof(l).expect("leaf is in the tree");
            assert!(verify_proof(&proof, root, l), "proof failed for {l:#x}");
        }
    }

    #[test]
    fn proof_for_absent_leaf_is_none() {
        let tree = MerkleTree::from_leaves([leaf(1), leaf(2)]);
        assert_eq!(tree.proof(leaf(99)), None);
    }

    #[test]
    fn contains_reports_membership() {
        let tree = MerkleTree::from_leaves([leaf(1), leaf(2)]);
        assert!(tree.contains(leaf(1)));
        assert!(!tree.contains(leaf(3)));
    }

    #[test]
    fn proof_does_not_verify_against_wrong_root() {
        let tree = MerkleTree::from_leaves([leaf(1), leaf(2), leaf(3)]);
        let target = leaf(2);
        let proof = tree.proof(target).unwrap();
        let wrong_root =
            B256::from_str("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert!(!verify_proof(&proof, wrong_root, target));
    }
}
