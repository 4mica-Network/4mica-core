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
//! ## Second-preimage safety
//!
//! A sorted-pair keccak tree gives no *value-level* way to tell a leaf hash
//! apart from an internal-node hash, so a second-preimage attack works by
//! presenting an interior node hash where a leaf is expected. [`verify_proof`]
//! closes this structurally: it accepts only a [`LeafHash`], which can be
//! obtained *only* by hashing a leaf preimage through [`LeafHash::from_preimage`],
//! and that constructor rejects any 64-byte preimage — the exact width of an
//! internal-node preimage (`left || right`). A raw [`B256`] can therefore never
//! be passed as a leaf, and no internal-node value can be reconstructed as one.
//!
//! The ClearingHouse leaf is a fixed 224-byte tuple
//! `(chainId, clearingHouse, cycleId, asset, participant, amount, role)`, well
//! clear of the 64-byte node width, and on-chain verification recomputes the
//! leaf from those typed arguments rather than trusting a caller-supplied hash.
//! Keep leaf derivation longer than 64 bytes; a 64-byte leaf preimage would be
//! rejected by [`LeafHash::from_preimage`] rather than silently reintroducing
//! the attack.
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
    const HALF: usize = NODE_PREIMAGE_LEN / 2;
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut encoded = [0u8; NODE_PREIMAGE_LEN];
    encoded[..HALF].copy_from_slice(left.as_slice());
    encoded[HALF..].copy_from_slice(right.as_slice());
    keccak256(encoded)
}

/// The byte width of an internal-node preimage: the two concatenated child
/// hashes that [`hash_pair`] feeds to keccak256. Derived from [`B256`]'s size so
/// it can never drift from the actual node encoding.
const NODE_PREIMAGE_LEN: usize = 2 * size_of::<B256>();

/// The keccak256 hash of a Merkle *leaf* preimage.
///
/// A `LeafHash` is the only value [`verify_proof`] accepts as a leaf, and it can
/// be produced *only* by hashing a preimage through [`LeafHash::from_preimage`].
/// That constructor rejects any preimage exactly [`NODE_PREIMAGE_LEN`] bytes
/// long — the width of an internal-node preimage (`left || right`) — so an
/// interior node hash can never be reconstructed and passed off as a leaf. This
/// is the structural half of the tree's second-preimage safety (see the module
/// docs); a raw [`B256`] cannot be used as a leaf at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafHash(B256);

impl LeafHash {
    /// Hash a leaf preimage into a [`LeafHash`].
    ///
    /// Returns `None` when `preimage` is exactly [`NODE_PREIMAGE_LEN`] bytes,
    /// since a preimage of that width could collide with an internal-node hash
    /// and defeat second-preimage safety. Domain leaf encodings should be well
    /// clear of 64 bytes (the ClearingHouse leaf is 224).
    pub fn from_preimage(preimage: &[u8]) -> Option<Self> {
        if preimage.len() == NODE_PREIMAGE_LEN {
            return None;
        }
        Some(Self(keccak256(preimage)))
    }

    /// The underlying keccak256 hash, for use as a raw tree node (e.g. building a
    /// [`MerkleTree`] or serializing a proof).
    pub fn hash(self) -> B256 {
        self.0
    }
}

/// Verify that `proof` reconstructs `root` starting from `leaf`.
///
/// This mirrors OpenZeppelin's `MerkleProof.verify`: each proof element is folded
/// into the running hash with [`hash_pair`], and the final hash must equal `root`.
///
/// `leaf` is a [`LeafHash`] rather than a raw [`B256`] so that an internal-node
/// value can never be presented here as a leaf.
pub fn verify_proof(proof: &[B256], root: B256, leaf: LeafHash) -> bool {
    let computed = proof.iter().fold(leaf.hash(), |computed, sibling| {
        hash_pair(computed, *sibling)
    });
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

    /// The same one-byte leaf as [`leaf`], but as a [`LeafHash`] for feeding
    /// [`verify_proof`]. `leaf(b) == leaf_hash(b).hash()`.
    fn leaf_hash(byte: u8) -> LeafHash {
        LeafHash::from_preimage(&[byte]).expect("a 1-byte preimage is not node-width")
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
        assert!(verify_proof(&[], tree.root(), leaf_hash(7)));
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
        for byte in 0u8..5 {
            let l = leaf(byte);
            let proof = tree.proof(l).expect("leaf is in the tree");
            assert!(
                verify_proof(&proof, root, leaf_hash(byte)),
                "proof failed for {l:#x}"
            );
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
        assert!(!verify_proof(&proof, wrong_root, leaf_hash(2)));
    }

    #[test]
    fn internal_node_value_cannot_be_reconstructed_as_a_leaf() {
        // A four-leaf tree has genuine internal nodes at level 1.
        let leaves: Vec<B256> = (0u8..4).map(leaf).collect();
        let tree = MerkleTree::from_leaves(leaves.clone());

        // The first level-1 node is hash_pair of the two smallest sorted leaves;
        // reconstruct its exact 64-byte preimage (left || right, ascending).
        let sorted: Vec<B256> = {
            let mut s = leaves.clone();
            s.sort();
            s
        };
        let (l, r) = (sorted[0], sorted[1]);
        let mut node_preimage = [0u8; 64];
        node_preimage[..32].copy_from_slice(l.as_slice());
        node_preimage[32..].copy_from_slice(r.as_slice());

        // Sanity: this preimage really is an internal node of the tree.
        let internal_node = keccak256(node_preimage);
        assert_eq!(internal_node, tree.levels[1][0]);
        assert_eq!(internal_node, hash_pair(l, r));

        // The whole point: that 64-byte node preimage is refused by LeafHash, so
        // the internal-node value can never be wrapped and handed to verify_proof
        // as a leaf. verify_proof takes no raw B256, so there is no other path in.
        assert!(LeafHash::from_preimage(&node_preimage).is_none());
    }

    #[test]
    fn from_preimage_accepts_non_node_widths() {
        // Anything but exactly 64 bytes is a valid leaf preimage.
        assert!(LeafHash::from_preimage(&[]).is_some());
        assert!(LeafHash::from_preimage(&[0u8; 63]).is_some());
        assert!(LeafHash::from_preimage(&[0u8; 64]).is_none());
        assert!(LeafHash::from_preimage(&[0u8; 65]).is_some());
        assert!(LeafHash::from_preimage(&[0u8; 224]).is_some());
        // The hash matches a bare keccak of the same preimage.
        assert_eq!(
            LeafHash::from_preimage(&[9u8]).unwrap().hash(),
            keccak256([9u8])
        );
    }
}
