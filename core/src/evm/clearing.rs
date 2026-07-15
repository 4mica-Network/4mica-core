//! EVM leaf encoding for the clearing batch Merkle tree.
//!
//! [`hash_participant_leaf`] computes the keccak256 pre-image that mirrors the
//! ClearingHouse contract so that proofs produced off-chain verify on-chain.

use alloy::primitives::{Address, U256};
use crypto::merkle::LeafHash;

use crate::evm::{address_word, cycle_id_hash};
use crate::service::netting::ClearingParticipantRole;

pub fn claim_cycle_id(cycle_id: &str) -> U256 {
    U256::from_be_bytes(crate::evm::cycle_id_hash(cycle_id).into())
}

/// Compute the keccak256 leaf for a single participant position.
///
/// The pre-image is the ABI-style concatenation of 32-byte words
/// `(chainId, clearingHouse, cycleId, asset, participant, amount, role)`, which
/// must stay byte-for-byte identical to the ClearingHouse contract.
///
/// This fixed 224-byte preimage is also what makes the Merkle tree
/// second-preimage safe: it can never equal a 64-byte internal-node preimage.
/// See the load-bearing caller invariant documented in [`crypto::merkle`].
pub fn hash_participant_leaf(
    chain_id: u64,
    clearing_house_address: Address,
    cycle_id: &str,
    asset_address: Address,
    participant: Address,
    amount: U256,
    role: ClearingParticipantRole,
) -> LeafHash {
    let cycle_id = cycle_id_hash(cycle_id);
    let mut encoded = Vec::with_capacity(0xe0);
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    encoded.extend_from_slice(&address_word(clearing_house_address));
    encoded.extend_from_slice(cycle_id.as_slice());
    encoded.extend_from_slice(&address_word(asset_address));
    encoded.extend_from_slice(&address_word(participant));
    encoded.extend_from_slice(&amount.to_be_bytes::<32>());
    encoded.extend_from_slice(&U256::from(role as u8).to_be_bytes::<32>());
    // The 224-byte preimage is well clear of the 64-byte internal-node width, so
    // this never returns None; it is what keeps the leaf second-preimage safe.
    LeafHash::from_preimage(&encoded).expect("participant leaf preimage is 224 bytes, never 64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::cycle_id_hash;
    use alloy::primitives::keccak256;
    use alloy_sol_types::SolValue;
    use crypto::merkle::{MerkleTree, verify_proof};
    use std::str::FromStr;

    #[test]
    fn claim_cycle_id_is_stable_and_cycle_scoped() {
        let first = claim_cycle_id("0x0000000000000000000000000000000000000000:1777248000");
        let second = claim_cycle_id("0x0000000000000000000000000000000000000000:1777248000");
        let other = claim_cycle_id("0x0000000000000000000000000000000000000000:1777334400");

        assert_eq!(first, second);
        assert_ne!(first, U256::ZERO);
        assert_ne!(first, other);
    }

    #[test]
    fn participant_leaf_matches_clearing_house_solidity_encoding() {
        let chain_id = 84532u64;
        let clearing_house =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let asset = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let participant = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let amount = U256::from(123_456_789u64);

        let actual = hash_participant_leaf(
            chain_id,
            clearing_house,
            "base-sepolia:2026-04-30T00",
            asset,
            participant,
            amount,
            ClearingParticipantRole::NetDebtor,
        );

        let expected = keccak256(
            (
                U256::from(chain_id),
                clearing_house,
                cycle_id_hash("base-sepolia:2026-04-30T00"),
                asset,
                participant,
                amount,
                U256::ZERO,
            )
                .abi_encode(),
        );

        assert_eq!(actual.hash(), expected);
    }

    #[test]
    fn merkle_proof_matches_openzeppelin_sorted_pair_verification() {
        let chain_id = 84532u64;
        let clearing_house =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let asset = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let debtor = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let creditor = Address::from_str("0x4444444444444444444444444444444444444444").unwrap();
        let other_debtor = Address::from_str("0x5555555555555555555555555555555555555555").unwrap();

        let debtor_leaf = hash_participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            debtor,
            U256::from(10),
            ClearingParticipantRole::NetDebtor,
        );
        let creditor_leaf = hash_participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            creditor,
            U256::from(10),
            ClearingParticipantRole::NetCreditor,
        );
        let other_debtor_leaf = hash_participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            other_debtor,
            U256::from(3),
            ClearingParticipantRole::NetDebtor,
        );

        let tree = MerkleTree::from_leaves([debtor_leaf, creditor_leaf, other_debtor_leaf]);
        let proof = tree.proof(debtor_leaf).unwrap();

        assert!(verify_proof(&proof, tree.root(), debtor_leaf));
    }
}
