//! Clearing Merkle leaves, tree, and proofs for a cycle's participant positions.

use std::sync::Arc;

use alloy::primitives::{Address, B256, U256};
use anyhow::anyhow;
use crypto::merkle::{LeafHash, MerkleTree};
use entities::cycle_participant_position;
use entities::sea_orm_active_enums::ParticipantCycleRole;

use crate::error::{ServiceError, ServiceResult};
use crate::evm::{self, clearing::hash_participant_leaf};
use crate::persist::repo;
use crate::service::ctx::Ctx;

/// The clearing role encoded into a leaf, matching the ClearingHouse contract's
/// numbering.
#[derive(Debug, Clone, Copy)]
pub enum ClearingParticipantRole {
    NetDebtor = 0,
    NetCreditor = 1,
}

/// A participant's net position within a cycle, paired with its Merkle leaf.
///
/// A single participant can appear as both a debtor and a creditor across
/// different positions, so each [`ParticipantLeaf`] captures one side.
#[derive(Debug, Clone)]
pub struct ParticipantLeaf {
    pub participant: Address,
    pub asset_address: Address,
    pub role: ParticipantCycleRole,
    /// The net amount for this side (the net debit for debtors, net credit for
    /// creditors).
    pub amount: U256,
    pub net_debit: U256,
    pub net_credit: U256,
    pub leaf: LeafHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingParticipantProof {
    pub cycle_id: B256,
    pub cycle_id_text: String,
    pub asset_address: Address,
    pub participant: Address,
    pub role: ParticipantCycleRole,
    pub amount: U256,
    pub net_debit: U256,
    pub net_credit: U256,
    pub leaf: B256,
    pub merkle_root: B256,
    pub proof: Vec<B256>,
}

/// Build the clearing leaves for a cycle from its stored participant positions.
///
/// A position contributes a debtor leaf when it has a positive net debit and a
/// creditor leaf when it has a positive net credit; flat positions contribute
/// nothing.
pub fn participant_leaves_for_positions(
    chain_id: u64,
    clearing_house_address: Address,
    cycle_id: &str,
    positions: Vec<cycle_participant_position::Model>,
) -> ServiceResult<Vec<ParticipantLeaf>> {
    let mut leaves = Vec::new();
    for position in positions {
        let asset_address = evm::parse_optional_address("cycle asset", &position.asset_address)?;
        let participant = evm::parse_optional_address("cycle participant", &position.participant)?;
        let net_debit = evm::parse_u256("cycle net debit", &position.net_debit)?;
        let net_credit = evm::parse_u256("cycle net credit", &position.net_credit)?;
        if net_debit > U256::ZERO {
            leaves.push(ParticipantLeaf {
                participant,
                asset_address,
                role: ParticipantCycleRole::NetDebtor,
                amount: net_debit,
                net_debit,
                net_credit,
                leaf: hash_participant_leaf(
                    chain_id,
                    clearing_house_address,
                    cycle_id,
                    asset_address,
                    participant,
                    net_debit,
                    ClearingParticipantRole::NetDebtor,
                ),
            });
        }
        if net_credit > U256::ZERO {
            leaves.push(ParticipantLeaf {
                participant,
                asset_address,
                role: ParticipantCycleRole::NetCreditor,
                amount: net_credit,
                net_debit,
                net_credit,
                leaf: hash_participant_leaf(
                    chain_id,
                    clearing_house_address,
                    cycle_id,
                    asset_address,
                    participant,
                    net_credit,
                    ClearingParticipantRole::NetCreditor,
                ),
            });
        }
    }
    Ok(leaves)
}

/// Build the clearing Merkle tree from participant leaves, rejecting any leaf
/// collision.
pub fn build_participant_merkle_tree(
    participant_leaves: &[ParticipantLeaf],
) -> ServiceResult<MerkleTree> {
    let tree = MerkleTree::from_leaves(participant_leaves.iter().map(|leaf| leaf.leaf));
    if tree.len() != participant_leaves.len() {
        return Err(ServiceError::Other(anyhow!(
            "clearing leaf collision: {} participant positions produced only {} distinct leaves",
            participant_leaves.len(),
            tree.len()
        )));
    }
    Ok(tree)
}

pub struct ClearingProofOps {
    ctx: Arc<Ctx>,
}

impl ClearingProofOps {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    pub fn chain_id(&self) -> u64 {
        self.ctx.public_params.chain_id
    }

    pub fn clearing_house_address(&self) -> ServiceResult<Address> {
        evm::parse_optional_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.ctx.config.ethereum_config.clearing_house_address,
        )
    }

    /// The cycle's participant leaves, built from its stored positions.
    pub async fn participant_leaves(&self, cycle_id: &str) -> ServiceResult<Vec<ParticipantLeaf>> {
        let positions =
            repo::list_participant_positions_for_cycle_on(self.ctx.db(), cycle_id).await?;
        participant_leaves_for_positions(
            self.chain_id(),
            self.clearing_house_address()?,
            cycle_id,
            positions,
        )
    }

    pub async fn get_participant_clearing_proof(
        &self,
        cycle_id: &str,
        participant: &str,
    ) -> ServiceResult<ClearingParticipantProof> {
        let cycle = repo::get_cycle_by_id(&self.ctx.persist, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        let batch = self.require_clearing_batch(cycle_id).await?;

        let participant_address = evm::parse_optional_address("cycle participant", participant)?;
        let stored_root = evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?;
        let positions =
            repo::list_participant_positions_for_cycle_on(self.ctx.db(), cycle_id).await?;
        let participant_leaves = participant_leaves_for_positions(
            self.chain_id(),
            self.clearing_house_address()?,
            &cycle.id,
            positions,
        )?;
        let tree = build_participant_merkle_tree(&participant_leaves)?;
        Self::require_matching_root(&tree, stored_root, cycle_id)?;

        let target = participant_leaves
            .iter()
            .find(|leaf| leaf.participant == participant_address)
            .ok_or_else(|| {
                ServiceError::NotFound(format!(
                    "Clearing participant {participant} in settlement cycle {cycle_id}"
                ))
            })?;
        let proof = tree.proof(target.leaf).ok_or_else(|| {
            ServiceError::NotFound(format!(
                "Clearing participant {participant} in settlement cycle {cycle_id}"
            ))
        })?;

        Ok(ClearingParticipantProof {
            cycle_id: evm::cycle_id_hash(&cycle.id),
            cycle_id_text: cycle.id,
            asset_address: target.asset_address,
            participant: target.participant,
            role: target.role.clone(),
            amount: target.amount,
            net_debit: target.net_debit,
            net_credit: target.net_credit,
            leaf: target.leaf.hash(),
            merkle_root: stored_root,
            proof,
        })
    }

    /// Build the clearing Merkle tree once and return every participant leaf paired with
    /// its proof.
    pub async fn get_cycle_participant_proofs(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<Vec<(ParticipantLeaf, Vec<B256>)>> {
        let cycle = repo::get_cycle_by_id(&self.ctx.persist, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        let stored_root = self.stored_merkle_root(cycle_id).await?;
        let positions =
            repo::list_participant_positions_for_cycle_on(self.ctx.db(), cycle_id).await?;
        let participant_leaves = participant_leaves_for_positions(
            self.chain_id(),
            self.clearing_house_address()?,
            &cycle.id,
            positions,
        )?;
        let tree = build_participant_merkle_tree(&participant_leaves)?;
        Self::require_matching_root(&tree, stored_root, cycle_id)?;

        let mut proofs = Vec::with_capacity(participant_leaves.len());
        for leaf in participant_leaves {
            let proof = tree.proof(leaf.leaf).ok_or_else(|| {
                ServiceError::NotFound(format!(
                    "Clearing proof for participant {} in settlement cycle {cycle_id}",
                    leaf.participant
                ))
            })?;
            proofs.push((leaf, proof));
        }
        Ok(proofs)
    }

    async fn require_clearing_batch(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<entities::clearing_batch::Model> {
        repo::get_clearing_batch_by_cycle_on(self.ctx.db(), cycle_id)
            .await?
            .ok_or_else(|| {
                ServiceError::InvalidParams(format!(
                    "settlement cycle {cycle_id} has no clearing batch"
                ))
            })
    }

    async fn stored_merkle_root(&self, cycle_id: &str) -> ServiceResult<B256> {
        let batch = self.require_clearing_batch(cycle_id).await?;
        evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)
    }

    fn require_matching_root(
        tree: &MerkleTree,
        stored_root: B256,
        cycle_id: &str,
    ) -> ServiceResult<()> {
        let computed_root = tree.root();
        if computed_root != stored_root {
            return Err(ServiceError::InvalidParams(format!(
                "clearing batch Merkle root mismatch for cycle {cycle_id}: stored {stored_root:#x}, computed {computed_root:#x}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crypto::merkle::{MerkleTree, verify_proof};
    use entities::sea_orm_active_enums::ParticipantCycleStatus;

    #[test]
    fn participant_leaves_build_contract_verifiable_proof_payload() {
        use std::str::FromStr;
        let chain_id = 84532u64;
        let clearing_house =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let asset = "0x2222222222222222222222222222222222222222";
        let debtor = "0x3333333333333333333333333333333333333333";
        let creditor = "0x4444444444444444444444444444444444444444";

        let leaves = participant_leaves_for_positions(
            chain_id,
            clearing_house,
            "cycle",
            vec![
                position_model(
                    "cycle",
                    debtor,
                    asset,
                    U256::from(10),
                    U256::ZERO,
                    ParticipantCycleRole::NetDebtor,
                    ParticipantCycleStatus::Unpaid,
                ),
                position_model(
                    "cycle",
                    creditor,
                    asset,
                    U256::ZERO,
                    U256::from(10),
                    ParticipantCycleRole::NetCreditor,
                    ParticipantCycleStatus::Claimable,
                ),
            ],
        )
        .unwrap();
        let debtor_leaf = leaves
            .iter()
            .find(|leaf| leaf.role == ParticipantCycleRole::NetDebtor)
            .unwrap();
        let tree = MerkleTree::from_leaves(leaves.iter().map(|leaf| leaf.leaf));
        let proof = tree.proof(debtor_leaf.leaf).unwrap();

        assert_eq!(debtor_leaf.amount, U256::from(10));
        assert_eq!(debtor_leaf.net_debit, U256::from(10));
        assert_eq!(debtor_leaf.net_credit, U256::ZERO);
        assert!(verify_proof(&proof, tree.root(), debtor_leaf.leaf));
    }

    fn position_model(
        cycle_id: &str,
        participant: &str,
        asset: &str,
        net_debit: U256,
        net_credit: U256,
        role: ParticipantCycleRole,
        status: ParticipantCycleStatus,
    ) -> cycle_participant_position::Model {
        let now = Utc::now().naive_utc();
        cycle_participant_position::Model {
            cycle_id: cycle_id.to_string(),
            participant: participant.to_string(),
            asset_address: asset.to_string(),
            gross_outgoing: net_debit.to_string(),
            gross_incoming: net_credit.to_string(),
            net_debit: net_debit.to_string(),
            net_credit: net_credit.to_string(),
            role,
            status,
            settlement_tx_hash: None,
            created_at: now,
            updated_at: now,
        }
    }
}
