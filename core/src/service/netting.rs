use std::collections::BTreeMap;

use alloy::primitives::{Address, B256, U256};
use anyhow::anyhow;
use chrono::Utc;
use crypto::merkle::{LeafHash, MerkleTree};
use entities::{
    clearing_batch, cycle_participant_position,
    sea_orm_active_enums::{ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus},
};
use sea_orm::TransactionTrait;

use crate::{
    error::{ServiceError, ServiceResult},
    evm::{self, clearing::hash_participant_leaf},
    persist::repo,
    service::CoreService,
};

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
fn build_participant_merkle_tree(
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

impl CoreService {
    pub async fn compute_cycle_exposure_edges(&self, cycle_id: &str) -> ServiceResult<()> {
        self.require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        let guarantees = repo::list_finalized_payable_guarantees_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;

        let mut edges = BTreeMap::<ExposureEdgeKey, ExposureEdgeAccumulator>::new();
        let mut gross_total = U256::ZERO;

        for guarantee in guarantees {
            let amount = evm::parse_u256("cycle settlement amount", &guarantee.value)?;
            gross_total = gross_total
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("cycle gross amount overflow")))?;

            let key = ExposureEdgeKey {
                payer: guarantee.from_address,
                payee: guarantee.to_address,
                asset_address: guarantee.asset_address,
            };
            let entry = edges.entry(key).or_default();
            entry.gross_amount = entry
                .gross_amount
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("edge gross amount overflow")))?;
            entry.finalized_payable_amount = entry
                .finalized_payable_amount
                .checked_add(amount)
                .ok_or_else(|| {
                    ServiceError::Other(anyhow!("edge finalized payable amount overflow"))
                })?;
            entry.guarantee_count += 1;
        }

        let edge_inputs = edges
            .into_iter()
            .map(|(key, edge)| repo::CycleExposureEdgeInput {
                cycle_id: cycle_id.to_string(),
                payer: key.payer,
                payee: key.payee,
                asset_address: key.asset_address,
                gross_amount: edge.gross_amount,
                finalized_payable_amount: edge.finalized_payable_amount,
                disputed_amount: U256::ZERO,
                cancelled_amount: U256::ZERO,
                guarantee_count: edge.guarantee_count,
            })
            .collect();

        repo::replace_cycle_exposure_edges_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            edge_inputs,
        )
        .await?;
        repo::update_cycle_netting_totals_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            gross_total,
            gross_total,
            U256::ZERO,
        )
        .await?;
        Ok(())
    }

    pub async fn compute_cycle_participant_positions(&self, cycle_id: &str) -> ServiceResult<()> {
        self.require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        let edges =
            repo::list_exposure_edges_for_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?;
        let mut totals = BTreeMap::<ParticipantAssetKey, ParticipantTotals>::new();

        for edge in edges {
            let amount =
                evm::parse_u256("cycle settlement amount", &edge.finalized_payable_amount)?;
            let payer_key = ParticipantAssetKey {
                participant: edge.payer,
                asset_address: edge.asset_address.clone(),
            };
            let payee_key = ParticipantAssetKey {
                participant: edge.payee,
                asset_address: edge.asset_address,
            };

            let payer = totals.entry(payer_key).or_default();
            payer.gross_outgoing = payer
                .gross_outgoing
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("gross outgoing overflow")))?;

            let payee = totals.entry(payee_key).or_default();
            payee.gross_incoming = payee
                .gross_incoming
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("gross incoming overflow")))?;
        }

        let mut positions = Vec::with_capacity(totals.len());
        let mut net_settlement_total = U256::ZERO;
        for (key, totals) in totals {
            let net_debit = totals.gross_outgoing.saturating_sub(totals.gross_incoming);
            let net_credit = totals.gross_incoming.saturating_sub(totals.gross_outgoing);
            let (role, status) = if net_debit > U256::ZERO {
                net_settlement_total =
                    net_settlement_total.checked_add(net_debit).ok_or_else(|| {
                        ServiceError::Other(anyhow!("net settlement amount overflow"))
                    })?;
                (
                    ParticipantCycleRole::NetDebtor,
                    ParticipantCycleStatus::Unpaid,
                )
            } else if net_credit > U256::ZERO {
                (
                    ParticipantCycleRole::NetCreditor,
                    ParticipantCycleStatus::Claimable,
                )
            } else {
                (
                    ParticipantCycleRole::Flat,
                    ParticipantCycleStatus::Finalized,
                )
            };

            positions.push(repo::CycleParticipantPositionInput {
                cycle_id: cycle_id.to_string(),
                participant: key.participant,
                asset_address: key.asset_address,
                gross_outgoing: totals.gross_outgoing,
                gross_incoming: totals.gross_incoming,
                net_debit,
                net_credit,
                role,
                status,
            });
        }

        repo::replace_cycle_participant_positions_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            positions,
        )
        .await?;
        repo::update_cycle_net_settlement_amount_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            net_settlement_total,
        )
        .await?;
        Ok(())
    }

    pub async fn build_clearing_batch(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<clearing_batch::Model> {
        let cycle = self
            .require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        if let Some(existing) =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
        {
            return Ok(existing);
        }

        let positions = repo::list_participant_positions_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        let mut total_net_debit = U256::ZERO;
        let mut total_net_credit = U256::ZERO;
        let mut debtor_count = 0i64;
        let mut creditor_count = 0i64;
        let chain_id = self.inner.public_params.chain_id;
        let clearing_house_address = evm::parse_optional_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
        )?;
        let participant_leaves = participant_leaves_for_positions(
            chain_id,
            clearing_house_address,
            &cycle.id,
            positions,
        )?;

        for leaf in &participant_leaves {
            match leaf.role {
                ParticipantCycleRole::NetDebtor => {
                    debtor_count += 1;
                    total_net_debit = total_net_debit
                        .checked_add(leaf.amount)
                        .ok_or_else(|| ServiceError::Other(anyhow!("net debit overflow")))?;
                }
                ParticipantCycleRole::NetCreditor => {
                    creditor_count += 1;
                    total_net_credit = total_net_credit
                        .checked_add(leaf.amount)
                        .ok_or_else(|| ServiceError::Other(anyhow!("net credit overflow")))?;
                }
                ParticipantCycleRole::Flat => {}
            }
        }

        if total_net_debit != total_net_credit {
            return Err(ServiceError::Other(anyhow!(
                "cycle {} net debit {} does not match net credit {}",
                cycle.id,
                total_net_debit,
                total_net_credit
            )));
        }

        let merkle_root = build_participant_merkle_tree(&participant_leaves)?.root();
        let batch_hash = evm::bytes32_hex(evm::length_prefixed_keccak(&[
            cycle.id.as_bytes(),
            cycle.asset_address.as_bytes(),
            total_net_debit.to_string().as_bytes(),
            total_net_credit.to_string().as_bytes(),
            merkle_root.as_slice(),
            b"batch".as_slice(),
        ]));
        let merkle_root = evm::bytes32_hex(merkle_root);

        repo::create_clearing_batch_on(
            self.inner.persist_ctx.db.as_ref(),
            repo::CreateClearingBatchInput {
                cycle_id: cycle.id,
                asset_address: cycle.asset_address,
                batch_hash,
                merkle_root,
                total_net_debit: total_net_debit.to_string(),
                total_net_credit: total_net_credit.to_string(),
                debtor_count,
                creditor_count,
                committed_at: Utc::now().naive_utc(),
            },
        )
        .await
        .map_err(Into::into)
    }

    pub async fn get_participant_clearing_proof(
        &self,
        cycle_id: &str,
        participant: &str,
    ) -> ServiceResult<ClearingParticipantProof> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        let batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;

        let participant_address = evm::parse_optional_address("cycle participant", participant)?;
        let stored_root = evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?;
        let chain_id = self.inner.public_params.chain_id;
        let clearing_house_address = evm::parse_optional_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
        )?;
        let positions = repo::list_participant_positions_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        let participant_leaves = participant_leaves_for_positions(
            chain_id,
            clearing_house_address,
            &cycle.id,
            positions,
        )?;
        let tree = build_participant_merkle_tree(&participant_leaves)?;
        let computed_root = tree.root();
        if computed_root != stored_root {
            return Err(ServiceError::InvalidParams(format!(
                "clearing batch Merkle root mismatch for cycle {cycle_id}: stored {stored_root:#x}, computed {computed_root:#x}"
            )));
        }

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
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        let batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;
        let stored_root = evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?;
        let chain_id = self.inner.public_params.chain_id;
        let clearing_house_address = evm::parse_optional_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
        )?;
        let positions = repo::list_participant_positions_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        let participant_leaves = participant_leaves_for_positions(
            chain_id,
            clearing_house_address,
            &cycle.id,
            positions,
        )?;
        let tree = build_participant_merkle_tree(&participant_leaves)?;
        let computed_root = tree.root();
        if computed_root != stored_root {
            return Err(ServiceError::InvalidParams(format!(
                "clearing batch Merkle root mismatch for cycle {cycle_id}: stored {stored_root:#x}, computed {computed_root:#x}"
            )));
        }

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

    pub async fn mark_cycle_netting_computed(&self, cycle_id: &str) -> ServiceResult<bool> {
        let now = Utc::now().naive_utc();
        let cycle_id = cycle_id.to_string();
        self.inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                Box::pin(async move {
                    let changed = repo::mark_cycle_netting_computed_on(txn, &cycle_id, now).await?;
                    if changed {
                        repo::mark_cycle_guarantees_netted_on(txn, &cycle_id, now).await?;
                    }
                    Ok(changed)
                })
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(inner) => inner,
                sea_orm::TransactionError::Connection(err) => {
                    crate::error::PersistDbError::DatabaseFailure(err).into()
                }
            })
    }

    async fn require_cycle_status(
        &self,
        cycle_id: &str,
        status: SettlementCycleStatus,
    ) -> ServiceResult<entities::settlement_cycle::Model> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != status {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status, status
            )));
        }
        Ok(cycle)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExposureEdgeKey {
    payer: String,
    payee: String,
    asset_address: String,
}

#[derive(Debug, Clone, Default)]
struct ExposureEdgeAccumulator {
    gross_amount: U256,
    finalized_payable_amount: U256,
    guarantee_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ParticipantAssetKey {
    participant: String,
    asset_address: String,
}

#[derive(Debug, Clone, Default)]
struct ParticipantTotals {
    gross_outgoing: U256,
    gross_incoming: U256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::merkle::{MerkleTree, verify_proof};

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
