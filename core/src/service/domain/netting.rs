//! Netting: turn a frozen cycle's payable guarantees into exposure edges, net participant
//! positions, and a committable clearing batch.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy::primitives::{B256, U256};
use anyhow::anyhow;
use chrono::Utc;
use entities::clearing_batch;
use entities::sea_orm_active_enums::{
    ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus,
};
use log::{info, warn};
use sea_orm::TransactionTrait;

use crate::error::{ServiceError, ServiceResult};
use crate::evm;
use crate::persist::repo;
use crate::service::ctx::Ctx;
use crate::service::shared::clearing_proofs::{
    ClearingParticipantProof, ClearingProofOps, ParticipantLeaf, build_participant_merkle_tree,
};
use crate::service::shared::cycle::CycleOps;
use crate::service::shared::{map_transaction_error, settlement_ledger};

/// Outcome of running the netting pipeline for a single frozen cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleNettingOutcome {
    /// The cycle was netted and transitioned to `NettingComputed`.
    Computed,
    /// The cycle had no payable exposure and was finalized without a commit.
    ShortCircuited,
    /// Nothing changed (e.g. the cycle was already past `Frozen`).
    Skipped,
}

pub struct NettingService {
    ctx: Arc<Ctx>,
    cycle_ops: Arc<CycleOps>,
    proof_ops: Arc<ClearingProofOps>,
}

impl NettingService {
    pub fn new(ctx: Arc<Ctx>, cycle_ops: Arc<CycleOps>, proof_ops: Arc<ClearingProofOps>) -> Self {
        Self {
            ctx,
            cycle_ops,
            proof_ops,
        }
    }

    pub async fn compute_due_cycle_netting(&self) -> ServiceResult<Vec<String>> {
        let now = Utc::now().naive_utc();
        let due = repo::list_frozen_cycles_resolution_due_on(self.ctx.db(), now).await?;
        let mut computed = Vec::new();
        for cycle in due {
            let cycle_id = cycle.id.clone();
            match self.compute_cycle_netting(&cycle_id).await {
                Ok(CycleNettingOutcome::Computed) => computed.push(cycle_id),
                Ok(CycleNettingOutcome::ShortCircuited) => info!(
                    "short-circuited settlement cycle {cycle_id} (no finalized payable guarantees); finalized without on-chain commit"
                ),
                Ok(CycleNettingOutcome::Skipped) => {}
                Err(err) => {
                    warn!("failed to compute netting for settlement cycle {cycle_id}: {err:?}")
                }
            }
        }
        Ok(computed)
    }

    /// Run the netting pipeline for a single frozen cycle.
    ///
    /// A cycle with no `FinalizedPayable` guarantees has nothing to net, and a
    /// fully-offsetting cycle (payable guarantees that all net flat) produces an
    /// empty batch; both are short-circuited straight to `Finalized` instead of
    /// emitting a zero ClearingHouse commit that would revert on-chain.
    pub async fn compute_cycle_netting(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<CycleNettingOutcome> {
        let payable_count =
            repo::count_finalized_payable_guarantees_for_cycle_on(self.ctx.db(), cycle_id).await?;
        if payable_count == 0 {
            let now = Utc::now().naive_utc();
            let finalized =
                repo::short_circuit_frozen_cycle_on(self.ctx.db(), cycle_id, now).await?;
            return Ok(if finalized {
                CycleNettingOutcome::ShortCircuited
            } else {
                CycleNettingOutcome::Skipped
            });
        }

        self.compute_cycle_exposure_edges(cycle_id).await?;
        self.compute_cycle_participant_positions(cycle_id).await?;

        // A fully-offsetting cycle (everyone's exposure nets flat) has no net
        // debtors or creditors. Committing its empty batch would revert on-chain
        // (commitCycle rejects zero totals), so finalize it off-chain and release
        // the netted collateral instead.
        let cycle = repo::get_cycle_by_id_on(self.ctx.db(), cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if evm::parse_u256("cycle net settlement amount", &cycle.net_settlement_amount)?
            == U256::ZERO
        {
            let finalized =
                settlement_ledger::short_circuit_offsetting_cycle(self.ctx.db(), cycle_id).await?;
            return Ok(if finalized {
                CycleNettingOutcome::ShortCircuited
            } else {
                CycleNettingOutcome::Skipped
            });
        }

        self.build_clearing_batch(cycle_id).await?;
        Ok(if self.mark_cycle_netting_computed(cycle_id).await? {
            CycleNettingOutcome::Computed
        } else {
            CycleNettingOutcome::Skipped
        })
    }

    pub async fn compute_cycle_exposure_edges(&self, cycle_id: &str) -> ServiceResult<()> {
        self.cycle_ops
            .require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        let guarantees =
            repo::list_finalized_payable_guarantees_for_cycle_on(self.ctx.db(), cycle_id).await?;

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

        repo::replace_cycle_exposure_edges_on(self.ctx.db(), cycle_id, edge_inputs).await?;
        repo::update_cycle_netting_totals_on(
            self.ctx.db(),
            cycle_id,
            gross_total,
            gross_total,
            U256::ZERO,
        )
        .await?;
        Ok(())
    }

    pub async fn compute_cycle_participant_positions(&self, cycle_id: &str) -> ServiceResult<()> {
        self.cycle_ops
            .require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        let edges = repo::list_exposure_edges_for_cycle_on(self.ctx.db(), cycle_id).await?;
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

        repo::replace_cycle_participant_positions_on(self.ctx.db(), cycle_id, positions).await?;
        repo::update_cycle_net_settlement_amount_on(self.ctx.db(), cycle_id, net_settlement_total)
            .await?;
        Ok(())
    }

    pub async fn build_clearing_batch(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<clearing_batch::Model> {
        let cycle = self
            .cycle_ops
            .require_cycle_status(cycle_id, SettlementCycleStatus::Frozen)
            .await?;

        if let Some(existing) =
            repo::get_clearing_batch_by_cycle_on(self.ctx.db(), cycle_id).await?
        {
            return Ok(existing);
        }

        let mut total_net_debit = U256::ZERO;
        let mut total_net_credit = U256::ZERO;
        let mut debtor_count = 0i64;
        let mut creditor_count = 0i64;
        let participant_leaves = self.proof_ops.participant_leaves(&cycle.id).await?;

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
            self.ctx.db(),
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

    pub async fn mark_cycle_netting_computed(&self, cycle_id: &str) -> ServiceResult<bool> {
        let now = Utc::now().naive_utc();
        let cycle_id = cycle_id.to_string();
        self.ctx
            .persist
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
            .map_err(map_transaction_error)
    }

    pub async fn get_participant_clearing_proof(
        &self,
        cycle_id: &str,
        participant: &str,
    ) -> ServiceResult<ClearingParticipantProof> {
        self.proof_ops
            .get_participant_clearing_proof(cycle_id, participant)
            .await
    }

    pub async fn get_cycle_participant_proofs(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<Vec<(ParticipantLeaf, Vec<B256>)>> {
        self.proof_ops.get_cycle_participant_proofs(cycle_id).await
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
