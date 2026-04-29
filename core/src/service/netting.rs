use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use alloy::primitives::{B256, U256, keccak256};
use anyhow::anyhow;
use chrono::Utc;
use entities::{
    clearing_batch,
    sea_orm_active_enums::{ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus},
};

use crate::{
    error::{ServiceError, ServiceResult},
    persist::repo,
    service::CoreService,
};

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
            let amount = parse_amount(&guarantee.value)?;
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
            let amount = parse_amount(&edge.finalized_payable_amount)?;
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
        let mut leaves = Vec::new();

        for position in positions {
            let net_debit = parse_amount(&position.net_debit)?;
            let net_credit = parse_amount(&position.net_credit)?;
            if net_debit > U256::ZERO {
                debtor_count += 1;
                total_net_debit = total_net_debit
                    .checked_add(net_debit)
                    .ok_or_else(|| ServiceError::Other(anyhow!("net debit overflow")))?;
                leaves.push(participant_leaf(
                    &cycle.id,
                    &position.asset_address,
                    &position.participant,
                    net_debit,
                    "NET_DEBTOR",
                ));
            }
            if net_credit > U256::ZERO {
                creditor_count += 1;
                total_net_credit = total_net_credit
                    .checked_add(net_credit)
                    .ok_or_else(|| ServiceError::Other(anyhow!("net credit overflow")))?;
                leaves.push(participant_leaf(
                    &cycle.id,
                    &position.asset_address,
                    &position.participant,
                    net_credit,
                    "NET_CREDITOR",
                ));
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

        let merkle_root = merkle_root(leaves);
        let batch_hash = settlement_hash([
            cycle.id.as_bytes(),
            cycle.asset_address.as_bytes(),
            total_net_debit.to_string().as_bytes(),
            total_net_credit.to_string().as_bytes(),
            merkle_root.as_slice(),
            b"batch",
        ]);
        let merkle_root = bytes32_hex(merkle_root);

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

    pub async fn mark_cycle_netting_computed(&self, cycle_id: &str) -> ServiceResult<bool> {
        let changed = repo::mark_cycle_netting_computed_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        Ok(changed)
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

fn parse_amount(raw: &str) -> ServiceResult<U256> {
    U256::from_str(raw).map_err(|err| {
        ServiceError::InvalidParams(format!("invalid cycle settlement amount '{raw}': {err}"))
    })
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

fn settlement_hash<const N: usize>(parts: [&[u8]; N]) -> String {
    bytes32_hex(settlement_digest(parts))
}

fn settlement_digest<const N: usize>(parts: [&[u8]; N]) -> B256 {
    let mut encoded = Vec::new();
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    keccak256(encoded)
}

fn participant_leaf(
    cycle_id: &str,
    asset_address: &str,
    participant: &str,
    amount: U256,
    role: &str,
) -> B256 {
    // This service-side commitment must be aligned with ClearingHouse proofs when chain commit is enabled.
    settlement_digest([
        b"4MICA_CLEARING_PARTICIPANT_V1",
        cycle_id.as_bytes(),
        asset_address.as_bytes(),
        participant.as_bytes(),
        amount.to_string().as_bytes(),
        role.as_bytes(),
    ])
}

fn merkle_root(leaves: Vec<B256>) -> B256 {
    if leaves.is_empty() {
        return B256::ZERO;
    }

    let mut level = leaves
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_pair(left, right));
        }
        level = next;
    }
    level[0]
}

fn hash_pair(a: B256, b: B256) -> B256 {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(left.as_slice());
    encoded.extend_from_slice(right.as_slice());
    keccak256(encoded)
}

fn bytes32_hex(value: B256) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_is_order_independent() {
        let a = participant_leaf(
            "cycle",
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
            U256::from(10),
            "NET_DEBTOR",
        );
        let b = participant_leaf(
            "cycle",
            "0x0000000000000000000000000000000000000000",
            "0x2222222222222222222222222222222222222222",
            U256::from(10),
            "NET_CREDITOR",
        );

        assert_eq!(merkle_root(vec![a, b]), merkle_root(vec![b, a]));
    }

    #[test]
    fn merkle_root_deduplicates_identical_leaves() {
        let leaf = participant_leaf(
            "cycle",
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
            U256::from(10),
            "NET_DEBTOR",
        );

        assert_eq!(merkle_root(vec![leaf]), merkle_root(vec![leaf, leaf]));
    }
}
