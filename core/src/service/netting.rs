use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::anyhow;
use chrono::Utc;
use entities::{
    clearing_batch, cycle_participant_position,
    sea_orm_active_enums::{ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus},
};

use crate::{
    error::{ServiceError, ServiceResult},
    persist::repo,
    service::CoreService,
};

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
        let chain_id = self.inner.public_params.chain_id;
        let clearing_house_address = parse_configured_address(
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

        let merkle_root = merkle_root(participant_leaves.iter().map(|leaf| leaf.leaf).collect());
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

        let participant_address = parse_configured_address("cycle participant", participant)?;
        let stored_root = parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?;
        let chain_id = self.inner.public_params.chain_id;
        let clearing_house_address = parse_configured_address(
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
        let computed_root = merkle_root(participant_leaves.iter().map(|leaf| leaf.leaf).collect());
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
        let proof = sorted_merkle_proof(
            participant_leaves.iter().map(|leaf| leaf.leaf).collect(),
            target.leaf,
        )
        .ok_or_else(|| {
            ServiceError::NotFound(format!(
                "Clearing participant {participant} in settlement cycle {cycle_id}"
            ))
        })?;

        Ok(ClearingParticipantProof {
            cycle_id: clearing_cycle_id(&cycle.id),
            cycle_id_text: cycle.id,
            asset_address: target.asset_address,
            participant: target.participant,
            role: target.role.clone(),
            amount: target.amount,
            net_debit: target.net_debit,
            net_credit: target.net_credit,
            leaf: target.leaf,
            merkle_root: stored_root,
            proof,
        })
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

fn parse_configured_address(label: &str, raw: &str) -> ServiceResult<Address> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(Address::ZERO);
    }
    Address::from_str(value).map_err(|err| {
        ServiceError::InvalidParams(format!("invalid {label} address '{raw}': {err}"))
    })
}

fn parse_bytes32(label: &str, raw: &str) -> ServiceResult<B256> {
    B256::from_str(raw.trim())
        .map_err(|err| ServiceError::InvalidParams(format!("invalid {label} '{raw}': {err}")))
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

#[derive(Debug, Clone)]
struct ParticipantLeaf {
    participant: Address,
    asset_address: Address,
    role: ParticipantCycleRole,
    amount: U256,
    net_debit: U256,
    net_credit: U256,
    leaf: B256,
}

fn participant_leaves_for_positions(
    chain_id: u64,
    clearing_house_address: Address,
    cycle_id: &str,
    positions: Vec<cycle_participant_position::Model>,
) -> ServiceResult<Vec<ParticipantLeaf>> {
    let mut leaves = Vec::new();
    for position in positions {
        let asset_address = parse_configured_address("cycle asset", &position.asset_address)?;
        let participant = parse_configured_address("cycle participant", &position.participant)?;
        let net_debit = parse_amount(&position.net_debit)?;
        let net_credit = parse_amount(&position.net_credit)?;
        if net_debit > U256::ZERO {
            leaves.push(ParticipantLeaf {
                participant,
                asset_address,
                role: ParticipantCycleRole::NetDebtor,
                amount: net_debit,
                net_debit,
                net_credit,
                leaf: participant_leaf(
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
                leaf: participant_leaf(
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

#[derive(Debug, Clone, Copy)]
enum ClearingParticipantRole {
    NetDebtor = 0,
    NetCreditor = 1,
}

fn participant_leaf(
    chain_id: u64,
    clearing_house_address: Address,
    cycle_id: &str,
    asset_address: Address,
    participant: Address,
    amount: U256,
    role: ClearingParticipantRole,
) -> B256 {
    let cycle_id = clearing_cycle_id(cycle_id);
    let mut encoded = Vec::with_capacity(0xe0);
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    encoded.extend_from_slice(&address_word(clearing_house_address));
    encoded.extend_from_slice(cycle_id.as_slice());
    encoded.extend_from_slice(&address_word(asset_address));
    encoded.extend_from_slice(&address_word(participant));
    encoded.extend_from_slice(&amount.to_be_bytes::<32>());
    encoded.extend_from_slice(&U256::from(role as u8).to_be_bytes::<32>());
    keccak256(encoded)
}

fn clearing_cycle_id(cycle_id: &str) -> B256 {
    keccak256(cycle_id.as_bytes())
}

fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
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

fn sorted_merkle_proof(leaves: Vec<B256>, target: B256) -> Option<Vec<B256>> {
    let mut level = leaves
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut target_index = level.iter().position(|leaf| *leaf == target)?;
    let mut proof = Vec::new();

    while level.len() > 1 {
        let sibling_index = if target_index % 2 == 0 {
            if target_index + 1 < level.len() {
                target_index + 1
            } else {
                target_index
            }
        } else {
            target_index - 1
        };
        proof.push(level[sibling_index]);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_pair(left, right));
        }
        level = next;
        target_index /= 2;
    }

    Some(proof)
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
    use alloy_sol_types::SolValue;
    use chrono::Utc;

    #[test]
    fn merkle_root_is_order_independent() {
        let clearing_house = Address::ZERO;
        let asset = Address::ZERO;
        let a = participant_leaf(
            1,
            clearing_house,
            "cycle",
            asset,
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            U256::from(10),
            ClearingParticipantRole::NetDebtor,
        );
        let b = participant_leaf(
            1,
            clearing_house,
            "cycle",
            asset,
            Address::from_str("0x2222222222222222222222222222222222222222").unwrap(),
            U256::from(10),
            ClearingParticipantRole::NetCreditor,
        );

        assert_eq!(merkle_root(vec![a, b]), merkle_root(vec![b, a]));
    }

    #[test]
    fn merkle_root_deduplicates_identical_leaves() {
        let leaf = participant_leaf(
            1,
            Address::ZERO,
            "cycle",
            Address::ZERO,
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            U256::from(10),
            ClearingParticipantRole::NetDebtor,
        );

        assert_eq!(merkle_root(vec![leaf]), merkle_root(vec![leaf, leaf]));
    }

    #[test]
    fn participant_leaf_matches_clearing_house_solidity_encoding() {
        let chain_id = 84532u64;
        let clearing_house =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let asset = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let participant = Address::from_str("0x3333333333333333333333333333333333333333").unwrap();
        let amount = U256::from(123_456_789u64);

        let actual = participant_leaf(
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
                clearing_cycle_id("base-sepolia:2026-04-30T00"),
                asset,
                participant,
                amount,
                U256::ZERO,
            )
                .abi_encode(),
        );

        assert_eq!(actual, expected);
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

        let debtor_leaf = participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            debtor,
            U256::from(10),
            ClearingParticipantRole::NetDebtor,
        );
        let creditor_leaf = participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            creditor,
            U256::from(10),
            ClearingParticipantRole::NetCreditor,
        );
        let other_debtor_leaf = participant_leaf(
            chain_id,
            clearing_house,
            "cycle",
            asset,
            other_debtor,
            U256::from(3),
            ClearingParticipantRole::NetDebtor,
        );

        let leaves = vec![debtor_leaf, creditor_leaf, other_debtor_leaf];
        let root = merkle_root(leaves.clone());
        let proof = sorted_merkle_proof(leaves, debtor_leaf).unwrap();

        assert!(verify_sorted_merkle_proof(&proof, root, debtor_leaf));
    }

    #[test]
    fn participant_leaves_build_contract_verifiable_proof_payload() {
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
        let root = merkle_root(leaves.iter().map(|leaf| leaf.leaf).collect());
        let proof = sorted_merkle_proof(
            leaves.iter().map(|leaf| leaf.leaf).collect(),
            debtor_leaf.leaf,
        )
        .unwrap();

        assert_eq!(debtor_leaf.amount, U256::from(10));
        assert_eq!(debtor_leaf.net_debit, U256::from(10));
        assert_eq!(debtor_leaf.net_credit, U256::ZERO);
        assert!(verify_sorted_merkle_proof(&proof, root, debtor_leaf.leaf));
    }

    fn verify_sorted_merkle_proof(proof: &[B256], root: B256, leaf: B256) -> bool {
        let computed = proof.iter().fold(leaf, |computed, proof_element| {
            hash_pair(computed, *proof_element)
        });
        computed == root
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
