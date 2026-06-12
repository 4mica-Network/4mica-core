use alloy::primitives::{Address, B256};
use anyhow::anyhow;
use chrono::{NaiveDateTime, Utc};
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleStatus, SettlementCycleStatus,
};
use log::{info, warn};
use sea_orm::TransactionTrait;

use crate::{
    error::{ServiceError, ServiceResult},
    ethereum::ClearingCommitInput,
    evm,
    persist::repo::{self, common::parse_address},
    service::CoreService,
};

impl CoreService {
    pub async fn commit_cycle_to_chain(&self, cycle_id: &str) -> ServiceResult<()> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != SettlementCycleStatus::NettingComputed {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status,
                SettlementCycleStatus::NettingComputed
            )));
        }

        let batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;
        let _clearing_house_address = evm::parse_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
        )
        .and_then(|address| {
            if address == Address::ZERO {
                Err(ServiceError::InvalidParams(
                    "ETHEREUM_CLEARING_HOUSE_ADDRESS must be configured before committing clearing batches"
                        .to_string(),
                ))
            } else {
                Ok(address)
            }
        })?;

        let input = ClearingCommitInput {
            cycle_id: evm::cycle_id_hash(&cycle.id),
            asset: evm::parse_address("cycle asset", &batch.asset_address)?,
            merkle_root: evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?,
            total_net_debit: evm::parse_u256(
                "clearing batch total net debit",
                &batch.total_net_debit,
            )?,
            total_net_credit: evm::parse_u256(
                "clearing batch total net credit",
                &batch.total_net_credit,
            )?,
            payment_submission_deadline: crate::util::timestamp_to_u64(
                "payment submission deadline",
                cycle.payment_submission_deadline,
            )?,
            payment_finality_deadline: crate::util::timestamp_to_u64(
                "payment finality deadline",
                cycle.payment_finality_deadline,
            )?,
        };

        let commit = self
            .inner
            .contract_api
            .commit_clearing_cycle(input)
            .await
            .map_err(|err| ServiceError::Other(anyhow!(err)))?;
        let tx_hash = commit.tx_hash.to_string();
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Some(tx_hash.clone()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            tx_hash.clone(),
            now,
        )
        .await?;
        if changed {
            info!(
                "committed settlement cycle {} to ClearingHouse in tx {}",
                cycle_id, tx_hash
            );
        }
        Ok(())
    }

    pub async fn process_cycle_committed(
        &self,
        onchain_cycle_id: B256,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle commit event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_by_id_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            Some(tx_hash.to_string()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            tx_hash.to_string(),
            now,
        )
        .await?;
        if changed {
            info!("mirrored ClearingHouse CycleCommitted for cycle {cycle_id}");
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor payment event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let debtor = parse_address(debtor)?.into_inner();
        let changed = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let debtor = debtor.clone();
                let tx_hash = tx_hash.to_string();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        &debtor,
                        ParticipantCycleStatus::Unpaid,
                        ParticipantCycleStatus::Paid,
                        Some(tx_hash),
                        now,
                    )
                    .await?;
                    if changed {
                        settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            &debtor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                            true,
                        )
                        .await?;
                    }
                    Ok(changed)
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!("mirrored DebtorPaid: cycle={cycle_id}, debtor={debtor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_credit_claim(
        &self,
        onchain_cycle_id: B256,
        creditor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("credit claim event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let creditor = parse_address(creditor)?.into_inner();
        let changed = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let creditor = creditor.clone();
                let tx_hash = tx_hash.to_string();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        &creditor,
                        ParticipantCycleStatus::Claimable,
                        ParticipantCycleStatus::Claimed,
                        Some(tx_hash),
                        now,
                    )
                    .await?;
                    if changed {
                        // A net creditor's own outgoing guarantees were fully
                        // offset by its incoming exposure, so settling its claim
                        // also discharges those obligations: settle the
                        // creditor's payer-side (`from = creditor`) guarantees and
                        // release the collateral they locked. Settlement is always
                        // keyed on the payer so each participant's locked
                        // collateral is released exactly once, by its own role
                        // event (debtor payment, creditor claim, default cover, or
                        // the finalization sweep for flat participants).
                        settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            &creditor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                            true,
                        )
                        .await?;
                    }
                    Ok(changed)
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!("mirrored CreditorClaimed: cycle={cycle_id}, creditor={creditor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_defaulted_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
    ) -> ServiceResult<()> {
        let debtor = parse_address(debtor)?.into_inner();

        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor default event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        repo::mark_participant_position_status_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            &debtor,
            ParticipantCycleStatus::Unpaid,
            ParticipantCycleStatus::Defaulted,
            None,
            Utc::now().naive_utc(),
        )
        .await?;
        let changed = repo::mark_cycle_defaulted_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!(
                "default event bridge received: cycle={}, debtor={}",
                cycle_id, debtor
            );
        }
        Ok(())
    }

    pub async fn process_default_covered(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("default covered event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let debtor = parse_address(debtor)?.into_inner();
        let changed = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let debtor = debtor.clone();
                Box::pin(async move {
                    settle_netted_guarantees_for_payer(
                        txn,
                        &cycle_id,
                        &debtor,
                        GuaranteeSettlementStatus::DefaultRemunerated,
                        now,
                        true,
                    )
                    .await
                })
            })
            .await
            .map_err(map_transaction_error)?;
        info!(
            "mirrored DefaultCovered: cycle={}, debtor={}, guarantees={}",
            cycle_id, debtor, changed
        );
        Ok(())
    }

    pub async fn process_cycle_finalized(&self, onchain_cycle_id: B256) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle finalized event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        self.finalize_cycle(&cycle_id).await
    }

    pub async fn finalize_cycle(&self, cycle_id: &str) -> ServiceResult<()> {
        let now = Utc::now().naive_utc();
        let cycle_id_owned = cycle_id.to_string();
        let (changed, settled) = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id_owned.clone();
                Box::pin(async move {
                    let changed = repo::mark_cycle_finalized_on(txn, &cycle_id, now).await?;
                    let settled = if changed {
                        settle_remaining_netted_guarantees_for_cycle(txn, &cycle_id, now).await?
                    } else {
                        0
                    };
                    Ok((changed, settled))
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!(
                "finalized settlement cycle {} (settled {} residual netted guarantee(s))",
                cycle_id, settled
            );
        }
        Ok(())
    }

    /// Finalize a fully-offsetting cycle without an on-chain commit: settle its
    /// netted guarantees and release the collateral they locked. Returns whether
    /// the cycle transitioned to `Finalized`.
    pub async fn short_circuit_offsetting_cycle(&self, cycle_id: &str) -> ServiceResult<bool> {
        let now = Utc::now().naive_utc();
        let cycle_id_owned = cycle_id.to_string();
        let (finalized, settled) = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id_owned.clone();
                Box::pin(async move {
                    let finalized =
                        repo::short_circuit_frozen_cycle_on(txn, &cycle_id, now).await?;
                    let settled = if finalized {
                        repo::mark_cycle_guarantees_netted_on(txn, &cycle_id, now).await?;
                        settle_remaining_netted_guarantees_for_cycle(txn, &cycle_id, now).await?
                    } else {
                        0
                    };
                    Ok((finalized, settled))
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if finalized {
            info!(
                "short-circuited fully-offsetting settlement cycle {} (settled {} netted guarantee(s), no on-chain commit)",
                cycle_id, settled
            );
        }
        Ok(finalized)
    }

    async fn resolve_onchain_cycle_id(
        &self,
        onchain_cycle_id: B256,
    ) -> ServiceResult<Option<String>> {
        // Indexed point lookup on the persisted on-chain cycle-id hash, replacing
        // a full-table scan (removing both the DoS surface and the silent-drop
        // risk when a cycle leaves a candidate window).
        let hash = evm::bytes32_hex(onchain_cycle_id);
        Ok(
            repo::get_cycle_id_by_onchain_hash_on(self.inner.persist_ctx.db.as_ref(), &hash)
                .await?,
        )
    }
}

async fn settle_netted_guarantees_for_payer<C: sea_orm::ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payer: &str,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
    release_locked_collateral: bool,
) -> ServiceResult<u64> {
    let guarantees = if release_locked_collateral {
        repo::list_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer).await?
    } else {
        Vec::new()
    };
    let changed =
        repo::transition_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer, target, now)
            .await?;

    if changed > 0 && release_locked_collateral {
        for guarantee in guarantees {
            repo::release_locked_collateral_for_guarantee_on(conn, &guarantee).await?;
        }
    }

    Ok(changed)
}

/// Settle every guarantee still in `Netted` for a cycle and release the
/// collateral each one locked, keyed on the payer (`from`) side.
///
/// This is the finalization backstop for guarantees that no role event reached:
/// flat participants (whose exposure netted to zero and who therefore emit no
/// on-chain event), creditors that never claimed, and creditor->debtor edges.
async fn settle_remaining_netted_guarantees_for_cycle<C: sea_orm::ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> ServiceResult<u64> {
    let guarantees = repo::list_netted_guarantees_for_cycle_on(conn, cycle_id).await?;
    if guarantees.is_empty() {
        return Ok(0);
    }
    let changed = repo::transition_all_netted_guarantees_for_cycle_on(
        conn,
        cycle_id,
        GuaranteeSettlementStatus::Settled,
        now,
    )
    .await?;
    if changed > 0 {
        for guarantee in &guarantees {
            repo::release_locked_collateral_for_guarantee_on(conn, guarantee).await?;
        }
    }
    Ok(changed)
}

fn map_transaction_error(err: sea_orm::TransactionError<ServiceError>) -> ServiceError {
    match err {
        sea_orm::TransactionError::Transaction(inner) => inner,
        sea_orm::TransactionError::Connection(err) => {
            crate::error::PersistDbError::DatabaseFailure(err).into()
        }
    }
}
