//! Ledger writes that resolve a cycle's guarantees and release the collateral they locked.
//!
//! Everything takes a connection so callers compose it into their own transaction.

use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::{GuaranteeSettlementStatus, SettlementCycleStatus};
use log::info;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};

use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo;

/// Confirm a `Settling`/`Shortfall` cycle if its ledger is now fully resolved. A no-op for cycles
/// in any other state, so it is safe to call after every resolving event.
pub async fn maybe_confirm_resolved_cycle<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> ServiceResult<()> {
    if !repo::is_cycle_ledger_resolved_on(conn, cycle_id).await? {
        return Ok(());
    }
    if !repo::confirm_cycle_resolved_on(conn, cycle_id, now).await? {
        return Ok(());
    }

    // Shortfall is terminal and never reaches finalize, so sweep any residual Netted guarantees
    // (e.g. flat participants that emit no role event) here to release their locked collateral.
    // Settling cycles get this sweep when they finalize instead.
    let is_shortfall = repo::get_cycle_by_id_on(conn, cycle_id)
        .await?
        .is_some_and(|cycle| cycle.status == SettlementCycleStatus::Shortfall);
    if is_shortfall {
        settle_remaining_netted_guarantees_for_cycle(conn, cycle_id, now).await?;
    }
    Ok(())
}

pub async fn settle_netted_guarantees_for_payer<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payer: &str,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> ServiceResult<u64> {
    let guarantees = repo::list_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer).await?;
    let changed =
        repo::transition_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer, target, now)
            .await?;

    if changed > 0 {
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
pub async fn settle_remaining_netted_guarantees_for_cycle<C: ConnectionTrait>(
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

/// Finalize a fully-offsetting cycle without an on-chain commit: settle its
/// netted guarantees and release the collateral they locked. Returns whether
/// the cycle transitioned to `Finalized`.
pub async fn short_circuit_offsetting_cycle(
    db: &DatabaseConnection,
    cycle_id: &str,
) -> ServiceResult<bool> {
    let now = chrono::Utc::now().naive_utc();
    let cycle_id_owned = cycle_id.to_string();
    let (finalized, settled) = db
        .transaction::<_, _, ServiceError>(|txn| {
            let cycle_id = cycle_id_owned.clone();
            Box::pin(async move {
                let finalized = repo::short_circuit_frozen_cycle_on(txn, &cycle_id, now).await?;
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
        .map_err(super::map_transaction_error)?;
    if finalized {
        info!(
            "short-circuited fully-offsetting settlement cycle {} (settled {} netted guarantee(s), no on-chain commit)",
            cycle_id, settled
        );
    }
    Ok(finalized)
}
