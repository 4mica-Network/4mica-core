//! Service-layer settlement, driven entirely off mirrored chain events (no chain,
//! no HTTP). Two concerns live here:
//!
//!   1. Ledger correctness — how debtor payments, defaults, and creditor claims move
//!      participant, guarantee, and collateral state, and how the finalize/shortfall
//!      sweeps release the collateral that netted guarantees locked.
//!   2. The optimistic-write / confirm-by-event state machine — every chain-driven
//!      transition is written unconfirmed and only confirmed once its event arrives,
//!      and an unconfirmed cycle keeps retrying instead of advancing.

use alloy::primitives::U256;
use chrono::{Duration, Utc};
use entities::sea_orm_active_enums::{ParticipantCycleStatus, SettlementCycleStatus};
use entities::settlement_cycle;
use sea_orm::EntityTrait;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{
    build_three_party_cycle, create_frozen_cycle, lock_collateral, net_cycle, open_payment_window,
    setup_cycle_service, store_payable_guarantee,
};
use common::fixtures::{
    ensure_user_with_collateral, normalize_address, random_address, read_locked_collateral,
};
use core_service::{
    config::DEFAULT_ASSET_ADDRESS, ethereum::event_data::EventMeta, evm, persist::PersistCtx,
    persist::repo, service::CoreService,
};

/// Minimal `EventMeta` for driving mirror handlers; only `tx_hash` is consulted.
fn event_meta(tx_hash: &str) -> EventMeta {
    EventMeta {
        chain_id: 1,
        block_hash: "0xblock".to_string(),
        tx_hash: tx_hash.to_string(),
        log_index: 0,
    }
}

async fn cycle(ctx: &PersistCtx, cycle_id: &str) -> anyhow::Result<settlement_cycle::Model> {
    Ok(settlement_cycle::Entity::find_by_id(cycle_id.to_string())
        .one(ctx.db.as_ref())
        .await?
        .expect("cycle exists"))
}

async fn claim(
    service: &CoreService,
    cycle_id: &str,
    creditor: &str,
    tx: &str,
) -> anyhow::Result<()> {
    service
        .process_credit_claim(
            evm::cycle_id_hash(cycle_id),
            creditor.to_string(),
            event_meta(tx),
        )
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ledger correctness
// ---------------------------------------------------------------------------

/// Every participant locks the gross value of its own outgoing guarantee at issuance.
/// After a full multilateral settlement — the net debtor paying and both net creditors
/// claiming, then the cycle finalizing — *all* of that locked collateral must be released,
/// not just the net debtor's. Guards the leak where creditors' collateral stayed locked
/// forever because settlement only freed the net debtor.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn voluntary_settlement_releases_all_collateral() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "voluntary-settlement";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    let asset = DEFAULT_ASSET_ADDRESS;

    // Topology alice->bob 10, bob->carol 4, carol->alice 1: alice is the net debtor (9),
    // bob/carol net creditors (6 and 3). Each locked its single outgoing guarantee.
    let (alice, bob, carol) = (&participants[0], &participants[1], &participants[2]);
    for (who, locked) in [(alice, 10u64), (bob, 4), (carol, 1)] {
        lock_collateral(ctx, who, locked).await?;
    }
    open_payment_window(&service, cycle_id).await?;

    // alice pays and each creditor claims; each participant's lock is released by settling its
    // own guarantee. (Collateral `total` is reconciled from chain, covered in chain_clearing.)
    service
        .process_paid_debtor(evm::cycle_id_hash(cycle_id), alice, "0xpay")
        .await?;
    claim(&service, cycle_id, bob, "0xclaim-bob").await?;
    claim(&service, cycle_id, carol, "0xclaim-carol").await?;

    // The finality job leaves a fully-resolved cycle confirmed in Settling; the CycleFinalized
    // event then finalizes it. (Here every guarantee was already settled by its payer's role
    // event, so the residual-netted sweep is a no-op — that path is covered by the shortfall test.)
    settle_confirmed(ctx, cycle_id).await?;
    service
        .process_cycle_finalized(evm::cycle_id_hash(cycle_id))
        .await?;

    for who in [alice, bob, carol] {
        assert_eq!(
            read_locked_collateral(ctx, who, asset).await?,
            U256::ZERO,
            "locked collateral not released for {who}"
        );
    }
    assert!(
        repo::list_netted_guarantees_for_cycle_on(ctx.db.as_ref(), cycle_id)
            .await?
            .is_empty()
    );
    assert_eq!(
        cycle(ctx, cycle_id).await?.status,
        SettlementCycleStatus::Finalized
    );
    Ok(())
}

/// When a net debtor never pays, the finality job seizes its collateral on-chain and the
/// `DebtorDefaulted` mirror flips the position to `Defaulted` and releases its lock. Once every
/// debtor and creditor is resolved the cycle confirms. (The seized/funded `total` balances are
/// reconciled from chain, covered in chain_clearing.)
#[tokio::test]
#[serial_test::file_serial(db)]
async fn defaulted_debtor_is_seized_and_creditors_are_funded() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "defaulted-debtor";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    let asset = DEFAULT_ASSET_ADDRESS;

    let (alice, bob, carol) = (&participants[0], &participants[1], &participants[2]);
    for (who, locked) in [(alice, 10u64), (bob, 4), (carol, 1)] {
        lock_collateral(ctx, who, locked).await?;
    }
    open_payment_window(&service, cycle_id).await?;

    // The job moves the cycle to Settling and then seizes/funds on-chain; the resulting
    // events arrive while it is Settling, and the last one confirms full resolution.
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, Utc::now().naive_utc()).await?);
    let onchain = evm::cycle_id_hash(cycle_id);
    service
        .process_defaulted_debtor(onchain, alice.clone(), event_meta("0xdefault-alice"))
        .await?;
    claim(&service, cycle_id, bob, "0xclaim-bob").await?;
    claim(&service, cycle_id, carol, "0xclaim-carol").await?;

    let resolved = cycle(ctx, cycle_id).await?;
    assert_eq!(resolved.status, SettlementCycleStatus::Settling);
    assert!(
        resolved.status_confirmed,
        "full resolution confirms the cycle"
    );

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    assert!(
        positions
            .iter()
            .any(|p| &p.participant == alice && p.status == ParticipantCycleStatus::Defaulted)
    );

    // Every lock is released. (Collateral `total` is reconciled from chain, covered in
    // chain_clearing — the seize and creditor funding land as CollateralSeized/Credited events.)
    for who in [alice, bob, carol] {
        assert_eq!(read_locked_collateral(ctx, who, asset).await?, U256::ZERO);
    }
    Ok(())
}

/// A shortfall cycle is terminal — it never reaches finalize — so the residual-netted sweep
/// has to run when it resolves, or flat participants would keep their collateral locked forever.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn shortfall_resolution_releases_flat_participant_collateral() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "shortfall-flat";
    let ctx = service.persist_ctx();
    let asset = DEFAULT_ASSET_ADDRESS;
    create_frozen_cycle(ctx, cycle_id).await?;

    // debtor->creditor 10 drives the cycle; flat_a<->flat_b 5 fully offset, so both are flat.
    let debtor = normalize_address(&random_address())?;
    let creditor = normalize_address(&random_address())?;
    let flat_a = normalize_address(&random_address())?;
    let flat_b = normalize_address(&random_address())?;
    store_payable_guarantee(ctx, cycle_id, &debtor, &creditor, 10, 0).await?;
    store_payable_guarantee(ctx, cycle_id, &flat_a, &flat_b, 5, 1).await?;
    store_payable_guarantee(ctx, cycle_id, &flat_b, &flat_a, 5, 2).await?;
    for (who, locked) in [(&debtor, 10u64), (&flat_a, 5), (&flat_b, 5)] {
        lock_collateral(ctx, who, locked).await?;
    }
    open_payment_window(&service, cycle_id).await?;

    // The job settles then drives the under-funded cycle into Shortfall (both unconfirmed).
    let now = Utc::now().naive_utc();
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, now).await?);
    assert!(repo::mark_cycle_shortfall_on(ctx.db.as_ref(), cycle_id, now).await?);

    // Seize the debtor and pay the creditor pro-rata; the creditor's claim is the last
    // resolving event, so it confirms the shortfall and sweeps the flat pair's guarantees.
    let onchain = evm::cycle_id_hash(cycle_id);
    service
        .process_defaulted_debtor(onchain, debtor.clone(), event_meta("0xseize"))
        .await?;
    claim(&service, cycle_id, &creditor, "0xclaim").await?;

    let resolved = cycle(ctx, cycle_id).await?;
    assert_eq!(resolved.status, SettlementCycleStatus::Shortfall);
    assert!(resolved.status_confirmed);
    for who in [&flat_a, &flat_b] {
        assert_eq!(
            read_locked_collateral(ctx, who, asset).await?,
            U256::ZERO,
            "flat participant {who} collateral not released on shortfall"
        );
    }
    assert!(
        repo::list_netted_guarantees_for_cycle_on(ctx.db.as_ref(), cycle_id)
            .await?
            .is_empty()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Optimistic-write / confirm-by-event state machine
// ---------------------------------------------------------------------------

/// A committed cycle is written `PaymentWindowOpen` optimistically and stays unconfirmed
/// until the `CycleCommitted` event mirrors it.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn payment_window_is_unconfirmed_until_commit_event() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "commit-confirm";
    build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    net_cycle(&service, cycle_id).await?;

    let now = Utc::now().naive_utc();
    assert!(
        repo::mark_cycle_payment_window_open_on(
            ctx.db.as_ref(),
            cycle_id,
            Some("0xcommit".to_string()),
            now,
            now,
            now,
        )
        .await?
    );
    let optimistic = cycle(ctx, cycle_id).await?;
    assert_eq!(optimistic.status, SettlementCycleStatus::PaymentWindowOpen);
    assert!(!optimistic.status_confirmed);

    service
        .process_cycle_committed(evm::cycle_id_hash(cycle_id), "0xcommit")
        .await?;
    assert!(cycle(ctx, cycle_id).await?.status_confirmed);
    Ok(())
}

/// A `Settling` cycle confirms only once its ledger is fully resolved: a partial resolution
/// leaves it unconfirmed, and the final resolving event flips it to confirmed.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn settling_confirms_only_when_ledger_fully_resolved() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "settling-confirm";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    let (alice, bob, carol) = (&participants[0], &participants[1], &participants[2]);
    for (who, locked) in [(alice, 10u64), (bob, 4), (carol, 1)] {
        lock_collateral(ctx, who, locked).await?;
    }
    open_payment_window(&service, cycle_id).await?;
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, Utc::now().naive_utc()).await?);

    // Debtor paid and only one creditor claimed: the other is still Claimable → unconfirmed.
    service
        .process_paid_debtor(evm::cycle_id_hash(cycle_id), alice, "0xpay")
        .await?;
    claim(&service, cycle_id, bob, "0xclaim-bob").await?;
    assert!(!cycle(ctx, cycle_id).await?.status_confirmed);

    // The last claim resolves the ledger and confirms the cycle.
    claim(&service, cycle_id, carol, "0xclaim-carol").await?;
    assert!(cycle(ctx, cycle_id).await?.status_confirmed);
    Ok(())
}

/// Finalization is optimistic: a confirmed `Settling` cycle is written `Finalized` unconfirmed
/// when `finalizeCycle` is submitted, and only the `CycleFinalized` event confirms it.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn finalize_is_optimistic_until_finalized_event() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "finalize-confirm";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    for (who, locked) in [
        (&participants[0], 10u64),
        (&participants[1], 4),
        (&participants[2], 1),
    ] {
        lock_collateral(ctx, who, locked).await?;
    }
    open_payment_window(&service, cycle_id).await?;
    settle_confirmed(ctx, cycle_id).await?;

    let now = Utc::now().naive_utc();
    assert!(repo::mark_cycle_finalized_optimistic_on(ctx.db.as_ref(), cycle_id, now).await?);
    let optimistic = cycle(ctx, cycle_id).await?;
    assert_eq!(optimistic.status, SettlementCycleStatus::Finalized);
    assert!(!optimistic.status_confirmed);

    service
        .process_cycle_finalized(evm::cycle_id_hash(cycle_id))
        .await?;
    assert!(cycle(ctx, cycle_id).await?.status_confirmed);
    Ok(())
}

/// The `CycleShortfall` event mirrors a `Settling` cycle into `Shortfall` (unconfirmed) when
/// Core's own optimistic mark never landed — a status mirror, not the confirmation source.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn shortfall_event_mirrors_settling_status() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "shortfall-mirror";
    build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    open_payment_window(&service, cycle_id).await?;
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, Utc::now().naive_utc()).await?);

    service
        .process_cycle_shortfall(evm::cycle_id_hash(cycle_id))
        .await?;
    let mirrored = cycle(ctx, cycle_id).await?;
    assert_eq!(mirrored.status, SettlementCycleStatus::Shortfall);
    assert!(!mirrored.status_confirmed);
    Ok(())
}

/// An unconfirmed cycle is re-driven only once it has been stale for the retry delay: fresh it
/// is skipped, past the delay it is due, and confirming it removes it from the retry set. The
/// query is shared by every stage, so `Settling` stands in for all of them.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn unconfirmed_cycles_are_retried_after_the_delay() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "retry-due";
    build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    open_payment_window(&service, cycle_id).await?;

    let now = Utc::now().naive_utc();
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, now).await?);

    // Freshly written: not yet stale, so not retried.
    let stale_before = now - Duration::minutes(30);
    assert!(
        repo::list_settling_retry_due_on(ctx.db.as_ref(), stale_before)
            .await?
            .is_empty()
    );

    // Backdate the write past the retry delay: now it is due.
    let stale = now - Duration::hours(1);
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, stale).await?);
    let due = repo::list_settling_retry_due_on(ctx.db.as_ref(), stale_before).await?;
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, cycle_id);

    // Confirming it drops it from the retry set.
    assert!(repo::confirm_cycle_resolved_on(ctx.db.as_ref(), cycle_id, now).await?);
    assert!(
        repo::list_settling_retry_due_on(ctx.db.as_ref(), stale_before)
            .await?
            .is_empty()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Payment queryability
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial_test::file_serial(db)]
async fn recipient_payments_are_queryable_by_recipient() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let user = random_address();
    let recipient = random_address();
    ensure_user_with_collateral(ctx, &user, U256::from(25u64)).await?;

    repo::submit_payment_transaction(
        ctx,
        user.clone(),
        recipient.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        "0xpayment".to_string(),
        U256::from(9u64),
    )
    .await?;

    let rows = repo::get_recipient_transactions(ctx, &recipient).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].user_address, user);
    assert_eq!(rows[0].amount, "9");
    Ok(())
}

/// Move an open cycle into confirmed `Settling` — the state the finality job leaves a
/// fully-resolved cycle in before it finalizes.
async fn settle_confirmed(ctx: &PersistCtx, cycle_id: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    assert!(repo::mark_cycle_settling_on(ctx.db.as_ref(), cycle_id, now).await?);
    assert!(repo::confirm_cycle_resolved_on(ctx.db.as_ref(), cycle_id, now).await?);
    Ok(())
}
