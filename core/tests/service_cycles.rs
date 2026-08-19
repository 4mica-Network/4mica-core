//! Service-layer cycle lifecycle: active-cycle reuse, freezing elapsed cycles,
//! and netting independence from collateral. No chain, no HTTP.

use alloy::primitives::U256;
use chrono::{Duration, Utc};
use entities::sea_orm_active_enums::SettlementCycleStatus;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{build_three_party_cycle, setup_cycle_service};
use common::fixtures::{ensure_user_with_collateral, random_address, read_locked_collateral};
use core_service::{config::DEFAULT_ASSET_ADDRESS, persist::repo};

#[tokio::test]
#[serial_test::file_serial(db)]
async fn active_cycle_creation_reuses_open_cycle_for_same_asset() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;

    let first = service
        .clearing()
        .get_or_create_active_cycle(DEFAULT_ASSET_ADDRESS, Utc::now())
        .await?;
    // Take the second instant from the window the service just opened, not from the configured
    // cycle length. Reuse turns on `period_end > now`, so any interval picked here is a guess about
    // how long a window is, and a guess that is one second long opens a second cycle instead.
    let midpoint = first.period_start + (first.period_end - first.period_start) / 2;
    let second = service
        .clearing()
        .get_or_create_active_cycle(DEFAULT_ASSET_ADDRESS, midpoint.and_utc())
        .await?;

    assert_eq!(first.id, second.id);
    assert_eq!(first.status, SettlementCycleStatus::Open);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn elapsed_open_cycle_is_frozen_before_new_cycle_is_created() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let now = Utc::now().naive_utc();
    let old_id = "elapsed-open-cycle";
    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: old_id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            payment_submission_deadline: now + Duration::hours(1),
            payment_finality_deadline: now + Duration::hours(2),
        },
    )
    .await?;

    let frozen = service.clearing().freeze_elapsed_cycles().await?;
    let old_after = repo::get_cycle_by_id(ctx, old_id)
        .await?
        .expect("old cycle");

    assert_eq!(frozen, vec![old_id.to_string()]);
    assert_eq!(old_after.status, SettlementCycleStatus::Frozen);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn freeze_elapsed_cycles_is_idempotent() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let now = Utc::now().naive_utc();
    let cycle_id = "idempotent-freeze-cycle";
    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: cycle_id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            payment_submission_deadline: now + Duration::hours(1),
            payment_finality_deadline: now + Duration::hours(2),
        },
    )
    .await?;

    let first = service.clearing().freeze_elapsed_cycles().await?;
    let second = service.clearing().freeze_elapsed_cycles().await?;

    assert!(
        first.contains(&cycle_id.to_string()),
        "first run must freeze the elapsed cycle"
    );
    assert!(
        second.is_empty(),
        "second run must be a no-op — cycle is already frozen"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn computing_netting_does_not_mutate_user_collateral_balances() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let user = random_address();
    ensure_user_with_collateral(ctx, &user, U256::from(100u64)).await?;
    let locked_before = read_locked_collateral(ctx, &user, DEFAULT_ASSET_ADDRESS).await?;

    let cycle_id = "collateral-independent-netting-cycle";
    build_three_party_cycle(&service, cycle_id).await?;
    service
        .netting()
        .compute_cycle_exposure_edges(cycle_id)
        .await?;
    service
        .netting()
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    service.netting().build_clearing_batch(cycle_id).await?;

    let locked_after = read_locked_collateral(ctx, &user, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked_before, locked_after);

    Ok(())
}
