use chrono::{Duration, Utc};
use entities::sea_orm_active_enums::SettlementCycleStatus;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::setup_cycle_service;
use core_service::{config::DEFAULT_ASSET_ADDRESS, persist::repo};

#[tokio::test]
#[serial_test::file_serial(db)]
async fn active_cycle_creation_reuses_open_cycle_for_same_asset() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let now = Utc::now();

    let first = service
        .get_or_create_active_cycle(DEFAULT_ASSET_ADDRESS, now)
        .await?;
    let second = service
        .get_or_create_active_cycle(DEFAULT_ASSET_ADDRESS, now + Duration::minutes(1))
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

    let frozen = service.freeze_elapsed_cycles().await?;
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

    let first = service.freeze_elapsed_cycles().await?;
    let second = service.freeze_elapsed_cycles().await?;

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
