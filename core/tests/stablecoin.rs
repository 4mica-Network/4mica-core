use alloy::primitives::U256;
use chrono::{Duration, Utc};

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{normalize_address, setup_cycle_service};
use common::fixtures::random_address;
use core_service::persist::repo;
use entities::sea_orm_active_enums::SettlementCycleStatus;

const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

#[tokio::test]
#[serial_test::file_serial(db)]
async fn netting_cycles_are_scoped_by_asset_address() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let now = Utc::now().naive_utc();
    let cycle_id = "stable-asset-cycle";

    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: cycle_id.to_string(),
            asset_address: STABLE_ASSET_ADDRESS.to_string(),
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            payment_submission_deadline: now + Duration::hours(1),
            payment_finality_deadline: now + Duration::hours(2),
        },
    )
    .await?;
    assert!(repo::freeze_cycle_on(ctx.db.as_ref(), cycle_id, now).await?);

    let payer = random_address();
    let payee = random_address();
    let payer = normalize_address(&payer)?;
    let payee = normalize_address(&payee)?;
    common::fixtures::ensure_user(ctx, &payer).await?;
    common::fixtures::ensure_user(ctx, &payee).await?;

    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        core_service::persist::CycleGuaranteeData {
            guarantee_id: "stable-guarantee".to_string(),
            cycle_id: cycle_id.to_string(),
            req_id: U256::ZERO,
            version: 2,
            from: payer,
            to: payee,
            asset: STABLE_ASSET_ADDRESS.to_string(),
            value: U256::from(8u64),
            start_ts: now,
            cert: "{}".to_string(),
            request: None,
            settlement_status:
                entities::sea_orm_active_enums::GuaranteeSettlementStatus::FinalizedPayable,
        },
    )
    .await?;

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    let cycle = repo::get_cycle_by_id(ctx, cycle_id)
        .await?
        .expect("cycle exists");
    assert_eq!(cycle.asset_address, STABLE_ASSET_ADDRESS);
    assert_eq!(cycle.status, SettlementCycleStatus::Frozen);
    assert_eq!(cycle.gross_payable_amount, "8");

    Ok(())
}
