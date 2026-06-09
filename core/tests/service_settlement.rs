//! Service-layer settlement: participant status transitions, default handling,
//! and recipient payment queryability. No chain, no HTTP.

use alloy::primitives::U256;
use chrono::Utc;
use entities::sea_orm_active_enums::{ParticipantCycleStatus, SettlementCycleStatus};
use entities::settlement_cycle;
use sea_orm::EntityTrait;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{build_three_party_cycle, setup_cycle_service};
use common::fixtures::{ensure_user_with_collateral, random_address};
use core_service::{config::DEFAULT_ASSET_ADDRESS, persist::repo};

#[tokio::test]
#[serial_test::file_serial(db)]
async fn debtor_payment_and_creditor_claim_advance_participant_statuses() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "participant-settlement-cycle";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    service.build_clearing_batch(cycle_id).await?;
    assert!(service.mark_cycle_netting_computed(cycle_id).await?);
    assert!(
        repo::mark_cycle_payment_window_open_on(
            ctx.db.as_ref(),
            cycle_id,
            Some("0xcommit".to_string()),
            Utc::now().naive_utc(),
        )
        .await?
    );

    assert!(
        repo::mark_participant_position_status_on(
            ctx.db.as_ref(),
            cycle_id,
            &participants[0],
            ParticipantCycleStatus::Unpaid,
            ParticipantCycleStatus::Paid,
            Some("0xpaid".to_string()),
            Utc::now().naive_utc(),
        )
        .await?
    );
    assert!(
        repo::mark_participant_position_status_on(
            ctx.db.as_ref(),
            cycle_id,
            &participants[1],
            ParticipantCycleStatus::Claimable,
            ParticipantCycleStatus::Claimed,
            Some("0xclaim".to_string()),
            Utc::now().naive_utc(),
        )
        .await?
    );

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    assert!(
        positions
            .iter()
            .any(|p| p.participant == participants[0] && p.status == ParticipantCycleStatus::Paid)
    );
    assert!(
        positions.iter().any(
            |p| p.participant == participants[1] && p.status == ParticipantCycleStatus::Claimed
        )
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn unpaid_debtors_move_payment_window_cycle_to_defaulted() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "defaulted-cycle";
    build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    service.build_clearing_batch(cycle_id).await?;
    assert!(service.mark_cycle_netting_computed(cycle_id).await?);
    assert!(
        repo::mark_cycle_payment_window_open_on(
            ctx.db.as_ref(),
            cycle_id,
            Some("0xcommit".to_string()),
            Utc::now().naive_utc(),
        )
        .await?
    );
    assert!(
        repo::mark_cycle_defaulted_on(ctx.db.as_ref(), cycle_id, Utc::now().naive_utc()).await?
    );

    let cycle = settlement_cycle::Entity::find_by_id(cycle_id.to_string())
        .one(ctx.db.as_ref())
        .await?
        .expect("cycle exists");
    assert_eq!(cycle.status, SettlementCycleStatus::Defaulted);

    Ok(())
}

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
