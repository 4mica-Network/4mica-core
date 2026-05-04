use chrono::Utc;
use entities::sea_orm_active_enums::{ParticipantCycleStatus, SettlementCycleStatus};
use entities::settlement_cycle;
use sea_orm::EntityTrait;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{build_three_party_cycle, setup_cycle_service};
use core_service::persist::repo;

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
