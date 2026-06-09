//! Service-layer netting: bilateral exposure offsetting, clearing-batch
//! construction, asset scoping, and guarantee identity/exclusion. No chain.

use std::collections::BTreeMap;

use alloy::primitives::U256;
use chrono::{Duration, Utc};
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus,
};

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{
    build_three_party_cycle, create_frozen_cycle, setup_cycle_service, store_payable_guarantee,
    store_pending_guarantee,
};
use common::fixtures::{ensure_user, normalize_address, random_address};
use core_service::persist::{CycleGuaranteeData, repo};

const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

#[tokio::test]
#[serial_test::file_serial(db)]
async fn cycle_netting_offsets_bilateral_exposures_into_net_positions() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "three-party-netting-cycle";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    assert_eq!(edges.len(), 3);

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    let by_participant = positions
        .into_iter()
        .map(|position| (position.participant.clone(), position))
        .collect::<BTreeMap<_, _>>();

    let alice = by_participant
        .get(&participants[0])
        .expect("alice position");
    assert_eq!(alice.net_debit, "9");
    assert_eq!(alice.role, ParticipantCycleRole::NetDebtor);
    assert_eq!(alice.status, ParticipantCycleStatus::Unpaid);

    let bob = by_participant.get(&participants[1]).expect("bob position");
    assert_eq!(bob.net_credit, "6");
    assert_eq!(bob.role, ParticipantCycleRole::NetCreditor);
    assert_eq!(bob.status, ParticipantCycleStatus::Claimable);

    let carol = by_participant
        .get(&participants[2])
        .expect("carol position");
    assert_eq!(carol.net_credit, "3");
    assert_eq!(carol.role, ParticipantCycleRole::NetCreditor);
    assert_eq!(carol.status, ParticipantCycleStatus::Claimable);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn clearing_batch_balances_total_net_debit_and_credit() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "clearing-batch-cycle";
    build_three_party_cycle(&service, cycle_id).await?;

    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    let batch = service.build_clearing_batch(cycle_id).await?;

    assert_eq!(batch.total_net_debit, "9");
    assert_eq!(batch.total_net_credit, "9");
    assert_eq!(batch.debtor_count, 1);
    assert_eq!(batch.creditor_count, 2);
    assert!(batch.merkle_root.starts_with("0x"));

    Ok(())
}

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
    ensure_user(ctx, &payer).await?;
    ensure_user(ctx, &payee).await?;

    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        CycleGuaranteeData {
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
            settlement_status: GuaranteeSettlementStatus::FinalizedPayable,
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

#[tokio::test]
#[serial_test::file_serial(db)]
async fn cycle_guarantees_are_identified_by_guarantee_id() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "guarantee-identity-cycle").await?;
    let payer = random_address();
    let payee = random_address();

    let guarantee_id = store_payable_guarantee(ctx, &cycle_id, &payer, &payee, 7, 11).await?;
    let stored = repo::get_guarantee_by_id_on(ctx.db.as_ref(), &guarantee_id)
        .await?
        .expect("guarantee stored");

    assert_eq!(stored.guarantee_id, guarantee_id);
    assert_eq!(stored.cycle_id, cycle_id);
    assert_eq!(stored.req_id, "0xb");
    assert_eq!(stored.value, "7");
    assert_eq!(
        stored.settlement_status,
        GuaranteeSettlementStatus::FinalizedPayable
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn pending_validation_guarantee_excluded_from_cycle_netting() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "pending-excluded-netting-cycle").await?;
    let payer = random_address();
    let payee = random_address();

    store_payable_guarantee(ctx, &cycle_id, &payer, &payee, 10, 0).await?;
    store_pending_guarantee(ctx, &cycle_id, &payer, &payee, 5, 1).await?;

    service.compute_cycle_exposure_edges(&cycle_id).await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;
    assert_eq!(
        edges.len(),
        1,
        "only FinalizedPayable guarantees produce edges"
    );
    assert_eq!(edges[0].finalized_payable_amount, "10");

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn marking_cycle_netting_computed_moves_payable_guarantees_to_netted() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "guarantee-netted-cycle").await?;
    let payer = random_address();
    let payee = random_address();
    let guarantee_id = store_payable_guarantee(ctx, &cycle_id, &payer, &payee, 13, 0).await?;

    assert!(service.mark_cycle_netting_computed(&cycle_id).await?);
    let stored = repo::get_guarantee_by_id_on(ctx.db.as_ref(), &guarantee_id)
        .await?
        .expect("guarantee stored");

    assert_eq!(stored.settlement_status, GuaranteeSettlementStatus::Netted);

    Ok(())
}
