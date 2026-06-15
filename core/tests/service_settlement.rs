//! Service-layer settlement: participant status transitions, default handling,
//! and recipient payment queryability. No chain, no HTTP.

use alloy::primitives::U256;
use chrono::Utc;
use entities::sea_orm_active_enums::{ParticipantCycleStatus, SettlementCycleStatus};
use entities::settlement_cycle;
use sea_orm::EntityTrait;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{
    build_three_party_cycle, create_frozen_cycle, setup_cycle_service, store_payable_guarantee,
};
use common::fixtures::{
    ensure_user_with_collateral, normalize_address, random_address, read_collateral,
    read_locked_collateral, set_locked_collateral,
};
use core_service::{config::DEFAULT_ASSET_ADDRESS, evm, persist::repo};

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

/// Every participant locks the gross value of its own outgoing guarantee at
/// issuance. After a full multilateral settlement — the net debtor paying and
/// both net creditors claiming — *all* of that locked collateral must be
/// released, not just the net debtor's. This is the regression guard for the
/// leak where creditors' (and flat participants') collateral stayed locked
/// forever because settlement only freed the net debtor.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn multi_party_settlement_releases_all_locked_collateral() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let cycle_id = "collateral-release-cycle";
    let participants = build_three_party_cycle(&service, cycle_id).await?;
    let ctx = service.persist_ctx();
    let asset = DEFAULT_ASSET_ADDRESS;

    // Topology: alice->bob 10, bob->carol 4, carol->alice 1. So alice is the net
    // debtor (9) and bob/carol are net creditors (6 and 3). Each participant
    // locked the gross value of its single outgoing guarantee.
    let alice = &participants[0];
    let bob = &participants[1];
    let carol = &participants[2];
    let locks = [(alice, 10u64), (bob, 4u64), (carol, 1u64)];
    for (who, locked) in locks {
        ensure_user_with_collateral(ctx, who, U256::from(locked)).await?;
        set_locked_collateral(ctx, who, asset, U256::from(locked)).await?;
    }

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

    let onchain = evm::cycle_id_hash(cycle_id);

    // Drive the real on-chain-event handlers: debtor pays, creditors claim.
    service.process_paid_debtor(onchain, alice, "0xpay").await?;
    service
        .process_credit_claim(onchain, bob, "0xclaim-bob")
        .await?;
    service
        .process_credit_claim(onchain, carol, "0xclaim-carol")
        .await?;

    // Finalize for good measure; the sweep must be a no-op here (nothing left).
    service.finalize_cycle(cycle_id).await?;

    for (who, original) in locks {
        assert_eq!(
            read_locked_collateral(ctx, who, asset).await?,
            U256::ZERO,
            "locked collateral not released for {who}"
        );
        assert_eq!(
            read_collateral(ctx, who, asset).await?,
            U256::from(original),
            "total collateral changed for {who}"
        );
    }
    assert!(
        repo::list_netted_guarantees_for_cycle_on(ctx.db.as_ref(), cycle_id)
            .await?
            .is_empty(),
        "no guarantee should remain Netted after settlement"
    );

    Ok(())
}

/// When every participant nets flat, no debtor-payment or creditor-claim event
/// ever fires, yet their collateral is locked. Cycle finalization must sweep the
/// residual `Netted` guarantees and release that collateral.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn finalize_cycle_sweeps_residual_netted_collateral() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let asset = DEFAULT_ASSET_ADDRESS;
    let cycle_id = create_frozen_cycle(ctx, "flat-sweep-cycle").await?;

    // a->b 10 and b->a 10 fully offset: both participants are flat.
    let a = random_address();
    let b = random_address();
    store_payable_guarantee(ctx, &cycle_id, &a, &b, 10, 0).await?;
    store_payable_guarantee(ctx, &cycle_id, &b, &a, 10, 1).await?;
    let a = normalize_address(&a)?;
    let b = normalize_address(&b)?;
    for who in [&a, &b] {
        ensure_user_with_collateral(ctx, who, U256::from(10u64)).await?;
        set_locked_collateral(ctx, who, asset, U256::from(10u64)).await?;
    }

    service.compute_cycle_exposure_edges(&cycle_id).await?;
    service
        .compute_cycle_participant_positions(&cycle_id)
        .await?;
    service.build_clearing_batch(&cycle_id).await?;
    assert!(service.mark_cycle_netting_computed(&cycle_id).await?);
    assert!(
        repo::mark_cycle_payment_window_open_on(
            ctx.db.as_ref(),
            &cycle_id,
            None,
            Utc::now().naive_utc(),
        )
        .await?
    );

    service.finalize_cycle(&cycle_id).await?;

    for who in [&a, &b] {
        assert_eq!(
            read_locked_collateral(ctx, who, asset).await?,
            U256::ZERO,
            "flat participant {who} collateral not released on finalize"
        );
    }
    assert!(
        repo::list_netted_guarantees_for_cycle_on(ctx.db.as_ref(), &cycle_id)
            .await?
            .is_empty(),
        "finalize should sweep all residual netted guarantees"
    );
    let cycle = settlement_cycle::Entity::find_by_id(cycle_id.clone())
        .one(ctx.db.as_ref())
        .await?
        .expect("cycle exists");
    assert_eq!(cycle.status, SettlementCycleStatus::Finalized);

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
