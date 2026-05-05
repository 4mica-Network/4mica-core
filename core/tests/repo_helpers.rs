use alloy::primitives::U256;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{create_frozen_cycle, setup_cycle_service};
use common::fixtures::{ensure_user, init_test_env, random_address};
use core_service::{config::DEFAULT_ASSET_ADDRESS, error::PersistDbError, persist::repo};
use entities::sea_orm_active_enums::{ParticipantCycleRole, ParticipantCycleStatus};

#[tokio::test]
#[serial_test::file_serial(db)]
async fn replacing_cycle_exposure_edges_is_idempotent() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "edge-replace-cycle").await?;
    let payer = random_address();
    let payee = random_address();

    let edge = repo::CycleExposureEdgeInput {
        cycle_id: cycle_id.clone(),
        payer: payer.clone(),
        payee: payee.clone(),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        gross_amount: U256::from(5u64),
        finalized_payable_amount: U256::from(5u64),
        disputed_amount: U256::ZERO,
        cancelled_amount: U256::ZERO,
        guarantee_count: 1,
    };

    repo::replace_cycle_exposure_edges_on(ctx.db.as_ref(), &cycle_id, vec![edge.clone()]).await?;
    repo::replace_cycle_exposure_edges_on(ctx.db.as_ref(), &cycle_id, vec![edge]).await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].gross_amount, "5");

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn replacing_participant_positions_removes_stale_rows() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "position-replace-cycle").await?;
    let first = random_address();
    let second = random_address();

    repo::replace_cycle_participant_positions_on(
        ctx.db.as_ref(),
        &cycle_id,
        vec![
            repo::CycleParticipantPositionInput {
                cycle_id: cycle_id.clone(),
                participant: first,
                asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
                gross_outgoing: U256::from(2u64),
                gross_incoming: U256::ZERO,
                net_debit: U256::from(2u64),
                net_credit: U256::ZERO,
                role: ParticipantCycleRole::NetDebtor,
                status: ParticipantCycleStatus::Unpaid,
            },
            repo::CycleParticipantPositionInput {
                cycle_id: cycle_id.clone(),
                participant: second.clone(),
                asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
                gross_outgoing: U256::ZERO,
                gross_incoming: U256::from(2u64),
                net_debit: U256::ZERO,
                net_credit: U256::from(2u64),
                role: ParticipantCycleRole::NetCreditor,
                status: ParticipantCycleStatus::Claimable,
            },
        ],
    )
    .await?;

    repo::replace_cycle_participant_positions_on(
        ctx.db.as_ref(),
        &cycle_id,
        vec![repo::CycleParticipantPositionInput {
            cycle_id: cycle_id.clone(),
            participant: second,
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            gross_outgoing: U256::ZERO,
            gross_incoming: U256::from(3u64),
            net_debit: U256::ZERO,
            net_credit: U256::from(3u64),
            role: ParticipantCycleRole::NetCreditor,
            status: ParticipantCycleStatus::Claimable,
        }],
    )
    .await?;

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;
    assert_eq!(positions.len(), 1);
    assert_eq!(positions[0].net_credit, "3");

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn get_user_balance_on_fails_for_nonexistent_user() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let addr = random_address();

    let err = repo::get_user_balance_on(ctx.db.as_ref(), &addr, DEFAULT_ASSET_ADDRESS)
        .await
        .expect_err("must fail for unknown user");

    assert!(
        matches!(err, PersistDbError::UserNotFound(_)),
        "expected UserNotFound, got: {err:?}"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn update_user_suspension_increments_version() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let addr = random_address();
    ensure_user(&ctx, &addr).await?;

    let after_suspend = repo::update_user_suspension(&ctx, &addr, true).await?;
    assert!(after_suspend.is_suspended);
    assert_eq!(after_suspend.version, 1);

    let after_unsuspend = repo::update_user_suspension(&ctx, &addr, false).await?;
    assert!(!after_unsuspend.is_suspended);
    assert_eq!(after_unsuspend.version, 2);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn store_blockchain_event_duplicate_returns_false() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    let first = repo::store_blockchain_event(
        &ctx,
        1,
        "Transfer(address,address,uint256)",
        100,
        "0xblock",
        "0xtx",
        0,
        "0x0000000000000000000000000000000000000001",
        "{}",
    )
    .await?;

    let second = repo::store_blockchain_event(
        &ctx,
        1,
        "Transfer(address,address,uint256)",
        100,
        "0xblock",
        "0xtx",
        0,
        "0x0000000000000000000000000000000000000001",
        "{}",
    )
    .await?;

    assert!(first, "first insert must return true");
    assert!(!second, "duplicate insert must return false");

    Ok(())
}
