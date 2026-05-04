use alloy::primitives::U256;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{create_frozen_cycle, setup_cycle_service};
use common::fixtures::random_address;
use core_service::{config::DEFAULT_ASSET_ADDRESS, persist::repo};
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
