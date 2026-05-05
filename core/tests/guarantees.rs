use entities::sea_orm_active_enums::GuaranteeSettlementStatus;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{
    create_frozen_cycle, setup_cycle_service, store_payable_guarantee, store_pending_guarantee,
};
use common::fixtures::random_address;
use core_service::persist::repo;

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
