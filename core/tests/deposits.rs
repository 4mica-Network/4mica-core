use alloy::primitives::U256;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{build_three_party_cycle, setup_cycle_service};
use common::fixtures::{ensure_user_with_collateral, random_address, read_locked_collateral};
use core_service::config::DEFAULT_ASSET_ADDRESS;

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
    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    service.build_clearing_batch(cycle_id).await?;

    let locked_after = read_locked_collateral(ctx, &user, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked_before, locked_after);

    Ok(())
}
