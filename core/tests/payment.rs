use alloy::primitives::U256;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::setup_cycle_service;
use common::fixtures::{ensure_user_with_collateral, random_address};
use core_service::{config::DEFAULT_ASSET_ADDRESS, persist::repo};

#[tokio::test]
#[serial_test::file_serial(db)]
async fn recipient_payments_remain_queryable_after_tab_removal() -> anyhow::Result<()> {
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
