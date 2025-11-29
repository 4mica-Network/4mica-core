use alloy::primitives::U256;
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::error::PersistDbError;
use core_service::persist::{PersistCtx, repo};
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    AppConfig::fetch()
}

#[test(tokio::test)]
#[serial_test::serial]
async fn weird_identifiers_do_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;

    let strange_user = "'; DROP TABLE users; --".to_string();
    let strange_recipient = "0xdeadbeef::weird".to_string();

    match repo::deposit(
        &ctx,
        strange_user.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(1u64),
    )
    .await
    {
        Err(PersistDbError::InvariantViolation(_)) => {}
        Ok(_) => panic!("deposit unexpectedly succeeded for non-existent user"),
        Err(e) => panic!("unexpected error from deposit: {e}"),
    }

    match repo::submit_payment_transaction(
        &ctx,
        strange_user.clone(),
        strange_recipient.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        "tx::id::odd".into(),
        U256::from(1u64),
    )
    .await
    {
        Err(PersistDbError::InvariantViolation(_)) => {}
        Ok(_) => panic!("submit_payment_transaction unexpectedly succeeded for non-existent user"),
        Err(e) => panic!("unexpected error from submit_payment_transaction: {e}"),
    }

    Ok(())
}
