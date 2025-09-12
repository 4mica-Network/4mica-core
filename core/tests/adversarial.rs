use alloy::primitives::U256;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn weird_identifiers_do_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let strange_user = "'; DROP TABLE users; --".to_string();
    let strange_recipient = "0xdeadbeef::weird".to_string();

    let _ = repo::deposit(&ctx, strange_user.clone(), U256::from(1u64)).await?;
    let _ = repo::submit_payment_transaction(
        &ctx,
        strange_user.clone(),
        strange_recipient.clone(),
        "tx::id::odd".into(),
        U256::from(1u64),
    )
    .await;
    Ok(())
}
