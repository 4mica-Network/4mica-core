use alloy::primitives::{Address, U256};
use anyhow::anyhow;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::{PersistCtx, repo};
use std::str::FromStr;
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    let cfg = AppConfig::fetch();
    let contract = Address::from_str(&cfg.ethereum_config.contract_address)
        .map_err(|e| anyhow!("invalid contract address: {}", e))?;
    crypto::guarantee::init_guarantee_domain_separator(cfg.ethereum_config.chain_id, contract)?;
    Ok(cfg)
}

#[test(tokio::test)]
async fn weird_identifiers_do_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;

    let strange_user = "'; DROP TABLE users; --".to_string();
    let strange_recipient = "0xdeadbeef::weird".to_string();

    match repo::deposit(&ctx, strange_user.clone(), U256::from(1u64)).await {
        Err(PersistDbError::UserNotFound(_)) => {}
        Ok(_) => panic!("deposit unexpectedly succeeded for non-existent user"),
        Err(e) => panic!("unexpected error from deposit: {e}"),
    }

    match repo::submit_payment_transaction(
        &ctx,
        strange_user.clone(),
        strange_recipient.clone(),
        "tx::id::odd".into(),
        U256::from(1u64),
    )
    .await
    {
        Err(PersistDbError::UserNotFound(_)) => {}
        Ok(_) => panic!("submit_payment_transaction unexpectedly succeeded for non-existent user"),
        Err(e) => panic!("unexpected error from submit_payment_transaction: {e}"),
    }

    Ok(())
}
