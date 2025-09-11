use crate::common::contract::AuthorityContract;
use alloy::primitives::U256;
use alloy::providers::{ProviderBuilder, WalletProvider};
use core_service::config::EthereumConfig;
use core_service::ethereum::EthereumListener;
use core_service::persist::PersistCtx;
use entities::user;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use test_log::test;

mod common;

// helper to convert U256 → f64 (safe for test amounts)
fn u256_to_f64(val: U256) -> f64 {
    let as_u128: u128 = val.try_into().expect("U256 too large for u128");
    as_u128 as f64
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn register_user_event() -> anyhow::Result<()> {
    let anvil_port = 40001u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10,
        number_of_pending_blocks: 5,
    };

    let persist_ctx = PersistCtx::new().await?;
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);

    let _tx_hash = contract
        .registerUser()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    assert!((user.collateral - u256_to_f64(deposit_amount)).abs() < 0.01);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn user_add_deposit_event() -> anyhow::Result<()> {
    let anvil_port = 40002u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10,
        number_of_pending_blocks: 5,
    };

    let persist_ctx = PersistCtx::new().await?;
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);

    contract
        .registerUser()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    contract
        .addDepositUser()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    assert!((user.collateral - (u256_to_f64(deposit_amount) * 2.0)).abs() < 0.01);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn user_add_deposit_after_contract_error() -> anyhow::Result<()> {
    let anvil_port = 40003u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10,
        number_of_pending_blocks: 5,
    };

    let persist_ctx = PersistCtx::new().await?;
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);

    contract
        .registerUser()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    let add_result = contract
        .addDepositUser()
        .value(U256::from(1000u128))
        .send()
        .await;

    if let Ok(result) = add_result {
        let _ = result.watch().await?;
    }

    let _ = contract
        .addDepositUser()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await;

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    assert!((user.collateral - (u256_to_f64(deposit_amount) * 2.0)).abs() < 0.01);

    Ok(())
}
