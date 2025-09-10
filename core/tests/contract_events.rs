use crate::common::contract::AuthorityContract;
use alloy::providers::{ProviderBuilder, WalletProvider};
use core_service::config::EthereumConfig;
use core_service::ethereum::EthereumListener;
use core_service::persist::PersistCtx;
use log::info;
use test_log::test;
// SeaORM bits
use entities::user;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

mod common;

// cargo test --test contract_events {test_name} -- --nocapture

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn register_user_event() -> anyhow::Result<()> {
    let anvil_port = 40001u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();
    info!("Wallet default signer address: {user_addr}");

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10u64,
        number_of_pending_blocks: 5u64,
    };

    let persist_ctx = PersistCtx::new().await?;

    info!("Spawning listener...");
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = 2e18 as u128;

    let tx_hash = contract
        .registerUser()
        .value(deposit_amount.try_into()?)
        .send()
        .await?
        .watch()
        .await?;

    info!("Tx hash: {tx_hash}");

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    // Listener should have written the collateral
    assert!(user.collateral - (deposit_amount as f64) < 0.01f64);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn user_add_deposit_event() -> anyhow::Result<()> {
    let anvil_port = 4000u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();
    info!("Wallet default signer address: {user_addr}");

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10u64,
        number_of_pending_blocks: 5u64,
    };

    let persist_ctx = PersistCtx::new().await?;

    info!("Spawning listener...");
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = 2e18 as u128;

    contract
        .registerUser()
        .value(deposit_amount.try_into()?)
        .send()
        .await?
        .watch()
        .await?;

    contract
        .addDepositUser()
        .value(deposit_amount.try_into()?)
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

    assert!(user.collateral - (deposit_amount as f64 * 2f64) < 0.01f64);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn user_add_deposit_after_contract_error() -> anyhow::Result<()> {
    let anvil_port = 4000u16;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;
    let contract = AuthorityContract::deploy(&provider).await?;

    let user_addr = provider.default_signer_address().to_string();
    info!("Wallet default signer address: {user_addr}");

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 10u64,
        number_of_pending_blocks: 5u64,
    };

    let persist_ctx = PersistCtx::new().await?;

    info!("Spawning listener...");
    EthereumListener::new(eth_config, persist_ctx.clone())
        .run()
        .await?;

    let deposit_amount = 2e18 as u128; // In wei

    contract
        .registerUser()
        .value(deposit_amount.try_into()?)
        .send()
        .await?
        .watch()
        .await?;

    let add_result = contract
        .addDepositUser()
        .value(1000u128.try_into()?) // In wei
        .send()
        .await;

    info!("First addDeposit result: {:?}", add_result);

    if let Ok(result) = add_result {
        result.watch().await?;
    }

    info!("Sending second addDeposit request...");

    let add_result = contract
        .addDepositUser()
        .value(deposit_amount.try_into()?)
        .send()
        .await?
        .watch()
        .await;

    info!("Second addDeposit result: {:?}", add_result);

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    assert!(user.collateral - (deposit_amount as f64 * 2f64) < 0.01f64);

    Ok(())
}
