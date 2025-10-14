use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{ProviderBuilder, WalletProvider};
use anyhow::anyhow;
use core_service::{
    config::{AppConfig, EthereumConfig},
    ethereum::EthereumListener,
    persist::{PersistCtx, repo},
};
use entities::{
    sea_orm_active_enums::{SettlementStatus, TabStatus},
    tabs, user, user_transaction,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serial_test::serial;
use std::{str::FromStr, time::Duration};
use test_log::test;
use tokio::task::JoinHandle;

mod common;
use crate::common::contract::{AccessManager, Core4Mica};

static NUMBER_OF_TRIALS: u32 = 60;

//
// ────────────────────── HELPERS ──────────────────────
//

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    let cfg = AppConfig::fetch();
    let contract = Address::from_str(&cfg.ethereum_config.contract_address)
        .map_err(|e| anyhow!("invalid contract address: {}", e))?;
    crypto::guarantee::init_guarantee_domain_separator(cfg.ethereum_config.chain_id, contract)?;
    Ok(cfg)
}

fn dummy_verification_key() -> (
    FixedBytes<32>,
    FixedBytes<32>,
    FixedBytes<32>,
    FixedBytes<32>,
) {
    (
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
    )
}

fn start_listener(eth_config: EthereumConfig, persist_ctx: PersistCtx) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = EthereumListener::new(eth_config, persist_ctx).run().await;
    })
}

fn parse_u256(s: &str) -> U256 {
    U256::from_str(s).expect("invalid numeric string")
}

fn unique_addr() -> String {
    format!("0x{:040x}", rand::random::<u128>())
}

/// Clean DB tables
async fn clean_db(ctx: &PersistCtx) -> anyhow::Result<()> {
    use entities::*;
    user_transaction::Entity::delete_many()
        .exec(ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many().exec(ctx.db.as_ref()).await?;
    user::Entity::delete_many().exec(ctx.db.as_ref()).await?;
    Ok(())
}

/// Insert a dummy tab so the listener can resolve user/server addresses.
async fn insert_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    user_addr: &str,
    server_addr: &str,
) -> anyhow::Result<()> {
    use chrono::Utc;
    let now = Utc::now().naive_utc();

    let tab = tabs::ActiveModel {
        id: Set(format!("{tab_id:#x}")),
        user_address: Set(user_addr.to_string()),
        server_address: Set(server_addr.to_string()),
        start_ts: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
        ttl: Set(3600i64),
        ..Default::default()
    };

    tabs::Entity::insert(tab).exec(ctx.db.as_ref()).await?;
    Ok(())
}

//
// ────────────────────── TESTS ──────────────────────
//

/// `PaymentRecorded` → user transaction created.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn record_payment_event_creates_user_transaction() -> anyhow::Result<()> {
    use tokio::time::sleep;
    init()?;

    let anvil_port = 40210u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // deploy contracts
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
    )
    .await?;

    let user_addr = unique_addr();
    let server_addr = unique_addr();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".into(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let ctx = PersistCtx::new().await?;
    clean_db(&ctx).await?;
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(1000u64)).await?;

    // Insert dummy tab so the listener can match it
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(&ctx, tab_id, &user_addr, &server_addr).await?;

    // start listener
    let listener = start_listener(eth_config, ctx.clone());
    sleep(Duration::from_millis(250)).await;

    let amount = U256::from(10u64);
    contract
        .recordPayment(tab_id, amount)
        .send()
        .await?
        .watch()
        .await?;

    // poll DB
    let mut tries = 0;
    loop {
        if let Some(tx) = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
            .one(ctx.db.as_ref())
            .await?
        {
            assert_eq!(parse_u256(&tx.amount), amount);
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Transaction not recorded in DB");
        }
        tries += 1;
        sleep(Duration::from_millis(500)).await;
    }

    listener.abort();
    Ok(())
}

/// Same event twice → only one DB row (idempotent).
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn record_payment_event_is_idempotent() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};
    init()?;

    let anvil_port = 40211u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
    )
    .await?;

    let user_addr = unique_addr();
    let server_addr = unique_addr();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".into(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let ctx = PersistCtx::new().await?;
    clean_db(&ctx).await?;
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(1000u64)).await?;

    // Insert dummy tab
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(&ctx, tab_id, &user_addr, &server_addr).await?;

    let listener = start_listener(eth_config, ctx.clone());
    sleep(Duration::from_millis(250)).await;

    let amount = U256::from(25u64);
    contract
        .recordPayment(tab_id, amount)
        .send()
        .await?
        .watch()
        .await?;

    let mut tries = 0;
    let tx_record = loop {
        if let Some(tx) = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
            .one(ctx.db.as_ref())
            .await?
        {
            assert_eq!(parse_u256(&tx.amount), amount);
            break tx;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("recordPayment not idempotent: transaction not recorded");
        }
        tries += 1;
        sleep(Duration::from_millis(500)).await;
    };

    // Simulate the same blockchain event being processed again (e.g. due to a reorg)
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        server_addr.clone(),
        tx_record.tx_id.clone(),
        amount,
    )
    .await?;

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(parse_u256(&txs[0].amount), amount);
    assert_eq!(txs[0].tx_id, tx_record.tx_id);

    listener.abort();
    Ok(())
}

/// PaymentRecorded does NOT reduce collateral (record only).
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn record_payment_event_does_not_reduce_collateral() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};
    init()?;

    let anvil_port = 40212u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
    )
    .await?;

    let user_addr = unique_addr();
    let server_addr = unique_addr();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".into(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let ctx = PersistCtx::new().await?;
    clean_db(&ctx).await?;
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;

    let start_collateral = U256::from(500u64);
    repo::deposit(&ctx, user_addr.clone(), start_collateral).await?;

    // Insert dummy tab
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(&ctx, tab_id, &user_addr, &server_addr).await?;

    let listener = start_listener(eth_config, ctx.clone());
    sleep(Duration::from_millis(250)).await;

    let amount = U256::from(100u64);
    contract
        .recordPayment(tab_id, amount)
        .send()
        .await?
        .watch()
        .await?;

    let mut tries = 0;
    loop {
        if let Some(u) = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(ctx.db.as_ref())
            .await?
        {
            // recordPayment should NOT alter collateral
            if parse_u256(&u.collateral) == start_collateral {
                break;
            }
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Collateral unexpectedly changed after PaymentRecorded");
        }
        tries += 1;
        sleep(Duration::from_millis(500)).await;
    }

    listener.abort();
    Ok(())
}
