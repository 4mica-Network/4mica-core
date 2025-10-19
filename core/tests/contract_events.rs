use alloy::primitives::{Address, FixedBytes, U256, keccak256};

use alloy::providers::ext::AnvilApi;
use alloy::providers::{ProviderBuilder, WalletProvider};
use anyhow::anyhow;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::config::EthereumConfig;
use core_service::ethereum::EthereumListener;
use core_service::persist::PersistCtx;
use core_service::service::CoreService;
use entities::sea_orm_active_enums::*;
use entities::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serial_test::serial;
use std::str::FromStr;
use test_log::test;
use tokio::task::JoinHandle;

mod common;
use crate::common::contract::{AccessManager, Core4Mica};

static NUMBER_OF_TRIALS: u32 = 120;

fn parse_collateral(val: &str) -> U256 {
    U256::from_str(val).expect("invalid collateral stored in DB")
}

fn fn_selector(sig: &str) -> FixedBytes<4> {
    let h = keccak256(sig.as_bytes());
    FixedBytes::<4>::from([h[0], h[1], h[2], h[3]])
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

fn dummy_stablecoins() -> (Address, Address) {
    let usdc = Address::with_last_byte(0x11);
    let usdt = Address::with_last_byte(0x22);
    (usdc, usdt)
}

//
// ────────────────────── ENV INIT ──────────────────────
//
fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    // also try parent folder when running from core/tests
    dotenv::from_filename("../.env").ok();
    let cfg = AppConfig::fetch();
    let contract = Address::from_str(&cfg.ethereum_config.contract_address)
        .map_err(|e| anyhow!("invalid contract address: {}", e))?;
    crypto::guarantee::init_guarantee_domain_separator(cfg.ethereum_config.chain_id, contract)?;
    Ok(cfg)
}

/// Start the Ethereum listener in the background for tests, and return a handle you can abort.
fn start_listener(eth_config: EthereumConfig, persist_ctx: PersistCtx) -> JoinHandle<()> {
    tokio::spawn(async move {
        let provider = CoreService::build_ws_provider(eth_config.clone())
            .await
            .expect("failed to connect to Ethereum provider");

        // Ignore the result; the listener is a long-running task with its own retry loop.
        let _ = EthereumListener::new(eth_config, persist_ctx, provider)
            .run()
            .await;
    })
}

/// Ensure a user row exists (idempotent).
async fn ensure_user(persist_ctx: &PersistCtx, addr: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    let am = user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
    };
    user::Entity::insert(am)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(persist_ctx.db.as_ref())
        .await?;
    Ok(())
}

//
// ────────────────────── DEPOSITS ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn user_deposit_event_creates_user() -> anyhow::Result<()> {
    init()?;
    let anvil_port = 40101u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1, // faster confirmations for tests
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let persist_ctx = PersistCtx::new().await?;
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;

    // start listener in the background
    let listener = start_listener(eth_config, persist_ctx.clone());

    // strictly ensure user exists before a deposit event is processed
    ensure_user(&persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    let mut tries = 0;
    loop {
        if let Some(u) = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
        {
            let current = parse_collateral(&u.collateral);
            if current == deposit_amount {
                break;
            }
        }

        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("User not updated after deposit event");
        }

        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // stop listener
    listener.abort();
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn multiple_deposits_accumulate() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};

    const NUMBER_OF_TRIALS: usize = 60;

    init()?;
    let anvil_port = 40102u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };

    let persist_ctx = PersistCtx::new().await?;

    // clean DB
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());
    // small delay so the WS subscription is up before we emit events
    sleep(Duration::from_millis(150)).await;

    // strictly ensure user exists before deposit events
    ensure_user(&persist_ctx, &user_addr).await?;

    let amount = U256::from(1_000_000_000_000_000_000u128);
    let expected = amount * U256::from(2u8);

    // two deposits
    contract
        .deposit()
        .value(amount)
        .send()
        .await?
        .watch()
        .await?;
    contract
        .deposit()
        .value(amount)
        .send()
        .await?
        .watch()
        .await?;

    // poll until the accumulated balance is visible
    let mut tries = 0;
    loop {
        if let Some(u) = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
        {
            let current = parse_collateral(&u.collateral);
            if current == expected {
                break;
            }
        }

        if tries >= NUMBER_OF_TRIALS {
            listener.abort();
            panic!(
                "User balance not updated after deposits: expected {}, still different after {} tries",
                expected, NUMBER_OF_TRIALS
            );
        }

        tries += 1;
        sleep(Duration::from_millis(500)).await;
    }

    listener.abort();
    Ok(())
}

// ────────────────────── WITHDRAWALS ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn withdrawal_request_and_cancel_events() -> anyhow::Result<()> {
    init()?;
    let anvil_port = 40110u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let persist_ctx = PersistCtx::new().await?;
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());

    // ensure user exists before deposit/withdrawal events
    ensure_user(&persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(1_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    let withdraw_amount = U256::from(500_000_000_000_000_000u128);
    contract
        .requestWithdrawal(withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;

    let mut tries = 0;
    loop {
        if let Some(w) = withdrawal::Entity::find()
            .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
        {
            assert_eq!(w.requested_amount, withdraw_amount.to_string());
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Withdrawal request not persisted");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    contract.cancelWithdrawal().send().await?.watch().await?;

    let mut tries = 0;
    loop {
        if withdrawal::Entity::find()
            .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
            .is_some_and(|w| w.status == WithdrawalStatus::Cancelled)
        {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Withdrawal not cancelled in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    listener.abort();
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn collateral_withdrawn_event_reduces_balance() -> anyhow::Result<()> {
    init()?;
    let anvil_port = 40111u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let persist_ctx = PersistCtx::new().await?;

    // clean DB
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());

    // ensure user exists before deposit/withdrawal events
    ensure_user(&persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    let withdraw_amount = U256::from(1_000_000_000_000_000_000u128);
    contract
        .requestWithdrawal(withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;

    // advance chain time past 22 days (use delta; add a buffer)
    provider
        .anvil_set_block_timestamp_interval(23 * 24 * 60 * 60)
        .await?;
    contract.finalizeWithdrawal().send().await?.watch().await?;

    // wait until the user collateral shows the reduced balance
    let mut tries = 0;
    loop {
        if user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
            .is_some_and(|u| parse_collateral(&u.collateral) == deposit_amount - withdraw_amount)
        {
            break;
        }

        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Withdrawal finalization not reflected in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    listener.abort();
    Ok(())
}

//
// ────────────────────── CONFIG EVENTS (requires roles) ──────────────────────
//
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn config_update_events_do_not_crash() -> anyhow::Result<()> {
    init()?;
    let anvil_port = 40113u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let me = provider.default_signer_address();

    // Map Core4Mica config functions to USER_ADMIN_ROLE = 4
    let selectors = vec![
        fn_selector("setWithdrawalGracePeriod(uint256)"),
        fn_selector("setRemunerationGracePeriod(uint256)"),
        fn_selector("setTabExpirationTime(uint256)"),
        fn_selector("setSynchronizationDelay(uint256)"),
    ];
    access_manager
        .setTargetFunctionRole(*contract.address(), selectors, 4u64)
        .send()
        .await?
        .watch()
        .await?;

    // Grant USER_ADMIN_ROLE to our test signer (no delay)
    access_manager
        .grantRole(4u64, me, 0u32)
        .send()
        .await?
        .watch()
        .await?;

    // Should now succeed and emit eSome(chrono::Utc::now().timestamp() as u64),vents
    contract
        .setWithdrawalGracePeriod(U256::from(30 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    contract
        .setRemunerationGracePeriod(U256::from(7 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    contract
        .setTabExpirationTime(U256::from(20 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    contract
        .setSynchronizationDelay(U256::from(12 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn ignores_events_from_other_contract() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};

    init()?;
    let anvil_port = 40130u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // Deploy two Core4Mica contracts
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc_a, usdt_a) = dummy_stablecoins();
    let contract_a = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc_a,
        usdt_a,
    )
    .await?;
    let usdc_b = Address::with_last_byte(0x33);
    let usdt_b = Address::with_last_byte(0x44);
    let contract_b = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc_b,
        usdt_b,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    // Listener configured to only watch contract A.
    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract_a.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };

    let persist_ctx = PersistCtx::new().await?;

    // Clean DB and ensure user exists with 0 balance
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    ensure_user(&persist_ctx, &user_addr).await?;

    // Start listener
    let listener = start_listener(eth_config, persist_ctx.clone());
    sleep(Duration::from_millis(200)).await;

    // Emit a deposit on the *other* contract (B); the listener should ignore it.
    let ignored_amount = U256::from(777u64);
    contract_b
        .deposit()
        .value(ignored_amount)
        .send()
        .await?
        .watch()
        .await?;

    // Give the listener a moment; user balance should still be zero.
    sleep(Duration::from_millis(500)).await;
    if let Some(u) = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(persist_ctx.db.as_ref())
        .await?
    {
        assert_eq!(
            parse_collateral(&u.collateral),
            U256::ZERO,
            "deposit from other contract must be ignored"
        );
    }

    // Now emit a deposit from the watched contract (A); this one must be applied.
    let tracked_amount = U256::from(1234u64);
    contract_a
        .deposit()
        .value(tracked_amount)
        .send()
        .await?
        .watch()
        .await?;

    // Poll until applied
    let mut tries = 0;
    loop {
        if user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
            .is_some_and(|u| parse_collateral(&u.collateral) == tracked_amount)
        {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Deposit from the watched contract was not applied");
        }
        tries += 1;
        sleep(Duration::from_millis(250)).await;
    }

    listener.abort();
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn listener_restart_still_processes_events() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};

    init()?;
    let anvil_port = 40133u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let (usdc, usdt) = dummy_stablecoins();
    let contract = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        dummy_verification_key(),
        usdc,
        usdt,
    )
    .await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        chain_id: 1,
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        cron_job_settings: "0 */1 * * * *".to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };
    let persist_ctx = PersistCtx::new().await?;

    // Clean DB and ensure user
    user_transaction::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    guarantee::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    collateral_event::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    withdrawal::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    tabs::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    user::Entity::delete_many()
        .exec(persist_ctx.db.as_ref())
        .await?;
    ensure_user(&persist_ctx, &user_addr).await?;

    // Start and immediately stop the listener
    let listener1 = start_listener(eth_config.clone(), persist_ctx.clone());
    sleep(Duration::from_millis(100)).await;
    listener1.abort();

    // Start a fresh listener
    let listener2 = start_listener(eth_config, persist_ctx.clone());
    sleep(Duration::from_millis(150)).await;

    // Emit a deposit and ensure it's processed by the restarted listener
    let amount = U256::from(555u64);
    contract
        .deposit()
        .value(amount)
        .send()
        .await?
        .watch()
        .await?;

    let mut tries = 0;
    loop {
        if user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
            .is_some_and(|u| parse_collateral(&u.collateral) == amount)
        {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener2.abort();
            panic!("Restarted listener did not process events");
        }
        tries += 1;
        sleep(Duration::from_millis(200)).await;
    }

    listener2.abort();
    Ok(())
}
