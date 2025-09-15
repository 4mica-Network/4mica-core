use alloy::primitives::{FixedBytes, U256, keccak256};
use alloy::providers::Provider;
use alloy::providers::ext::AnvilApi;
use alloy::providers::{ProviderBuilder, WalletProvider};
use alloy::rpc::types::BlockNumberOrTag;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::config::EthereumConfig;
use core_service::ethereum::EthereumListener;
use core_service::persist::PersistCtx;
use entities::sea_orm_active_enums::*;
use entities::*;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serial_test::serial;
use std::str::FromStr;
use test_log::test;
use tokio::task::JoinHandle; // for aborting the background listener

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

//
// ────────────────────── ENV INIT ──────────────────────
//
fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    // also try parent folder when running from core/tests
    dotenv::from_filename("../.env").ok();
    Ok(AppConfig::fetch())
}

/// Start the Ethereum listener in the background for tests, and return a handle you can abort.
fn start_listener(eth_config: EthereumConfig, persist_ctx: PersistCtx) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Ignore the result; the listener is a long-running task with its own retry loop.
        let _ = EthereumListener::new(eth_config, persist_ctx).run().await;
    })
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
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1, // faster confirmations for tests
        number_of_pending_blocks: 1,
    };
    let persist_ctx = PersistCtx::new().await?;
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    // start listener in the background
    let listener = start_listener(eth_config, persist_ctx.clone());

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
            .one(&*persist_ctx.db)
            .await?
        {
            assert_eq!(parse_collateral(&u.collateral), deposit_amount);
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("User not created after deposit event");
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

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
    };

    let persist_ctx = PersistCtx::new().await?;

    // clean DB
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());
    // small delay so the WS subscription is up before we emit events
    sleep(Duration::from_millis(150)).await;

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
            .one(&*persist_ctx.db)
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
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
    };
    let persist_ctx = PersistCtx::new().await?;
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());

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
            .one(&*persist_ctx.db)
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
        if let Some(w) = withdrawal::Entity::find()
            .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
            .one(&*persist_ctx.db)
            .await?
        {
            assert_eq!(w.status, WithdrawalStatus::Cancelled);
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
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
    let user_addr = provider.default_signer_address().to_string();

    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
    };
    let persist_ctx = PersistCtx::new().await?;

    // clean DB
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());

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
        if let Some(u) = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*persist_ctx.db)
            .await?
        {
            if parse_collateral(&u.collateral) == deposit_amount - withdraw_amount {
                break;
            }
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
// ────────────────────── REMUNERATION ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn recipient_remunerated_event_is_persisted() -> anyhow::Result<()> {
    init()?;
    let anvil_port = 40112u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;

    // Clean DB
    let persist_ctx = PersistCtx::new().await?;
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    //  Start listener
    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
    };
    let listener = start_listener(eth_config, persist_ctx.clone());

    let tab_id = "1".to_string();
    let now = Utc::now().naive_utc();
    let user_addr = provider.default_signer_address().to_string();

    // Deposit so listener creates the user
    contract
        .deposit()
        .value(U256::from(10_000u64))
        .send()
        .await?
        .watch()
        .await?;

    // Wait until user is in DB
    let mut tries = 0;
    while tries < NUMBER_OF_TRIALS {
        if user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*persist_ctx.db)
            .await?
            .is_some()
        {
            break;
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if tries == NUMBER_OF_TRIALS {
        listener.abort();
        panic!("User not created in DB from deposit");
    }

    // Insert only the tab
    let t_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    tabs::Entity::insert(t_am).exec(&*persist_ctx.db).await?;

    // Move chain time well beyond any default grace period.
    let expiration_secs: u64 = 21 * 24 * 60 * 60;
    provider
        .anvil_increase_time((expiration_secs - 2 * 24 * 60 * 60) as u64)
        .await?;
    provider.anvil_mine(Some(1), None).await?;

    // Get latest timestamp after the jump
    let latest_after_jump = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("no latest block");
    let current_ts: u64 = latest_after_jump.header.timestamp;

    // Query grace/expiration periods from the contract
    let grace: u64 = contract.remunerationGracePeriod().call().await?.to::<u64>();
    let expiry: u64 = contract.tabExpirationTime().call().await?.to::<u64>();

    // Choose a delta that is:
    //   >= grace (overdue)
    //   <  expiry (not expired)
    let one_day = 24 * 60 * 60;
    let overdue_delta = std::cmp::min(grace + one_day, expiry - 1);
    let tab_ts = current_ts - overdue_delta;

    let g = Core4Mica::Guarantee {
        tab_id: U256::from_str(&tab_id)?,
        tab_timestamp: U256::from(tab_ts),
        client: user_addr.parse()?,
        recipient: user_addr.parse()?,
        req_id: U256::from(1u64),
        amount: U256::from(1000u64),
    };
    let sig = [[0u8; 32].into(), [0u8; 32].into(), [0u8; 32].into()];

    // Call remunerate
    contract.remunerate(g, sig).send().await?.watch().await?;

    // Verify remuneration persisted
    let mut tries = 0;
    loop {
        let events = collateral_event::Entity::find()
            .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
            .all(&*persist_ctx.db)
            .await?;
        if !events.is_empty() {
            assert_eq!(events[0].amount, "1000");
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Remuneration not persisted");
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
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
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

    // Should now succeed and emit events
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
async fn withdrawal_requested_vs_executed_amount_differs() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    init()?;
    let anvil_port = 40120u16;
    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.block_time(1).port(anvil_port))?;

    // Deploy contracts
    let access_manager =
        AccessManager::deploy(&provider, provider.default_signer_address()).await?;
    let contract = Core4Mica::deploy(&provider, *access_manager.address()).await?;
    let user_addr = provider.default_signer_address().to_string();

    // Start the EthereumListener
    let eth_config = EthereumConfig {
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        contract_address: contract.address().to_string(),
        number_of_blocks_to_confirm: 1,
        number_of_pending_blocks: 1,
    };
    let persist_ctx = PersistCtx::new().await?;
    // clean DB
    user_transaction::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    guarantee::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    collateral_event::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    withdrawal::Entity::delete_many()
        .exec(&*persist_ctx.db)
        .await?;
    tabs::Entity::delete_many().exec(&*persist_ctx.db).await?;
    user::Entity::delete_many().exec(&*persist_ctx.db).await?;

    // start listener
    let listener = start_listener(eth_config, persist_ctx.clone());

    let ten_eth = U256::from(10_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(ten_eth)
        .send()
        .await?
        .watch()
        .await?;

    // Wait until user is persisted
    let mut tries = 0;
    while user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*persist_ctx.db)
        .await?
        .is_none()
    {
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("User not created after deposit");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let eight_eth = U256::from(8_000_000_000_000_000_000u128);
    contract
        .requestWithdrawal(eight_eth)
        .send()
        .await?
        .watch()
        .await?;

    // Capture the request timestamp from chain
    let req_block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("no latest block");
    let req_ts: u64 = req_block.header.timestamp;

    // Read timing params
    let sync_delay: u64 = contract.synchronizationDelay().call().await?.to::<u64>();
    let grace: u64 = contract.remunerationGracePeriod().call().await?.to::<u64>();
    let withdraw_grace: u64 = contract.withdrawalGracePeriod().call().await?.to::<u64>();

    let tab_ts: u64 = req_ts + sync_delay + 1;

    // Insert tab in DB so listener can attach events
    let tab_id_str = 43u64.to_string();
    let now = Utc::now().naive_utc();
    let t_am = entities::tabs::ActiveModel {
        id: Set(tab_id_str.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    tabs::Entity::insert(t_am).exec(&*persist_ctx.db).await?;

    // Advance time so the tab is OVERDUE but NOT EXPIRED relative to tab_ts.
    // We must move at least sync_delay + grace after the withdrawal request,
    // so that:  block.timestamp ≥ tab_ts + remunerationGracePeriod.
    let jump = sync_delay + grace + 3600; // +1h safety margin
    provider.anvil_increase_time(jump as u64).await?;
    provider.anvil_mine(Some(1), None).await?;

    // Now call remunerate(4 ETH). Since tab_ts >= wr.ts + syncDelay,
    // the request amount is NOT shrunk.
    let g = Core4Mica::Guarantee {
        tab_id: U256::from(43u64),
        tab_timestamp: U256::from(tab_ts),
        client: user_addr.parse()?,
        recipient: user_addr.parse()?,
        req_id: U256::from(1u64),
        amount: U256::from(4_000_000_000_000_000_000u128), // 4 ETH
    };
    let sig = [[0u8; 32].into(), [0u8; 32].into(), [0u8; 32].into()];
    contract.remunerate(g, sig).send().await?.watch().await?;

    // Ensure we pass wr.timestamp + withdrawalGracePeriod.
    provider
        .anvil_increase_time((withdraw_grace + 2 * 24 * 60 * 60) as u64)
        .await?;
    provider.anvil_mine(Some(1), None).await?;

    contract.finalizeWithdrawal().send().await?.watch().await?;

    let six_eth = U256::from(6_000_000_000_000_000_000u128);

    let mut tries = 0;
    loop {
        if let Some(w) = withdrawal::Entity::find()
            .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
            .one(&*persist_ctx.db)
            .await?
        {
            if w.status == WithdrawalStatus::Executed {
                let u = user::Entity::find()
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .one(&*persist_ctx.db)
                    .await?
                    .unwrap();

                let executed = U256::from_str(w.executed_amount.as_str())?;
                let requested = U256::from_str(&w.requested_amount)?;

                assert_eq!(requested, eight_eth, "requested amount unchanged");
                assert_eq!(
                    executed, six_eth,
                    "executed amount = min(requested, remaining collateral) = 6 ETH"
                );
                assert_eq!(
                    parse_collateral(&u.collateral),
                    U256::ZERO,
                    "collateral reduced exactly by executed amount"
                );
                break;
            }
        }
        if tries > NUMBER_OF_TRIALS {
            listener.abort();
            panic!("Withdrawal execution not reflected in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    listener.abort();
    Ok(())
}
