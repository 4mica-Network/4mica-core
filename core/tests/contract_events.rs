use alloy::primitives::{Address, FixedBytes, U256, keccak256};
use alloy::sol_types::SolEvent;

use alloy::providers::DynProvider;
use alloy::providers::ext::AnvilApi;
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::PersistCtx;
use entities::sea_orm_active_enums::*;
use entities::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::time::Duration;
use test_log::test;

mod common;
use crate::common::contract::Core4Mica;
use crate::common::fixtures::read_collateral;
use crate::common::setup::{
    dummy_verification_key, setup_e2e_environment, spawn_core_service_in_existing_environment,
};

static NUMBER_OF_TRIALS: u32 = 120;

fn fn_selector(sig: &str) -> FixedBytes<4> {
    let h = keccak256(sig.as_bytes());
    FixedBytes::<4>::from([h[0], h[1], h[2], h[3]])
}

async fn mine_confirmations(provider: &DynProvider, blocks: u64) -> anyhow::Result<()> {
    let finalized_depth = std::env::var("FINALIZED_HEAD_DEPTH")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let total = blocks.saturating_add(finalized_depth);
    if total > 0 {
        provider.anvil_mine(Some(total), None).await?;
    }
    Ok(())
}

/// Ensure a user row exists (idempotent).
async fn ensure_user(persist_ctx: &PersistCtx, addr: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    let am = user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        is_suspended: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
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
#[serial_test::serial]
async fn user_deposit_event_creates_user() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == deposit_amount {
            break;
        }

        if tries > 5 {
            panic!("User not updated after deposit event");
        }

        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn multiple_deposits_accumulate() -> anyhow::Result<()> {
    const NUMBER_OF_TRIALS: usize = 60;

    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    // small delay so the WS subscription is up before we emit events
    tokio::time::sleep(Duration::from_millis(150)).await;

    // strictly ensure user exists before deposit events
    ensure_user(persist_ctx, &user_addr).await?;

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
    mine_confirmations(&provider, 1).await?;
    contract
        .deposit()
        .value(amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // poll until the accumulated balance is visible
    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == expected {
            break;
        }

        if tries >= NUMBER_OF_TRIALS {
            panic!(
                "User balance not updated after deposits: expected {}, still different after {} tries",
                expected, NUMBER_OF_TRIALS
            );
        }

        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

// ────────────────────── WITHDRAWALS ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn withdrawal_request_and_cancel_events() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    // ensure user exists before deposit/withdrawal events
    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(1_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let withdraw_amount = U256::from(500_000_000_000_000_000u128);
    contract
        .requestWithdrawal_0(withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

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
            panic!("Withdrawal request not persisted");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    contract.cancelWithdrawal_0().send().await?.watch().await?;
    mine_confirmations(&provider, 1).await?;

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
            panic!("Withdrawal not cancelled in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn collateral_withdrawn_event_reduces_balance() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    // ensure user exists before deposit/withdrawal events
    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let withdraw_amount = U256::from(1_000_000_000_000_000_000u128);
    contract
        .requestWithdrawal_0(withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // advance chain time past 22 days (use delta; add a buffer)
    provider
        .anvil_set_block_timestamp_interval(23 * 24 * 60 * 60)
        .await?;
    contract
        .finalizeWithdrawal_0()
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // wait until the user collateral shows the reduced balance
    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == deposit_amount - withdraw_amount {
            break;
        }

        if tries > NUMBER_OF_TRIALS {
            panic!("Withdrawal finalization not reflected in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

//
// ────────────────────── CONFIG EVENTS (requires roles) ──────────────────────
//
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn config_update_events_do_not_crash() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let access_manager = env.access_manager.clone();
    let me = env.signer_addr;

    // Map Core4Mica config functions to USER_ADMIN_ROLE = 4
    let selectors = vec![
        fn_selector("setWithdrawalGracePeriod(uint256)"),
        fn_selector("setRemunerationGracePeriod(uint256)"),
        fn_selector("setTabExpirationTime(uint256)"),
        fn_selector("setSynchronizationDelay(uint256)"),
        fn_selector(
            "configureGuaranteeVersion(uint64,(bytes32,bytes32,bytes32,bytes32),bytes32,address,bool)",
        ),
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
    mine_confirmations(&provider, 1).await?;
    contract
        .setRemunerationGracePeriod(U256::from(7 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;
    contract
        .setTabExpirationTime(U256::from(20 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;
    contract
        .setSynchronizationDelay(U256::from(12 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn ignores_events_from_other_contract() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let access_manager = env.access_manager.clone();
    let user_addr = env.signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

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

    ensure_user(persist_ctx, &user_addr).await?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Emit a deposit on the *other* contract (B); the listener should ignore it.
    let ignored_amount = U256::from(777u64);
    contract_b
        .deposit()
        .value(ignored_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // Give the listener a moment; user balance should still be zero.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(
        current,
        U256::ZERO,
        "deposit from other contract must be ignored"
    );

    // Now emit a deposit from the watched contract (A); this one must be applied.
    let tracked_amount = U256::from(1234u64);
    contract
        .deposit()
        .value(tracked_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // Poll until applied
    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == tracked_amount {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("Deposit from the watched contract was not applied");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn listener_catches_up_on_missed_events() -> anyhow::Result<()> {
    // Setup environment with fresh DB and make first deposit
    let mut test_env = setup_e2e_environment().await?;
    let user_addr = test_env.signer_addr.to_string();
    let persist_ctx = test_env.core_service.persist_ctx();

    ensure_user(persist_ctx, &user_addr).await?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // First deposit while service is running
    let deposit_amount_1 = U256::from(1_000_000_000_000_000_000u128);
    test_env
        .contract
        .deposit()
        .value(deposit_amount_1)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&test_env.provider, 1).await?;

    // Wait for first deposit to be processed
    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == deposit_amount_1 {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("First deposit not processed");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Kill the listener
    test_env.core_service.kill_listener();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Make 2 deposits while service is down
    let deposit_amount_2 = U256::from(2_000_000_000_000_000_000u128);
    test_env
        .contract
        .deposit()
        .value(deposit_amount_2)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&test_env.provider, 1).await?;

    let deposit_amount_3 = U256::from(3_000_000_000_000_000_000u128);
    test_env
        .contract
        .deposit()
        .value(deposit_amount_3)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&test_env.provider, 1).await?;

    let core_service = spawn_core_service_in_existing_environment(&mut test_env).await?;
    let persist_ctx = core_service.persist_ctx();

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Make 4th deposit while service is running
    let deposit_amount_4 = U256::from(4_000_000_000_000_000_000u128);
    test_env
        .contract
        .deposit()
        .value(deposit_amount_4)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&test_env.provider, 1).await?;

    // Wait for the service to catch up and process the missed events
    let expected_total = deposit_amount_1 + deposit_amount_2 + deposit_amount_3 + deposit_amount_4;
    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == expected_total {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!(
                "Service did not catch up on missed events. Expected: {}, Got: {}",
                expected_total, current
            );
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Verify there are 4 CollateralDeposited events in the DB
    let deposit_sig = format!(
        "{:x}",
        core_service::ethereum::contract::CollateralDeposited::SIGNATURE_HASH
    );
    let event_count = blockchain_event::Entity::find()
        .filter(blockchain_event::Column::Signature.eq(deposit_sig))
        .all(persist_ctx.db.as_ref())
        .await?
        .len();
    assert!(
        event_count >= 4,
        "Expected at least 4 deposit blockchain events, found {}",
        event_count
    );

    Ok(())
}
