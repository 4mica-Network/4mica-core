use alloy::primitives::{Address, FixedBytes, U256, keccak256};

use alloy::providers::ext::AnvilApi;
use alloy::providers::{DynProvider, Provider};
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::sea_orm_active_enums::*;
use entities::*;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::time::Duration;
use test_log::test;

mod common;
use crate::common::contract::Core4Mica;
use crate::common::fixtures::read_collateral;
use crate::common::setup::{dummy_verification_key, setup_e2e_environment};

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
    const NUMBER_OF_TRIALS: usize = 20;

    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    // strictly ensure user exists before deposit events
    ensure_user(persist_ctx, &user_addr).await?;

    let amount = U256::from(1_000_000_000_000_000_000u128);
    let expected = amount * U256::from(3u8);

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
        .value(amount * U256::from(2u8))
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

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn deposit_waits_for_finalized_head() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(5_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    // Without confirmations, finalized head should not include this deposit yet.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(
        current,
        U256::ZERO,
        "deposit should not be persisted before finalized head advances"
    );

    mine_confirmations(&provider, 1).await?;

    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        if current == deposit_amount {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("Deposit not persisted after finalized head advanced");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn listener_deletes_cursor_on_hash_mismatch_and_rescans() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let chain_id = provider.get_chain_id().await?;

    let persist_ctx = env.core_service.persist_ctx();

    // Set a cursor with a mismatched hash at a real block height.
    let latest = provider.get_block_number().await?;
    repo::upsert_blockchain_event_cursor(
        persist_ctx,
        chain_id,
        latest,
        Some("0xdeadbeef".to_string()),
    )
    .await?;
    let initial_cursor = repo::get_blockchain_event_cursor(persist_ctx, chain_id)
        .await?
        .expect("cursor should exist after upsert");
    let initial_created_at = initial_cursor.created_at;

    let user_addr = env.signer_addr.to_string();
    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(9_000_000_000_000_000_000u128);
    env.contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let mut saw_deleted = false;
    let mut cursor_after = None;
    let mut tries = 0;
    while tries < 40 {
        let cursor = repo::get_blockchain_event_cursor(persist_ctx, chain_id).await?;
        match cursor {
            None => {
                saw_deleted = true;
            }
            Some(cursor) => {
                if cursor.last_confirmed_block_hash.as_deref() != Some("0xdeadbeef") {
                    cursor_after = Some(cursor);
                    break;
                }
            }
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let cursor_after =
        cursor_after.expect("cursor should be recreated with updated hash after rescan");
    assert_ne!(
        cursor_after.last_confirmed_block_hash.as_deref(),
        Some("0xdeadbeef"),
        "cursor hash should be updated to the correct hash"
    );
    assert!(
        saw_deleted || cursor_after.created_at > initial_created_at,
        "cursor should be deleted and recreated after hash mismatch"
    );

    let last_event = repo::get_last_processed_blockchain_event(persist_ctx).await?;
    assert!(
        last_event.is_some(),
        "listener should store events after deleting bad cursor and rescanning"
    );

    let current = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(
        current, deposit_amount,
        "collateral should be updated after cursor deletion and rescan"
    );

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
