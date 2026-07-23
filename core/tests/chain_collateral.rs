//! On-chain collateral flows (anvil + event scanner → DB): deposits (native &
//! stablecoin), withdrawals, finalized-head gating, cursor recovery, and
//! contract-scoping of events.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::providers::ext::AnvilApi;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::ethereum::EthereumEventScanner;
use core_service::ethereum::contract::CollateralDeposited;
use core_service::ethereum::event_data::EventMeta;
use core_service::persist::{PersistCtx, repo};
use core_service::scheduler::Task;
use entities::sea_orm_active_enums::*;
use entities::*;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{sync::Arc, time::Duration};
use test_log::test;

#[path = "common/mod.rs"]
mod common;
use common::chain::{
    deposit_stablecoin, dummy_verification_key, fn_selector, mine_confirmations,
    setup_e2e_environment,
};
use common::contract::{Core4Mica, GuaranteeVerifier::GuaranteeVersionUpdated};
use common::fixtures::{ensure_user, read_collateral};

static NUMBER_OF_TRIALS: u32 = 120;

/// Poll the off-chain balance until it reaches `expected`, or panic after
/// `NUMBER_OF_TRIALS`. The scanner applies chain events on a per-second cron, so
/// tests observe DB state asynchronously.
async fn await_collateral(
    ctx: &PersistCtx,
    user_address: &str,
    expected: U256,
) -> anyhow::Result<()> {
    for _ in 0..NUMBER_OF_TRIALS {
        if read_collateral(ctx, user_address, DEFAULT_ASSET_ADDRESS).await? == expected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("collateral did not reach {expected} after {NUMBER_OF_TRIALS} tries");
}

// ════════════════════════ deposits ════════════════════════
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn user_deposit_event_creates_user() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = format!("{signer_addr:#x}");
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
#[serial_test::file_serial(db)]
async fn eth_balance_self_heals_from_reorg_double_credit() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let persist_ctx = env.core_service.persist_ctx();
    let user_addr = format!("{:#x}", env.signer_addr);
    ensure_user(persist_ctx, &user_addr).await?;

    // First deposit lands normally.
    let first = U256::from(2_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(first)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;
    await_collateral(persist_ctx, &user_addr, first).await?;

    // Simulate the reorg double-apply: the same deposit credited again under a
    // fresh event identity, as a re-mined block hash would bypass the dedup.
    repo::credit_collateral_with_event_on(
        persist_ctx.db.as_ref(),
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        first,
        CollateralEventType::Deposit,
        Some(EventMeta {
            chain_id: env.cfg.ethereum_config.chain_id,
            block_hash: "0xreorged".to_string(),
            tx_hash: "0xdeadbeef".to_string(),
            log_index: 0,
        }),
    )
    .await?;
    assert_eq!(
        read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        first * U256::from(2u8),
        "double-credit should inflate the off-chain total (bug reproduced)"
    );

    // A subsequent real deposit triggers a re-sync from chain, healing the total
    // back to the true on-chain balance rather than first * 2 + second.
    let second = U256::from(1_000_000_000_000_000_000u128);
    contract
        .deposit()
        .value(second)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;
    await_collateral(persist_ctx, &user_addr, first + second).await?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn stored_but_unhandled_event_is_reprocessed_not_skipped() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let persist_ctx = env.core_service.persist_ctx();
    let chain_id = env.cfg.ethereum_config.chain_id;
    let user_addr = format!("{:#x}", env.signer_addr);
    ensure_user(persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(3_000_000_000_000_000_000u128);
    let receipt = contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    let deposit_block = receipt
        .block_number
        .ok_or_else(|| anyhow::anyhow!("deposit receipt missing block number"))?;
    let filter = Filter::new()
        .address(*contract.address())
        .event_signature(CollateralDeposited::SIGNATURE_HASH)
        .from_block(deposit_block)
        .to_block(deposit_block);
    let logs = provider.get_logs(&filter).await?;
    let log = logs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no CollateralDeposited log in deposit block"))?;
    let block_hash = log
        .block_hash
        .ok_or_else(|| anyhow::anyhow!("log missing block hash"))?;
    let log_index = log
        .log_index
        .ok_or_else(|| anyhow::anyhow!("log missing log index"))?;
    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| anyhow::anyhow!("log missing tx hash"))?;

    let inserted = repo::store_blockchain_event(
        persist_ctx,
        chain_id,
        &format!("{:x}", CollateralDeposited::SIGNATURE_HASH),
        deposit_block,
        &format!("{:#x}", block_hash),
        &format!("{:#x}", tx_hash),
        log_index,
        &format!("{:#x}", log.address()),
        "{}",
    )
    .await?;
    assert!(
        inserted,
        "pre-insert should create a fresh blockchain_event row for the deposit"
    );
    assert_eq!(
        read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO,
        "collateral must be zero before the handler runs"
    );

    // Confirm the block. The scanner now reaches it, finds the row already stored,
    // and must still apply the deposit rather than skipping it.
    mine_confirmations(&provider, 1).await?;

    const TRIES: usize = 30;
    for _ in 0..TRIES {
        if read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await? == deposit_amount
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "deposit was never credited: a stored-but-unhandled event was skipped instead of \
         reprocessed"
    );
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn multiple_deposits_accumulate() -> anyhow::Result<()> {
    const NUMBER_OF_TRIALS: usize = 20;

    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = format!("{signer_addr:#x}");
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
#[serial_test::file_serial(db)]
async fn deposit_waits_for_finalized_head() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = format!("{signer_addr:#x}");
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
#[serial_test::file_serial(db)]
async fn listener_deletes_cursor_on_hash_mismatch_and_rescans() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let chain_id = provider.get_chain_id().await?;

    let persist_ctx = env.core_service.persist_ctx().clone();

    // Set a cursor with a mismatched hash at a real block height.
    let latest = provider.get_block_number().await?;
    repo::upsert_blockchain_event_cursor(
        &persist_ctx,
        chain_id,
        latest,
        Some("0xdeadbeef".to_string()),
    )
    .await?;
    let initial_cursor = repo::get_blockchain_event_cursor(&persist_ctx, chain_id)
        .await?
        .expect("cursor should exist after upsert");
    let initial_created_at = initial_cursor.created_at;

    let user_addr = format!("{:#x}", env.signer_addr);
    ensure_user(&persist_ctx, &user_addr).await?;

    let deposit_amount = U256::from(9_000_000_000_000_000_000u128);
    env.contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let scanner = EthereumEventScanner::new(
        env.cfg.ethereum_config.clone(),
        persist_ctx.clone(),
        env.core_service.read_provider().clone(),
        Arc::new(env.core_service.clone()),
    );

    if let Err(err) = scanner.run().await {
        let msg = err.to_string();
        if !msg.contains("Finalized block hash mismatch") {
            return Err(err);
        }
    }

    let saw_deleted = repo::get_blockchain_event_cursor(&persist_ctx, chain_id)
        .await?
        .is_none();

    scanner.run().await?;

    let cursor_after = repo::get_blockchain_event_cursor(&persist_ctx, chain_id)
        .await?
        .expect("cursor should be recreated with updated hash after rescan");
    assert_ne!(
        cursor_after.last_confirmed_block_hash.as_deref(),
        Some("0xdeadbeef"),
        "cursor hash should be updated to the correct hash"
    );
    assert!(
        saw_deleted || cursor_after.created_at > initial_created_at,
        "cursor should be deleted and recreated after hash mismatch"
    );

    let last_event = repo::get_last_processed_blockchain_event(&persist_ctx).await?;
    assert!(
        last_event.is_some(),
        "listener should store events after deleting bad cursor and rescanning"
    );

    let current = read_collateral(&persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(
        current, deposit_amount,
        "collateral should be updated after cursor deletion and rescan"
    );

    Ok(())
}

// ────────────────────── WITHDRAWALS ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn withdrawal_request_and_cancel_events() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = format!("{signer_addr:#x}");
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
#[serial_test::file_serial(db)]
async fn collateral_withdrawn_event_reduces_balance() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let signer_addr = env.signer_addr;
    let user_addr = format!("{signer_addr:#x}");
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
#[serial_test::file_serial(db)]
async fn config_update_events_do_not_crash() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let guarantee_verifier = env.guarantee_verifier.clone();
    let access_manager = env.access_manager.clone();
    let persist_ctx = env.core_service.persist_ctx();
    let chain_id = env.cfg.ethereum_config.chain_id;
    let me = env.signer_addr;

    access_manager
        .setTargetFunctionRole(
            *contract.address(),
            vec![fn_selector("setWithdrawalGracePeriod(uint256)")],
            4u64,
        )
        .send()
        .await?
        .watch()
        .await?;

    // Guarantee version configuration lives on the GuaranteeVerifier, so the role must be granted
    // against that target now — not Core4Mica.
    access_manager
        .setTargetFunctionRole(
            *guarantee_verifier.address(),
            vec![fn_selector(
                "configureGuaranteeVersion(uint64,(bytes32,bytes32,bytes32,bytes32),bytes32,address,bool)",
            )],
            4u64,
        )
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

    // Should now succeed and emit events without crashing the scanner.
    contract
        .setWithdrawalGracePeriod(U256::from(30 * 24 * 60 * 60))
        .send()
        .await?
        .watch()
        .await?;

    // Rotating a guarantee version emits from the verifier, not the vault. The scanner filters logs
    // by address, so this only lands if the verifier is in the filter — the regression this guards.
    let receipt = guarantee_verifier
        .configureGuaranteeVersion(
            1u64,
            dummy_verification_key(),
            guarantee_verifier.guaranteeDomainSeparator().call().await?,
            Address::ZERO,
            true,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    let event_block = receipt
        .block_number
        .ok_or_else(|| anyhow::anyhow!("configureGuaranteeVersion receipt missing block number"))?;
    mine_confirmations(&provider, 1).await?;

    let want = format!("{:x}", GuaranteeVersionUpdated::SIGNATURE_HASH);
    let mut tries = 0;
    loop {
        let rows =
            repo::get_blockchain_events_after(persist_ctx, chain_id, event_block - 1).await?;
        if rows.iter().any(|r| r.signature == want) {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("GuaranteeVersionUpdated from the verifier was never ingested by the scanner");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn ignores_events_from_other_contract() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let contract = env.contract.clone();
    let core_service = env.core_service.clone();
    let access_manager = env.access_manager.clone();
    let user_addr = format!("{:#x}", env.signer_addr);
    let persist_ctx = core_service.persist_ctx();

    let contract_b = Core4Mica::deploy(
        &provider,
        *access_manager.address(),
        *env.guarantee_verifier.address(),
        vec![*env.usdc.address(), *env.usdt.address()],
        alloy::primitives::U256::ZERO,
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

// ════════════════════════ stablecoin deposit / withdrawal (aToken branch) ════════════════════════

/// Depositing an ERC-20 stablecoin exercises `handle_collateral_deposited` ->
/// `sync_balance_from_chain` -> `guaranteeCapacity` (the aToken branch), which
/// the native-ETH deposit tests never reach.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn stablecoin_deposit_syncs_balance_from_chain() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let persist_ctx = env.core_service.persist_ctx();
    let user_addr = format!("{:#x}", env.signer_addr);
    let asset_addr = format!("{:#x}", env.usdc.address());
    ensure_user(persist_ctx, &user_addr).await?;

    let amount = U256::from(1_000_000u64);
    deposit_stablecoin(&env, &env.usdc, amount).await?;
    mine_confirmations(&provider, 1).await?;

    let mut tries = 0;
    loop {
        let current = read_collateral(persist_ctx, &user_addr, &asset_addr).await?;
        if current == amount {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("stablecoin deposit not synced to collateral (last={current})");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

/// Finalizing a stablecoin withdrawal exercises `handle_collateral_withdrawn`'s
/// aToken branch (`mark_withdrawal_executed_with_event`), distinct from the
/// native `finalize_withdrawal_with_event` branch.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn stablecoin_withdrawal_marks_executed() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let persist_ctx = env.core_service.persist_ctx();
    let user_addr = format!("{:#x}", env.signer_addr);
    let asset_addr = format!("{:#x}", env.usdc.address());
    let usdc_addr = *env.usdc.address();
    ensure_user(persist_ctx, &user_addr).await?;

    let amount = U256::from(2_000_000u64);
    deposit_stablecoin(&env, &env.usdc, amount).await?;
    mine_confirmations(&provider, 1).await?;

    // Wait for the deposit to be reflected before requesting a withdrawal.
    let mut tries = 0;
    loop {
        if read_collateral(persist_ctx, &user_addr, &asset_addr).await? >= amount {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("stablecoin deposit not synced before withdrawal");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let withdraw_amount = U256::from(1_000_000u64);
    env.contract
        .requestWithdrawal_1(usdc_addr, withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    // Advance past the withdrawal grace period, then finalize.
    provider
        .anvil_set_block_timestamp_interval(23 * 24 * 60 * 60)
        .await?;
    env.contract
        .finalizeWithdrawal_1(usdc_addr)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let mut tries = 0;
    loop {
        if let Some(w) = withdrawal::Entity::find()
            .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
            .filter(withdrawal::Column::AssetAddress.eq(asset_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
            && w.status == WithdrawalStatus::Executed
        {
            assert_eq!(w.executed_amount, withdraw_amount.to_string());
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("stablecoin withdrawal never marked executed");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}
