use alloy::network::TransactionBuilder;
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy_primitives::{Address, B256};
use blockchain::txtools::PaymentTx;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::{PersistCtx, repo};
use entities::{
    sea_orm_active_enums::{SettlementStatus, TabStatus},
    tabs, user_transaction,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::{str::FromStr, time::Duration};
use test_log::test;

mod common;
use crate::common::fixtures::{clear_all_tables, read_collateral, read_locked_collateral};
use crate::common::setup::{E2eEnvironment, setup_e2e_environment};

static NUMBER_OF_TRIALS: u32 = 60;
//
// ────────────────────── HELPERS ──────────────────────
//

fn parse_u256(s: &str) -> U256 {
    U256::from_str(s).expect("invalid numeric string")
}

fn unique_addr() -> String {
    Address::random().to_string()
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
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
        ttl: Set(3600i64),
    };

    tabs::Entity::insert(tab).exec(ctx.db.as_ref()).await?;
    Ok(())
}

//
// ────────────────────── TESTS ──────────────────────
//

/// `PaymentRecorded` → user transaction created.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn payment_transaction_creates_user_transaction() -> anyhow::Result<()> {
    let E2eEnvironment {
        provider,
        core_service,
        signer_addr,
        scheduler: _scheduler,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();
    let user_addr = signer_addr.to_string();

    let server_addr = unique_addr();

    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        persist_ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(1000u64),
    )
    .await?;

    // Insert dummy tab so the listener can match it
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(persist_ctx, tab_id, &user_addr, &server_addr).await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let amount = U256::from(10u64);

    let balance =
        repo::get_user_balance_on(persist_ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS)
            .await?;
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>().unwrap(),
        amount,
    )
    .await?;

    let req_id = U256::from(1);
    let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
    let tx = TransactionRequest::default()
        .with_to(server_addr.parse().unwrap())
        .with_value(amount)
        .with_input(input.into_bytes());

    provider.send_transaction(tx).await?.watch().await?;

    // poll DB
    let mut tries = 0;
    loop {
        if let Some(tx) = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
        {
            assert_eq!(parse_u256(&tx.amount), amount);
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("Transaction not recorded in DB");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

/// Same event twice → only one DB row (idempotent).
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn record_payment_event_is_idempotent() -> anyhow::Result<()> {
    let E2eEnvironment {
        provider,
        core_service,
        signer_addr,
        scheduler: _scheduler,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();
    let user_addr = signer_addr.to_string();

    let server_addr = unique_addr();

    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        persist_ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(1000u64),
    )
    .await?;

    // Insert dummy tab
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(persist_ctx, tab_id, &user_addr, &server_addr).await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let amount = U256::from(25u64);

    let balance =
        repo::get_user_balance_on(persist_ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS)
            .await?;
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>().unwrap(),
        amount,
    )
    .await?;

    let req_id = U256::from(1);
    let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
    let tx = TransactionRequest::default()
        .with_to(server_addr.parse().unwrap())
        .with_value(amount)
        .with_input(input.into_bytes());

    provider.send_transaction(tx).await?.watch().await?;

    let mut tries = 0;
    let tx_record = loop {
        if let Some(tx) = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
            .one(persist_ctx.db.as_ref())
            .await?
        {
            assert_eq!(parse_u256(&tx.amount), amount);
            break tx;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("recordPayment not idempotent: transaction not recorded");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // Simulate the same blockchain event being processed again (e.g. due to a reorg)
    repo::submit_payment_transaction(
        persist_ctx,
        user_addr.clone(),
        server_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        tx_record.tx_id.clone(),
        amount,
    )
    .await?;

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
        .all(persist_ctx.db.as_ref())
        .await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(parse_u256(&txs[0].amount), amount);
    assert_eq!(txs[0].tx_id, tx_record.tx_id);

    Ok(())
}

/// Payments originating from a non-tab user must be ignored by the scanner.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn payments_from_wrong_user_are_ignored() -> anyhow::Result<()> {
    let E2eEnvironment {
        core_service,
        signer_addr,
        scheduler: _scheduler,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();

    let expected_user = unique_addr();
    let server_addr = unique_addr();

    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &expected_user).await?;
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(persist_ctx, tab_id, &expected_user, &server_addr).await?;

    let payment = PaymentTx {
        block_number: 1,
        tx_hash: B256::ZERO,
        from: signer_addr,
        to: Address::from_str(&server_addr)?,
        amount: U256::from(42u64),
        tab_id,
        req_id: U256::ZERO,
        erc20_token: None,
    };

    core_service
        .handle_discovered_payments(vec![payment])
        .await?;

    let tx_rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(expected_user.clone()))
        .all(persist_ctx.db.as_ref())
        .await?;
    assert!(
        tx_rows.is_empty(),
        "unexpected user transactions recorded: {:?}",
        tx_rows
    );

    let tab = tabs::Entity::find_by_id(format!("{tab_id:#x}"))
        .one(persist_ctx.db.as_ref())
        .await?
        .expect("tab not found");
    assert_eq!(tab.settlement_status, SettlementStatus::Pending);

    clear_all_tables(persist_ctx).await?;
    Ok(())
}

/// PaymentRecorded does NOT reduce collateral (record only).
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn payment_transaction_does_not_reduce_collateral() -> anyhow::Result<()> {
    let E2eEnvironment {
        provider,
        core_service,
        signer_addr,
        scheduler: _scheduler,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();
    let user_addr = signer_addr.to_string();

    let server_addr = unique_addr();

    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;

    let start_collateral = U256::from(500u64);
    repo::deposit(
        persist_ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        start_collateral,
    )
    .await?;

    // Insert dummy tab
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(persist_ctx, tab_id, &user_addr, &server_addr).await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let amount = U256::from(100u64);

    let balance =
        repo::get_user_balance_on(persist_ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS)
            .await?;
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>().unwrap(),
        amount,
    )
    .await?;

    let req_id = U256::from(1);
    let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
    let tx = TransactionRequest::default()
        .with_to(server_addr.parse().unwrap())
        .with_value(amount)
        .with_input(input.into_bytes());
    provider.send_transaction(tx).await?.watch().await?;

    let mut tries = 0;
    loop {
        let collateral = read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
        // recordPayment should NOT alter collateral
        if collateral == start_collateral {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("Collateral unexpectedly changed after PaymentRecorded");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::serial]
async fn payment_transaction_unlocks_collateral() -> anyhow::Result<()> {
    let E2eEnvironment {
        provider,
        core_service,
        signer_addr,
        scheduler: _scheduler,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();
    let user_addr = signer_addr.to_string();

    let server_addr = unique_addr();

    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;

    let start_collateral = U256::from(500u64);
    repo::deposit(
        persist_ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        start_collateral,
    )
    .await?;

    // Insert dummy tab
    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(persist_ctx, tab_id, &user_addr, &server_addr).await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    // Lock 100 ETH
    let balance =
        repo::get_user_balance_on(persist_ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS)
            .await?;
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>().unwrap(),
        U256::from(100u64),
    )
    .await?;

    // Pay 60 ETH
    let req_id = U256::from(1);
    let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
    let tx = TransactionRequest::default()
        .with_to(server_addr.parse().unwrap())
        .with_value(U256::from(60u64))
        .with_input(input.into_bytes());
    provider.send_transaction(tx).await?.watch().await?;

    let mut tries = 0;
    loop {
        let locked = read_locked_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;

        // locked should now be 40 ETH (100 - 60)
        if locked == U256::from(40u64) {
            break;
        }
        if tries > NUMBER_OF_TRIALS {
            panic!("Collateral unexpectedly changed after PaymentRecorded");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}
