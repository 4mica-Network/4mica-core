use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use blockchain::txtools::PaymentTx;
use core_service::{
    config::DEFAULT_ASSET_ADDRESS, persist::repo, service::payment::process_discovered_payment,
};
use entities::{tabs, user_transaction};
use rand::random;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
#[path = "common/mod.rs"]
mod common;
use common::fixtures::{clear_all_tables, ensure_user, init_test_env, random_address};
use common::setup::setup_e2e_environment;

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn process_discovered_payment_creates_pending_transaction() -> anyhow::Result<()> {
    let (_config, ctx) = init_test_env().await?;
    clear_all_tables(&ctx).await?;

    let now = chrono::Utc::now().naive_utc();
    let user_addr = random_address();
    let server_addr = Address::from_str(&random_address())?;
    let server_addr_str = server_addr.to_string();

    ensure_user(&ctx, &user_addr).await?;

    let tab_id = U256::from(42u64);
    let tab_am = tabs::ActiveModel {
        id: Set(format!("{:#x}", tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(server_addr_str.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        ttl: Set(300),
    };
    tabs::Entity::insert(tab_am).exec(ctx.db.as_ref()).await?;

    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let payment = PaymentTx {
        block_number: 1,
        block_hash: None,
        tx_hash,
        from: Address::from_str(&user_addr)?,
        to: server_addr,
        amount: U256::from(10u64),
        tab_id,
        req_id: U256::ZERO,
        erc20_token: None,
    };
    let tx_hash_str = format!("{:#x}", tx_hash);

    process_discovered_payment(&ctx, payment).await?;

    let tx_row = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_hash_str))
        .one(ctx.db.as_ref())
        .await?
        .expect("transaction should exist");

    assert_eq!(tx_row.status, "pending");
    assert!(!tx_row.finalized, "transaction should not be finalized");
    assert!(!tx_row.verified, "transaction should not be verified");
    assert!(!tx_row.failed, "transaction should not be failed");
    assert_eq!(tx_row.block_number, Some(1));
    assert!(tx_row.block_hash.is_none());
    assert!(tx_row.confirmed_at.is_none());

    clear_all_tables(&ctx).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn process_discovered_payment_is_idempotent() -> anyhow::Result<()> {
    let (_config, ctx) = init_test_env().await?;
    clear_all_tables(&ctx).await?;

    let now = chrono::Utc::now().naive_utc();
    let user_addr = random_address();
    let server_addr = Address::from_str(&random_address())?;
    let server_addr_str = server_addr.to_string();

    ensure_user(&ctx, &user_addr).await?;

    let tab_id = U256::from(43u64);
    let tab_am = tabs::ActiveModel {
        id: Set(format!("{:#x}", tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(server_addr_str.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        ttl: Set(300),
    };
    tabs::Entity::insert(tab_am).exec(ctx.db.as_ref()).await?;

    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let payment = PaymentTx {
        block_number: 1,
        block_hash: None,
        tx_hash,
        from: Address::from_str(&user_addr)?,
        to: server_addr,
        amount: U256::from(10u64),
        tab_id,
        req_id: U256::ZERO,
        erc20_token: None,
    };
    let tx_hash_str = format!("{:#x}", tx_hash);

    process_discovered_payment(&ctx, payment.clone()).await?;
    process_discovered_payment(&ctx, payment).await?;

    let tx_rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_hash_str.clone()))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(tx_rows.len(), 1, "transaction should be unique");
    assert_eq!(tx_rows[0].status, "pending");

    clear_all_tables(&ctx).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn record_payment_skips_when_asset_mismatched() -> anyhow::Result<()> {
    let (_config, ctx) = init_test_env().await?;
    clear_all_tables(&ctx).await?;

    let now = chrono::Utc::now().naive_utc();
    let user_addr = random_address();
    let server_addr = Address::from_str(&random_address())?;
    let server_addr_str = server_addr.to_string();

    ensure_user(&ctx, &user_addr).await?;

    let tab_asset = random_address();
    let mut payment_asset = random_address();
    while tab_asset == payment_asset {
        payment_asset = random_address();
    }

    let tab_id = U256::from(44u64);
    let tab_am = tabs::ActiveModel {
        id: Set(format!("{:#x}", tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(server_addr_str.clone()),
        asset_address: Set(tab_asset.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        ttl: Set(300),
    };
    tabs::Entity::insert(tab_am).exec(ctx.db.as_ref()).await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let payment = PaymentTx {
        block_number: 1,
        block_hash: None,
        tx_hash,
        from: Address::from_str(&user_addr)?,
        to: server_addr,
        amount: U256::from(10u64),
        tab_id,
        req_id: U256::ZERO,
        erc20_token: Some(Address::from_str(&payment_asset)?),
    };
    let tx_hash_str = format!("{:#x}", tx_hash);

    process_discovered_payment(&ctx, payment).await?;

    let tx_row = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_hash_str.clone()))
        .one(ctx.db.as_ref())
        .await?;
    assert!(tx_row.is_none(), "mismatched asset should be ignored");

    clear_all_tables(&ctx).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn reorg_does_not_mutate_without_finality() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let core_service = env.core_service.clone();

    let persist_ctx = core_service.persist_ctx();
    let chain_id = provider.get_chain_id().await?;
    let latest = provider.get_block_number().await?;
    let safe_head = latest.saturating_sub(1);

    repo::upsert_chain_cursor(persist_ctx, chain_id, safe_head, "0xdeadbeef".to_string()).await?;

    let user_address = random_address();
    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_address).await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let tx_hash_str = format!("{:#x}", tx_hash);
    let tab_id = U256::from(777u64);

    repo::submit_pending_payment_transaction(
        persist_ctx,
        repo::PendingPaymentInput {
            user_address,
            recipient_address: random_address(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            transaction_id: tx_hash_str.clone(),
            amount: U256::from(10u64),
            tab_id: format!("{:#x}", tab_id),
            block_number: safe_head,
            block_hash: None,
        },
    )
    .await?;

    core_service.confirm_pending_payments().await?;

    let tx_row = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_hash_str))
        .one(persist_ctx.db.as_ref())
        .await?
        .expect("transaction should exist");

    assert_eq!(tx_row.status, "pending");

    clear_all_tables(persist_ctx).await?;
    Ok(())
}
