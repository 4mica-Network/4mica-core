use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::providers::ext::AnvilApi;
use alloy::rpc::types::TransactionRequest;
use blockchain::txtools::PaymentTx;
use chrono::Utc;
use core_service::{
    config::DEFAULT_ASSET_ADDRESS, persist::repo, service::payment::process_discovered_payment,
};
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus, UserTransactionStatus};
use entities::{tabs, user_transaction};
use rand::random;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
#[path = "common/mod.rs"]
mod common;
use common::fixtures::{clear_all_tables, ensure_user, init_test_env, random_address};
use common::setup::setup_e2e_environment;

#[test_log::test(tokio::test)]
#[serial_test::file_serial]
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
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(1)),
        version: Set(1),
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
        block_timestamp: None,
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

    assert_eq!(tx_row.status, UserTransactionStatus::Pending);
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
#[serial_test::file_serial]
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
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(1)),
        version: Set(1),
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
        block_timestamp: None,
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
    assert_eq!(tx_rows[0].status, UserTransactionStatus::Pending);

    clear_all_tables(&ctx).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial]
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
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(1)),
        version: Set(1),
        ttl: Set(300),
    };
    tabs::Entity::insert(tab_am).exec(ctx.db.as_ref()).await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let payment = PaymentTx {
        block_number: 1,
        block_hash: None,
        block_timestamp: None,
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
#[serial_test::file_serial]
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

    assert_eq!(tx_row.status, UserTransactionStatus::Pending);

    clear_all_tables(persist_ctx).await?;
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial]
async fn confirm_pending_payment_rejects_reverted_receipt() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let core_service = env.core_service.clone();
    let contract = env.contract.clone();
    let persist_ctx = core_service.persist_ctx();

    let user_address = format!("{:#x}", env.signer_addr);
    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_address).await?;

    let recipient_address = Address::random();
    // Runtime bytecode: PUSH1 0x00 PUSH1 0x00 REVERT.
    provider
        .anvil_set_code(
            recipient_address,
            Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd]),
        )
        .await?;

    let tab_id = U256::from(9_001u64);
    let amount = U256::from(1_000u64);
    let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, U256::from(1u64));
    let tx = TransactionRequest::default()
        .with_to(recipient_address)
        .with_value(amount)
        .with_input(input.into_bytes())
        .with_gas_limit(50_000);

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();
    let receipt = pending_tx.get_receipt().await?;
    assert!(!receipt.status(), "test transaction must be reverted");

    provider.anvil_mine(Some(2), None).await?;

    repo::submit_pending_payment_transaction(
        persist_ctx,
        repo::PendingPaymentInput {
            user_address,
            recipient_address: recipient_address.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            transaction_id: format!("{:#x}", tx_hash),
            amount,
            tab_id: format!("{:#x}", tab_id),
            block_number: receipt
                .block_number
                .expect("reverted transaction should have a block number"),
            block_hash: receipt.block_hash.map(|hash| format!("{:#x}", hash)),
        },
    )
    .await?;

    core_service.confirm_pending_payments().await?;

    let tx_row = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(format!("{:#x}", tx_hash)))
        .one(persist_ctx.db.as_ref())
        .await?
        .expect("transaction should exist");
    assert_eq!(tx_row.status, UserTransactionStatus::Reverted);

    let payment_status = contract.getPaymentStatus(tab_id).call().await?;
    assert_eq!(payment_status.paid, U256::ZERO);

    clear_all_tables(persist_ctx).await?;
    Ok(())
}

// Regression test: a RECORDED tx whose record_tx_block_hash was stored as the
// zero hash (B256::ZERO) must finalize rather than be marked REVERTED.
// This reproduces the bug where the proxy returned a zero block hash before
// the tx was included in a block, causing a spurious hash-mismatch revert.
#[test_log::test(tokio::test)]
#[serial_test::file_serial]
async fn finalize_recorded_payment_with_zero_block_hash_does_not_revert() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let core_service = env.core_service.clone();
    let persist_ctx = core_service.persist_ctx();

    let user_addr = format!("{:#x}", env.signer_addr);
    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        persist_ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    // Send a real tx on Anvil to get a real tx hash and block number.
    let recipient = Address::random();
    let tx = TransactionRequest::default()
        .with_to(recipient)
        .with_value(U256::from(1u64));
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    assert!(receipt.status(), "anvil tx must succeed");
    provider.anvil_mine(Some(2), None).await?;

    let record_tx_hash = format!("{:#x}", receipt.transaction_hash);
    let record_block_number = receipt.block_number.expect("must have block number") as i64;

    // Insert a tab and a RECORDED UserTransaction with record_tx_block_hash = zero.
    let now = Utc::now().naive_utc();
    let tab_id = U256::from(random::<u64>());
    let server_addr = format!("{:#x}", recipient);
    tabs::Entity::insert(tabs::ActiveModel {
        id: Set(format!("{tab_id:#x}")),
        user_address: Set(user_addr.clone()),
        server_address: Set(server_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        total_amount: Set("1".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(1)),
        version: Set(1),
        created_at: Set(now),
        updated_at: Set(now),
        ttl: Set(3600i64),
    })
    .exec(persist_ctx.db.as_ref())
    .await?;

    // Lock collateral as the normal payment discovery flow would have done.
    let balance =
        repo::get_user_balance_on(persist_ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS)
            .await?;
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>().unwrap(),
        U256::from(1u64),
    )
    .await?;

    let payment_tx_hash = format!("{:#x}", B256::from(random::<[u8; 32]>()));
    user_transaction::Entity::insert(user_transaction::ActiveModel {
        tx_id: Set(payment_tx_hash.clone()),
        user_address: Set(user_addr.clone()),
        recipient_address: Set(server_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        amount: Set("1".to_string()),
        tab_id: Set(Some(format!("{tab_id:#x}"))),
        block_number: Set(Some(record_block_number)),
        block_hash: Set(None),
        status: Set(UserTransactionStatus::Recorded),
        record_tx_hash: Set(Some(record_tx_hash.clone())),
        record_tx_block_number: Set(Some(record_block_number)),
        // Zero hash: the exact condition that triggered the bug.
        record_tx_block_hash: Set(Some(format!("{:#x}", B256::ZERO))),
        recorded_at: Set(Some(now)),
        confirmed_at: Set(Some(now)),
        verified: Set(false),
        finalized: Set(false),
        failed: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    })
    .exec(persist_ctx.db.as_ref())
    .await?;

    core_service.finalize_recorded_payments().await?;

    let tx_row = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(payment_tx_hash))
        .one(persist_ctx.db.as_ref())
        .await?
        .expect("transaction should exist");

    assert_ne!(
        tx_row.status,
        UserTransactionStatus::Reverted,
        "zero block hash must not cause a spurious revert"
    );
    assert_eq!(
        tx_row.status,
        UserTransactionStatus::Finalized,
        "transaction should be finalized"
    );

    clear_all_tables(persist_ctx).await?;
    Ok(())
}
