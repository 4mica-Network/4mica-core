//! Repository-layer state machines & idempotency: withdrawals, payment
//! transactions, cycle exposure/position upserts, wallet-role lookup, and
//! adversarial inputs. These exercise `repo::` directly against the DB — no
//! service logic, no chain, no HTTP.

use alloy::primitives::{Address, U256};
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::error::PersistDbError;
use core_service::persist::repo;
use entities::sea_orm_active_enums::{
    ParticipantCycleRole, ParticipantCycleStatus, UserTransactionStatus, WithdrawalStatus,
};
use entities::user_transaction;
use entities::withdrawal::{self, ActiveModel, Entity};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

#[path = "common/mod.rs"]
mod common;

use common::cycle_fixtures::{create_frozen_cycle, setup_cycle_service};
use common::db::{clear_all_tables, setup_db_test_env};
use common::fixtures::{
    ensure_user, ensure_user_with_collateral, normalize_address, random_address, read_collateral,
    set_locked_collateral,
};
use core_service::auth::constants::{SCOPE_GUARANTEE_ISSUE, SCOPE_PAYMENT_READ};

const ADMIN_WALLET_ROLE: &str = "admin";
const DEFAULT_WALLET_STATUS: &str = "active";

/// Toggle the first lowercase hex digit of an address to upper case, exercising
/// case-insensitive wallet-role lookup.
fn mixed_case_address(raw: &str) -> String {
    let mut toggled = false;
    let mut out = String::with_capacity(raw.len());
    for (idx, ch) in raw.chars().enumerate() {
        if idx < 2 {
            out.push(ch);
            continue;
        }
        if !toggled && ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() {
            out.push(ch.to_ascii_uppercase());
            toggled = true;
        } else {
            out.push(ch);
        }
    }
    out
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn wallet_role_lookup_accepts_mixed_case_wallet_address() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let stored_address = format!("{:#x}", signer.address());
    let presented_address = mixed_case_address(&stored_address);

    assert_eq!(stored_address, presented_address.to_ascii_lowercase());
    let scopes = vec![
        SCOPE_GUARANTEE_ISSUE.to_string(),
        SCOPE_PAYMENT_READ.to_string(),
    ];
    repo::upsert_wallet_role(
        &ctx,
        stored_address.parse()?,
        ADMIN_WALLET_ROLE,
        &scopes,
        DEFAULT_WALLET_STATUS,
    )
    .await?;
    let row = repo::get_wallet_role(&ctx, presented_address.parse()?)
        .await?
        .expect("wallet role should be retrievable by mixed-case address");
    assert_eq!(row.role, ADMIN_WALLET_ROLE);
    assert_eq!(
        row.scopes,
        serde_json::json!(["guarantee:issue", "payment:read"])
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn weird_identifiers_do_not_crash() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;

    // Address validation lives at the boundary now: the repo layer takes `Address`, so a
    // malformed identifier is refused here and can never reach a query.
    for weird in ["'; DROP TABLE users; --", "0xdeadbeef::weird", "", "0xABCD"] {
        assert!(
            weird.parse::<Address>().is_err(),
            "{weird:?} must not parse as an address"
        );
    }

    // Free-text columns still take arbitrary strings, so an odd transaction id must round-trip
    // safely rather than break the statement.
    let user = random_address();
    ensure_user_with_collateral(&ctx, &user, U256::from(5u64)).await?;
    repo::submit_payment_transaction(
        &ctx,
        user.parse()?,
        random_address().parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        "'; DROP TABLE users; --".into(),
        U256::from(1u64),
    )
    .await?;

    let stored = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq("'; DROP TABLE users; --"))
        .one(ctx.db.as_ref())
        .await?
        .expect("the odd transaction id is stored verbatim");
    assert_eq!(stored.user_address, normalize_address(&user)?);

    Ok(())
}

// ════════════════════════ withdrawals (repo state machine) ════════════════════════
#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn withdrawal_exceeding_free_is_recorded_not_rejected() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(10u64),
    )
    .await?;

    // The over-free request is still recorded as a pending withdrawal...
    let pending = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .one(ctx.db.as_ref())
        .await?
        .expect("over-free withdrawal request should still be recorded");
    assert_eq!(pending.requested_amount, U256::from(10u64).to_string());

    // ...and it does not move `total` (a request only records a pending withdrawal).
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn withdrawal_request_bumps_balance_version_to_serialise_with_locks() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(100u64)).await?;
    set_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS, U256::from(30u64)).await?;

    let before =
        repo::get_user_asset_balance(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?)
            .await?
            .expect("balance exists");

    // free = 100 - 30 = 70; a 50 request is within free.
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(50u64),
    )
    .await?;

    let after =
        repo::get_user_asset_balance(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?)
            .await?
            .expect("balance exists");

    assert!(
        after.version > before.version,
        "withdrawal request must bump the balance version to serialise with concurrent locks"
    );
    assert_eq!(after.total, U256::from(100u64).to_string());
    assert_eq!(after.locked, U256::from(30u64).to_string());

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn duplicate_withdrawal_request_updates_existing_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(10u64),
    )
    .await?;

    let first_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist");

    assert_eq!(
        first_withdrawal.requested_amount,
        U256::from(10u64).to_string()
    );

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        2,
        U256::from(5u64),
    )
    .await?;

    let pending = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(pending.len(), 1, "only one pending withdrawal should exist");

    let updated_withdrawal = &pending[0];
    assert_eq!(
        updated_withdrawal.requested_amount,
        U256::from(5u64).to_string(),
        "requested amount should be updated to new value"
    );
    assert_eq!(
        updated_withdrawal.executed_amount, "0",
        "executed amount should be reset to 0"
    );
    assert_eq!(
        updated_withdrawal.id, first_withdrawal.id,
        "same withdrawal record should be updated, not a new one created"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn request_withdrawal_after_cancelled_creates_new_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(10u64),
    )
    .await?;

    let first_id = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist")
        .id;

    repo::cancel_withdrawal(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        2,
        U256::from(5u64),
    )
    .await?;

    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(withdrawals.len(), 2, "should have two withdrawal records");

    let cancelled = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Cancelled)
        .expect("should have cancelled withdrawal");
    assert_eq!(cancelled.id, first_id);
    assert_eq!(cancelled.requested_amount, U256::from(10u64).to_string());

    let pending = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Pending)
        .expect("should have new pending withdrawal");
    assert_ne!(pending.id, first_id, "should be a new withdrawal record");
    assert_eq!(pending.requested_amount, U256::from(5u64).to_string());

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn request_withdrawal_after_executed_creates_new_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(8u64),
    )
    .await?;

    let first_id = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist")
        .id;

    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(8u64),
    )
    .await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        2,
        U256::from(5u64),
    )
    .await?;

    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(withdrawals.len(), 2, "should have two withdrawal records");

    let executed = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Executed)
        .expect("should have executed withdrawal");
    assert_eq!(executed.id, first_id);
    assert_eq!(executed.requested_amount, U256::from(8u64).to_string());
    assert_eq!(executed.executed_amount, U256::from(8u64).to_string());

    let pending = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Pending)
        .expect("should have new pending withdrawal");
    assert_ne!(pending.id, first_id, "should be a new withdrawal record");
    assert_eq!(pending.requested_amount, U256::from(5u64).to_string());
    assert_eq!(pending.executed_amount, "0");

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_withdrawal_twice_second_call_errors() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        1,
        U256::from(5u64),
    )
    .await?;

    // First finalize succeeds
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(5u64),
    )
    .await?;

    // Second finalize should now ERROR (no pending withdrawal left)
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(5u64),
    )
    .await;
    assert!(res.is_err(), "second finalize must error");

    // State remains Executed
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn withdrawal_request_cancel_then_finalize_errors() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    // Create and verify it's Pending
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        12345,
        U256::from(2u64),
    )
    .await?;
    let w1 = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w1.status, WithdrawalStatus::Pending);

    // Cancel it
    repo::cancel_withdrawal(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?).await?;
    let w2 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w2.status, WithdrawalStatus::Cancelled);

    // Finalize after cancel should now ERROR
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(2u64),
    )
    .await;
    assert!(res.is_err(), "finalize after cancel must error");

    // Status remains Cancelled and collateral unchanged (5)
    let w3 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w3.status, WithdrawalStatus::Cancelled);

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_withdrawal_reduces_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        123,
        U256::from(5u64),
    )
    .await?;
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(3u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(2u64)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_without_any_request_errors_and_preserves_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // No request exists; finalize must ERROR now
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(3u64),
    )
    .await;
    assert!(
        res.is_err(),
        "finalize without a pending request must error"
    );

    // Collateral unchanged
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn cancel_after_finalize_does_not_change_executed() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(6u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        111,
        U256::from(5u64),
    )
    .await?;
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(5u64),
    )
    .await?;

    // Calling cancel afterward should be a no-op on Executed withdrawals
    repo::cancel_withdrawal(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn double_cancel_is_idempotent() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(8u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        222,
        U256::from(3u64),
    )
    .await?;

    repo::cancel_withdrawal(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?).await?;
    repo::cancel_withdrawal(&ctx, user_addr.parse()?, DEFAULT_ASSET_ADDRESS.parse()?).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Cancelled);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_withdrawal_exceeding_requested_amount_takes_minimum() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        333,
        U256::from(2u64),
    )
    .await?;

    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(5u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(8u64),
        "Collateral should be reduced by minimum(executed, requested) = min(5, 2) = 2"
    );

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.executed_amount,
        U256::from(2u64).to_string(),
        "Executed amount should be min(5, 2) = 2"
    );
    assert_eq!(
        w.requested_amount,
        U256::from(2u64).to_string(),
        "Requested amount unchanged"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_withdrawal_records_executed_amount_and_updates_collateral() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    // user starts with 10
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // user requests 8
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        42,
        U256::from(8u64),
    )
    .await?;

    // but chain only executes 5
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(5u64),
    )
    .await?;

    // user collateral must now be 10 – 5 = 5
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    // withdrawal row must be Executed and executed_amount = 5, requested amount still 8
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.requested_amount,
        U256::from(8u64).to_string(),
        "requested amount unchanged"
    );
    assert_eq!(
        w.executed_amount,
        U256::from(5u64).to_string(),
        "executed amount persisted correctly"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn finalize_withdrawal_with_full_execution_still_sets_executed_amount() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // request 4, chain executes full 4
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        99,
        U256::from(4u64),
    )
    .await?;
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        U256::from(4u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(6u64)
    );

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.requested_amount,
        U256::from(4u64).to_string(),
        "requested amount unchanged"
    );
    assert_eq!(
        w.executed_amount,
        U256::from(4u64).to_string(),
        "executed amount persisted correctly"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn unique_pending_withdrawal_per_user_is_enforced() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let now = Utc::now().naive_utc();

    // insert the first Pending withdrawal – should succeed
    let w1 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        request_event_chain_id: Set(None),
        request_event_block_hash: Set(None),
        request_event_tx_hash: Set(None),
        request_event_log_index: Set(None),
        cancel_event_chain_id: Set(None),
        cancel_event_block_hash: Set(None),
        cancel_event_tx_hash: Set(None),
        cancel_event_log_index: Set(None),
        execute_event_chain_id: Set(None),
        execute_event_block_hash: Set(None),
        execute_event_tx_hash: Set(None),
        execute_event_log_index: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Entity::insert(w1).exec(ctx.db.as_ref()).await?;

    // insert a second Pending withdrawal for the same user – should violate the
    // partial unique index and return a database error.
    let w2 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        request_event_chain_id: Set(None),
        request_event_block_hash: Set(None),
        request_event_tx_hash: Set(None),
        request_event_log_index: Set(None),
        cancel_event_chain_id: Set(None),
        cancel_event_block_hash: Set(None),
        cancel_event_tx_hash: Set(None),
        cancel_event_log_index: Set(None),
        execute_event_chain_id: Set(None),
        execute_event_block_hash: Set(None),
        execute_event_tx_hash: Set(None),
        execute_event_log_index: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let res = Entity::insert(w2).exec(ctx.db.as_ref()).await;
    assert!(
        res.is_err(),
        "Second pending withdrawal for same user should violate unique index"
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn multiple_pending_withdrawals_per_user_different_assets_allowed() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let now = Utc::now().naive_utc();
    let asset1 = "0x0000000000000000000000000000000000000000".to_string();
    let asset2 = "0x0000000000000000000000000000000000000001".to_string();

    // Insert first pending withdrawal for asset1 – should succeed
    let w1 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(asset1.clone()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        request_event_chain_id: Set(None),
        request_event_block_hash: Set(None),
        request_event_tx_hash: Set(None),
        request_event_log_index: Set(None),
        cancel_event_chain_id: Set(None),
        cancel_event_block_hash: Set(None),
        cancel_event_tx_hash: Set(None),
        cancel_event_log_index: Set(None),
        execute_event_chain_id: Set(None),
        execute_event_block_hash: Set(None),
        execute_event_tx_hash: Set(None),
        execute_event_log_index: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Entity::insert(w1).exec(ctx.db.as_ref()).await?;

    // Insert second pending withdrawal for asset2 – should also succeed
    let w2 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(asset2.clone()),
        requested_amount: Set(U256::from(3u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        request_event_chain_id: Set(None),
        request_event_block_hash: Set(None),
        request_event_tx_hash: Set(None),
        request_event_log_index: Set(None),
        cancel_event_chain_id: Set(None),
        cancel_event_block_hash: Set(None),
        cancel_event_tx_hash: Set(None),
        cancel_event_log_index: Set(None),
        execute_event_chain_id: Set(None),
        execute_event_block_hash: Set(None),
        execute_event_tx_hash: Set(None),
        execute_event_log_index: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let res = Entity::insert(w2).exec(ctx.db.as_ref()).await;
    assert!(
        res.is_ok(),
        "User should be allowed to have pending withdrawals for different assets"
    );

    // Verify both withdrawals exist
    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(
        withdrawals.len(),
        2,
        "Should have two pending withdrawals for different assets"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn deposit_and_withdraw_multiple_assets_updates_collateral_correctly() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    // Define two different assets: ETH (default) and a stablecoin
    let eth_asset = DEFAULT_ASSET_ADDRESS.to_string();
    let stablecoin_asset = "0x0000000000000000000000000000000000000001".to_string();

    // Deposit ETH: 100 units
    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.parse()?,
        eth_asset.parse()?,
        U256::from(100u64),
    )
    .await?;

    // Deposit stablecoin: 200 units
    repo::deposit(
        &ctx,
        user_addr.parse()?,
        stablecoin_asset.parse()?,
        U256::from(200u64),
    )
    .await?;

    // Verify initial collateral
    assert_eq!(
        read_collateral(&ctx, &user_addr, &eth_asset).await?,
        U256::from(100u64),
        "Initial ETH collateral should be 100"
    );
    assert_eq!(
        read_collateral(&ctx, &user_addr, &stablecoin_asset).await?,
        U256::from(200u64),
        "Initial stablecoin collateral should be 200"
    );

    // Request withdrawal for ETH: 30 units
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        eth_asset.parse()?,
        1,
        U256::from(30u64),
    )
    .await?;

    // Request withdrawal for stablecoin: 50 units
    repo::request_withdrawal(
        &ctx,
        user_addr.parse()?,
        stablecoin_asset.parse()?,
        2,
        U256::from(50u64),
    )
    .await?;

    // Verify both withdrawal requests exist and are pending
    let eth_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(eth_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("ETH withdrawal request should exist");
    assert_eq!(eth_withdrawal.status, WithdrawalStatus::Pending);
    assert_eq!(
        eth_withdrawal.requested_amount,
        U256::from(30u64).to_string()
    );

    let stablecoin_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(stablecoin_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("Stablecoin withdrawal request should exist");
    assert_eq!(stablecoin_withdrawal.status, WithdrawalStatus::Pending);
    assert_eq!(
        stablecoin_withdrawal.requested_amount,
        U256::from(50u64).to_string()
    );

    // Finalize ETH withdrawal: execute 25 units (less than requested 30)
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        eth_asset.parse()?,
        U256::from(25u64),
    )
    .await?;

    // Finalize stablecoin withdrawal: execute full 50 units
    repo::finalize_withdrawal(
        &ctx,
        user_addr.parse()?,
        stablecoin_asset.parse()?,
        U256::from(50u64),
    )
    .await?;

    // Verify ETH collateral: 100 - 25 = 75
    assert_eq!(
        read_collateral(&ctx, &user_addr, &eth_asset).await?,
        U256::from(75u64),
        "ETH collateral should be reduced by executed amount (25)"
    );

    // Verify stablecoin collateral: 200 - 50 = 150
    assert_eq!(
        read_collateral(&ctx, &user_addr, &stablecoin_asset).await?,
        U256::from(150u64),
        "Stablecoin collateral should be reduced by executed amount (50)"
    );

    // Verify both withdrawals are marked as Executed
    let eth_withdrawal_final = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(eth_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("ETH withdrawal should exist");
    assert_eq!(eth_withdrawal_final.status, WithdrawalStatus::Executed);
    assert_eq!(
        eth_withdrawal_final.executed_amount,
        U256::from(25u64).to_string(),
        "ETH executed amount should be 25"
    );

    let stablecoin_withdrawal_final = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(stablecoin_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("Stablecoin withdrawal should exist");
    assert_eq!(
        stablecoin_withdrawal_final.status,
        WithdrawalStatus::Executed
    );
    assert_eq!(
        stablecoin_withdrawal_final.executed_amount,
        U256::from(50u64).to_string(),
        "Stablecoin executed amount should be 50"
    );

    Ok(())
}

// ════════════════════════ payment transactions (repo state machine) ════════════════════════

#[serial_test::file_serial(db)]
async fn duplicate_transaction_id_is_noop() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    let recipient = random_address();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.parse()?,
        recipient.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        tx_id.clone(),
        U256::from(2u64),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.parse()?,
        recipient.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        tx_id.clone(),
        U256::from(2u64),
    )
    .await?;

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_id))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(txs.len(), 1);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn fail_transaction_twice_is_idempotent() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.parse()?,
        recipient.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    repo::fail_transaction(&ctx, user_addr.parse()?, tx_id.clone()).await?;
    repo::fail_transaction(&ctx, user_addr.parse()?, tx_id.clone()).await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(7u64)
    );
    Ok(())
}

// (Dropped `duplicate_tx_id_is_stable_and_idempotent` — exact duplicate of
// `duplicate_transaction_id_is_noop` above.)

/// Failing a non-existent transaction should error with TransactionNotFound.
#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn fail_transaction_missing_tx_returns_err() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;

    let missing_tx_id = Uuid::new_v4().to_string();
    let res = repo::fail_transaction(&ctx, user_addr.parse()?, missing_tx_id.clone()).await;

    match res {
        Err(PersistDbError::TransactionNotFound(id)) => assert_eq!(id, missing_tx_id),
        Err(e) => panic!("expected TransactionNotFound, got {e:?}"),
        Ok(_) => panic!("expected error when tx is missing"),
    }

    Ok(())
}

/// NEW: failing a transaction with the wrong user must error and cause no side effects.
#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn fail_transaction_wrong_user_returns_err_and_no_changes() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;

    let owner_addr = random_address();
    let other_addr = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &owner_addr, U256::from(10u64)).await?;
    ensure_user_with_collateral(&ctx, &other_addr, U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        owner_addr.parse()?,
        recipient.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    // Attempt to fail using the WRONG user address
    let res = repo::fail_transaction(&ctx, other_addr.parse()?, tx_id.clone()).await;
    assert!(
        res.is_err(),
        "expected error when failing tx for the wrong user"
    );

    // Transaction should remain untouched
    let row = user_transaction::Entity::find_by_id(tx_id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert!(!row.failed, "tx should not be marked failed");
    assert!(!row.finalized, "tx should not be finalized");

    // Collateral should be unchanged for both users
    assert_eq!(
        read_collateral(&ctx, &owner_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );

    assert_eq!(
        read_collateral(&ctx, &other_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial(db)]
async fn mark_recorded_accepts_confirmed_status() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.parse()?,
        recipient.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    repo::mark_payment_transaction_recorded(
        &ctx,
        &tx_id,
        "0xrecordtx".to_string(),
        Some(42),
        Some("0xrecordblock".to_string()),
    )
    .await?;

    let row = user_transaction::Entity::find_by_id(tx_id)
        .one(ctx.db.as_ref())
        .await?
        .expect("transaction should exist");
    assert_eq!(row.status, UserTransactionStatus::Recorded);
    assert_eq!(row.record_tx_hash.as_deref(), Some("0xrecordtx"));
    assert_eq!(row.record_tx_block_number, Some(42));

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial]
async fn payment_recording_claim_is_atomic() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_pending_payment_transaction(
        &ctx,
        repo::PendingPaymentInput {
            user_address: user_addr.parse()?,
            recipient_address: recipient.parse()?,
            asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
            transaction_id: tx_id.clone(),
            amount: U256::from(3u64),
            block_number: 1,
            block_hash: None,
        },
    )
    .await?;

    assert!(repo::claim_payment_transaction_for_recording(&ctx, &tx_id).await?);
    assert!(!repo::claim_payment_transaction_for_recording(&ctx, &tx_id).await?);

    let row = user_transaction::Entity::find_by_id(tx_id)
        .one(ctx.db.as_ref())
        .await?
        .expect("transaction should exist");
    assert_eq!(row.status, UserTransactionStatus::Recording);

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial]
async fn finalized_transaction_cannot_be_marked_reverted() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_pending_payment_transaction(
        &ctx,
        repo::PendingPaymentInput {
            user_address: user_addr.parse()?,
            recipient_address: recipient.parse()?,
            asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
            transaction_id: tx_id.clone(),
            amount: U256::from(3u64),
            block_number: 1,
            block_hash: None,
        },
    )
    .await?;
    repo::mark_payment_transaction_finalized(&ctx, &tx_id).await?;

    assert!(
        !repo::mark_payment_transaction_reverted(&ctx, &tx_id).await?,
        "finalized rows must not be reverted by a stale worker"
    );

    let row = user_transaction::Entity::find_by_id(tx_id)
        .one(ctx.db.as_ref())
        .await?
        .expect("transaction should exist");
    assert!(row.finalized);
    assert!(row.verified);
    assert_eq!(row.status, UserTransactionStatus::Finalized);

    Ok(())
}

// ════════════════════════ cycle edge/position upserts ════════════════════════

#[serial_test::file_serial(db)]
async fn replacing_cycle_exposure_edges_is_idempotent() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "edge-replace-cycle").await?;
    let payer = random_address();
    let payee = random_address();

    let edge = repo::CycleExposureEdgeInput {
        cycle_id: cycle_id.clone(),
        payer: payer.parse()?,
        payee: payee.parse()?,
        asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
        gross_amount: U256::from(5u64),
        finalized_payable_amount: U256::from(5u64),
        disputed_amount: U256::ZERO,
        cancelled_amount: U256::ZERO,
        guarantee_count: 1,
    };

    repo::replace_cycle_exposure_edges_on(ctx.db.as_ref(), &cycle_id, vec![edge.clone()]).await?;
    repo::replace_cycle_exposure_edges_on(ctx.db.as_ref(), &cycle_id, vec![edge]).await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].gross_amount, U256::from(5u64));

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn replacing_participant_positions_removes_stale_rows() -> anyhow::Result<()> {
    let service = setup_cycle_service().await?;
    let ctx = service.persist_ctx();
    let cycle_id = create_frozen_cycle(ctx, "position-replace-cycle").await?;
    let first = random_address();
    let second = random_address();

    repo::replace_cycle_participant_positions_on(
        ctx.db.as_ref(),
        &cycle_id,
        vec![
            repo::CycleParticipantPositionInput {
                cycle_id: cycle_id.clone(),
                participant: first.parse()?,
                asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
                gross_outgoing: U256::from(2u64),
                gross_incoming: U256::ZERO,
                net_debit: U256::from(2u64),
                net_credit: U256::ZERO,
                role: ParticipantCycleRole::NetDebtor,
                status: ParticipantCycleStatus::Unpaid,
            },
            repo::CycleParticipantPositionInput {
                cycle_id: cycle_id.clone(),
                participant: second.parse()?,
                asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
                gross_outgoing: U256::ZERO,
                gross_incoming: U256::from(2u64),
                net_debit: U256::ZERO,
                net_credit: U256::from(2u64),
                role: ParticipantCycleRole::NetCreditor,
                status: ParticipantCycleStatus::Claimable,
            },
        ],
    )
    .await?;

    repo::replace_cycle_participant_positions_on(
        ctx.db.as_ref(),
        &cycle_id,
        vec![repo::CycleParticipantPositionInput {
            cycle_id: cycle_id.clone(),
            participant: second.parse()?,
            asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
            gross_outgoing: U256::ZERO,
            gross_incoming: U256::from(3u64),
            net_debit: U256::ZERO,
            net_credit: U256::from(3u64),
            role: ParticipantCycleRole::NetCreditor,
            status: ParticipantCycleStatus::Claimable,
        }],
    )
    .await?;

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;
    assert_eq!(positions.len(), 1);
    assert_eq!(positions[0].net_credit, U256::from(3u64));

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn get_user_balance_on_fails_for_nonexistent_user() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let addr = random_address();

    let err = repo::get_user_balance_on(
        ctx.db.as_ref(),
        addr.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
    )
    .await
    .expect_err("must fail for unknown user");

    assert!(
        matches!(err, PersistDbError::UserNotFound(_)),
        "expected UserNotFound, got: {err:?}"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn update_user_suspension_increments_version() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;
    let addr = random_address();
    ensure_user(&ctx, &addr).await?;

    let after_suspend = repo::update_user_suspension(&ctx, addr.parse()?, true).await?;
    assert!(after_suspend.is_suspended);
    assert_eq!(after_suspend.version, 1);

    let after_unsuspend = repo::update_user_suspension(&ctx, addr.parse()?, false).await?;
    assert!(!after_unsuspend.is_suspended);
    assert_eq!(after_unsuspend.version, 2);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn store_blockchain_event_duplicate_returns_false() -> anyhow::Result<()> {
    let (_cfg, ctx) = setup_db_test_env().await?;

    let first = repo::store_blockchain_event(
        &ctx,
        1,
        "Transfer(address,address,uint256)",
        100,
        "0xblock",
        "0xtx",
        0,
        "0x0000000000000000000000000000000000000001".parse()?,
        "{}",
    )
    .await?;

    let second = repo::store_blockchain_event(
        &ctx,
        1,
        "Transfer(address,address,uint256)",
        100,
        "0xblock",
        "0xtx",
        0,
        "0x0000000000000000000000000000000000000001".parse()?,
        "{}",
    )
    .await?;

    assert!(first, "first insert must return true");
    assert!(!second, "duplicate insert must return false");

    Ok(())
}
