use alloy::primitives::U256;
use chrono::Utc;
use core_service::error::PersistDbError;
use core_service::persist::{PersistCtx, repo};
use entities::collateral_event;
use entities::sea_orm_active_enums::CollateralEventType;
use entities::sea_orm_active_enums::WithdrawalStatus;
use entities::user_transaction;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;

mod common;
use common::fixtures::{
    ensure_user, ensure_user_with_collateral, fetch_user, init_test_env, random_address,
};

/// Fetch unfinalized transactions for a user
pub async fn get_unfinalized_transactions_for_user(
    ctx: &PersistCtx,
    user_address: &str,
    exclude_tx_id: Option<&str>,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let exclude =
        exclude_tx_id.ok_or_else(|| PersistDbError::TransactionNotFound("None".to_string()))?;

    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_address))
        .filter(user_transaction::Column::Finalized.eq(false))
        .filter(user_transaction::Column::TxId.ne(exclude))
        .all(ctx.db.as_ref())
        .await?;

    Ok(rows)
}

/// Ensure get_user_transactions only returns transactions for the given user.
#[test(tokio::test)]
async fn get_user_transactions_returns_only_users_txs() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    let other_user = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;
    ensure_user_with_collateral(&ctx, &other_user, U256::from(10u64)).await?;

    let tx_id_1 = format!("0x{:040x}", rand::random::<u128>());
    let tx_id_2 = format!("0x{:040x}", rand::random::<u128>());

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_id_1.clone(),
        U256::from(1),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        other_user.clone(),
        recipient.clone(),
        tx_id_2.clone(),
        U256::from(1),
    )
    .await?;

    let txs = repo::get_user_transactions(&ctx, &user_addr).await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].tx_id, tx_id_1);
    Ok(())
}

/// Ensure get_unfinalized_transactions_for_user excludes the passed tx_id.
#[test(tokio::test)]
async fn get_unfinalized_transactions_excludes_given_id() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let tx_id_1 = format!("0x{:040x}", rand::random::<u128>());
    let tx_id_2 = format!("0x{:040x}", rand::random::<u128>());

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_id_1.clone(),
        U256::from(2),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_id_2.clone(),
        U256::from(2),
    )
    .await?;

    // Baseline: both are present and unfinalized
    let all = repo::get_user_transactions(&ctx, &user_addr).await?;
    assert_eq!(all.len(), 2);

    // Excluding tx_id_1 should yield only tx_id_2
    let filtered = get_unfinalized_transactions_for_user(&ctx, &user_addr, Some(&tx_id_1)).await?;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].tx_id, tx_id_2);

    // Calling with None should now error
    let none_res = get_unfinalized_transactions_for_user(&ctx, &user_addr, None).await;
    assert!(
        none_res.is_err(),
        "expected error when exclude_tx_id is None"
    );

    Ok(())
}

/// Ensure get_pending_withdrawals_for_user finds only pending ones.
#[test(tokio::test)]
async fn get_pending_withdrawals_for_user_returns_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    let when = chrono::Utc::now().timestamp();
    // request withdrawal of 5
    repo::request_withdrawal(&ctx, user_addr.clone(), when, U256::from(5)).await?;

    let pending = repo::get_pending_withdrawals_for_user(&ctx, &user_addr).await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, WithdrawalStatus::Pending);

    // cancel it
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;

    let pending_after = repo::get_pending_withdrawals_for_user(&ctx, &user_addr).await?;
    assert_eq!(pending_after.len(), 0);
    Ok(())
}

/// bump_user_version should increase version once and return false on second attempt
#[test(tokio::test)]
async fn bump_user_version_increments_once() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await?;

    let u0 = fetch_user(&ctx, &user_addr).await?;
    let v0 = u0.version;

    // First bump succeeds
    let res1 = repo::bump_user_version(&ctx, &user_addr, v0).await;
    assert!(res1.is_ok(), "first bump should succeed");

    // Version incremented by 1
    let u1 = fetch_user(&ctx, &user_addr).await?;
    assert_eq!(u1.version, v0 + 1);

    // Second bump with stale version must error
    let res2 = repo::bump_user_version(&ctx, &user_addr, v0).await;
    assert!(res2.is_err(), "second bump with old version should error");

    // Version unchanged after failed attempt
    let u2 = fetch_user(&ctx, &user_addr).await?;
    assert_eq!(u2.version, v0 + 1);

    Ok(())
}

/// Ensure get_tab_by_id returns None for unknown id (simple smoke test)
#[test(tokio::test)]
async fn get_tab_by_id_none_for_unknown() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let res = repo::get_tab_by_id(&ctx, U256::from(12345u64)).await?;
    assert!(res.is_none());
    Ok(())
}

#[test(tokio::test)]
async fn inserting_second_remunerate_event_for_tab_fails() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let tab_id = U256::from(rand::random::<u128>());
    let now = Utc::now().naive_utc();

    let ev1 = collateral_event::ActiveModel {
        id: Set(format!("0x{:040x}", rand::random::<u128>())),
        user_address: Set(user_addr.clone()),
        amount: Set(U256::from(1u64).to_string()),
        event_type: Set(CollateralEventType::Remunerate),
        tab_id: Set(Some(tab_id.to_string())),
        req_id: Set(None),
        tx_id: Set(None),
        created_at: Set(now),
    };
    // First insert must succeed
    collateral_event::Entity::insert(ev1)
        .exec(ctx.db.as_ref())
        .await?;

    // Second insert with same tab_id + Remunerate must fail due to the unique index
    let ev2 = collateral_event::ActiveModel {
        id: Set(format!("0x{:040x}", rand::random::<u128>())),
        user_address: Set(user_addr),
        amount: Set(U256::from(2u64).to_string()),
        event_type: Set(CollateralEventType::Remunerate),
        tab_id: Set(Some(tab_id.to_string())),
        req_id: Set(None),
        tx_id: Set(None),
        created_at: Set(now),
    };

    let res = collateral_event::Entity::insert(ev2)
        .exec(ctx.db.as_ref())
        .await;
    assert!(
        res.is_err(),
        "second Remunerate event for same tab should violate unique index"
    );

    Ok(())
}
