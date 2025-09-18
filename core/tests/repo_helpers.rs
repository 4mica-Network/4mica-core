use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::collateral_event;
use entities::sea_orm_active_enums::CollateralEventType;
use entities::sea_orm_active_enums::WithdrawalStatus;
use entities::{user, user_transaction};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

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

// Ensure a user row exists (idempotent)
async fn ensure_user(ctx: &PersistCtx, addr: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    let am = entities::user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
        ..Default::default()
    };
    user::Entity::insert(am)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;
    Ok(())
}

/// Ensure get_user_transactions only returns transactions for the given user.
#[test(tokio::test)]
async fn get_user_transactions_returns_only_users_txs() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let other_user = format!("0x{:040x}", rand::random::<u128>());
    let recipient = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    ensure_user(&ctx, &other_user).await?;

    repo::deposit(&ctx, user_addr.clone(), U256::from(10)).await?;
    repo::deposit(&ctx, other_user.clone(), U256::from(10)).await?;

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
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let recipient = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(10)).await?;

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
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(20)).await?;

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
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(1)).await?;

    let u0 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    let v0 = u0.version;

    // First bump succeeds
    let res1 = repo::bump_user_version(&ctx, &user_addr, v0).await;
    assert!(res1.is_ok(), "first bump should succeed");

    // Version incremented by 1
    let u1 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u1.version, v0 + 1);

    // Second bump with stale version must error
    let res2 = repo::bump_user_version(&ctx, &user_addr, v0).await;
    assert!(res2.is_err(), "second bump with old version should error");

    // Version unchanged after failed attempt
    let u2 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u2.version, v0 + 1);

    Ok(())
}

/// Ensure get_tab_by_id returns None for unknown id (simple smoke test)
#[test(tokio::test)]
async fn get_tab_by_id_none_for_unknown() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let res = repo::get_tab_by_id(&ctx, "non-existent-id").await?;
    assert!(res.is_none());
    Ok(())
}

/// Ensure has_remunerate_event_for_tab returns false for unknown tab
#[test(tokio::test)]
async fn ensure_remunerate_event_for_tab_errors_for_unknown_and_ok_when_present()
-> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let res = repo::ensure_remunerate_event_for_tab(&ctx, "non-existent-id").await;
    assert!(
        res.is_err(),
        "ensure_* must error when no remunerate event exists"
    );

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;

    let tab_id = "tab-foo";
    let ev = collateral_event::ActiveModel {
        id: Set(format!("0x{:040x}", rand::random::<u128>())),
        user_address: Set(user_addr),
        amount: Set(U256::from(1u64).to_string()),
        event_type: Set(CollateralEventType::Remunerate),
        tab_id: Set(Some(tab_id.to_string())),
        req_id: Set(None),
        tx_id: Set(None),
        created_at: Set(Utc::now().naive_utc()),
    };
    collateral_event::Entity::insert(ev)
        .exec(ctx.db.as_ref())
        .await?;

    repo::ensure_remunerate_event_for_tab(&ctx, tab_id).await?; // now Ok(())

    Ok(())
}
