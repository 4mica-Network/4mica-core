use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{user, withdrawal};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn withdrawal_more_than_collateral_fails() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;
    let res = repo::request_withdrawal(&ctx, user_addr.clone(), 1, U256::from(10u64)).await;

    assert!(res.is_err());

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(5u64).to_string());

    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_twice_is_idempotent() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;
    repo::request_withdrawal(&ctx, user_addr.clone(), 1, U256::from(5u64)).await?;

    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();

    assert_eq!(w.status, WithdrawalStatus::Executed);

    Ok(())
}

#[test(tokio::test)]
async fn withdrawal_request_cancel_finalize_flow() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    repo::request_withdrawal(&ctx, user_addr.clone(), 12345, U256::from(2u64)).await?;
    let w1 = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(w1.status, WithdrawalStatus::Pending);

    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;
    let w2 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(w2.status, WithdrawalStatus::Cancelled);

    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(2u64)).await?;
    let w3 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(w3.status, WithdrawalStatus::Executed);
    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_reduces_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    repo::request_withdrawal(&ctx, user_addr.clone(), 123, U256::from(5u64)).await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(3u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(2u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn finalize_without_any_request_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;
    // No request was created; finalize should be a no-op
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(3u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(10u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn cancel_after_finalize_does_not_change_executed() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(6u64)).await?;
    repo::request_withdrawal(&ctx, user_addr.clone(), 111, U256::from(5u64)).await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // Calling cancel afterward should be a no-op on Executed withdrawals
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    Ok(())
}

#[test(tokio::test)]
async fn double_cancel_is_idempotent() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(8u64)).await?;
    repo::request_withdrawal(&ctx, user_addr.clone(), 222, U256::from(3u64)).await?;

    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Cancelled);
    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_underflow_errors() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(3u64)).await?;
    repo::request_withdrawal(&ctx, user_addr.clone(), 333, U256::from(2u64)).await?;

    let res = repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await;
    assert!(res.is_err());

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(3u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_records_executed_amount_and_updates_collateral() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    // user starts with 10
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    // user requests 8
    repo::request_withdrawal(&ctx, user_addr.clone(), 42, U256::from(8u64)).await?;

    // but chain only executes 5
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // user collateral must now be 10 – 5 = 5
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(5u64).to_string());

    // withdrawal row must be Executed and executed_amount = 5, requested amount still 8
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(&*ctx.db)
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
async fn finalize_withdrawal_with_full_execution_still_sets_executed_amount() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    // request 4, chain executes full 4
    repo::request_withdrawal(&ctx, user_addr.clone(), 99, U256::from(4u64)).await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(4u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(6u64).to_string());

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(&*ctx.db)
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
async fn request_withdrawal_rejects_when_more_than_two_minutes_in_future() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    // give the user some collateral
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // pick a timestamp > 2 minutes in the future (2m + 1s)
    let too_far = Utc::now().timestamp() + 121;
    let res = repo::request_withdrawal(&ctx, user_addr.clone(), too_far, U256::from(1u64)).await;

    assert!(
        res.is_err(),
        "should reject timestamps more than 2 minutes in the future"
    );

    // ensure no withdrawal was inserted
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(&*ctx.db)
        .await?;
    assert!(w.is_none(), "no withdrawal row should be inserted on error");

    Ok(())
}

#[test(tokio::test)]
async fn request_withdrawal_allows_when_up_to_two_minutes_in_future() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // exactly 2 minutes ahead should be allowed
    let boundary = Utc::now().timestamp() + 120;
    let res = repo::request_withdrawal(&ctx, user_addr.clone(), boundary, U256::from(1u64)).await;

    assert!(res.is_ok(), "exactly +2 minutes should be allowed");

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();

    assert_eq!(w.status, WithdrawalStatus::Pending);

    Ok(())
}
