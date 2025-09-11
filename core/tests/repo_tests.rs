use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{
    collateral_event, guarantee, sea_orm_active_enums::CollateralEventType, user, user_transaction,
    withdrawal,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn deposit_zero_does_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(0u64)).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(0u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn deposit_large_value() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    let big = U256::from(1000000000000u64);
    repo::deposit(&ctx, user_addr.clone(), big).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, big.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn multiple_deposits_accumulate_and_log_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(15u64).to_string());

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr))
        .all(&*ctx.db)
        .await?;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|e| e.event_type == CollateralEventType::Deposit)
    );
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_transaction_id_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_id.clone(),
        U256::from(2u64),
        "c1".to_string(),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(2u64),
        "c1".to_string(),
    )
    .await?;

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_id))
        .all(&*ctx.db)
        .await?;
    assert_eq!(txs.len(), 1);
    Ok(())
}

#[test(tokio::test)]
async fn fail_transaction_twice_is_idempotent() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(3u64),
        "cert".to_string(),
    )
    .await?;

    // First fail → collateral should drop
    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;

    let u1 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u1.collateral, U256::from(7u64).to_string());

    // Second fail → no further effect (idempotent)
    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;

    let u2 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u2.collateral, U256::from(7u64).to_string());

    Ok(())
}

#[test(tokio::test)]
async fn transaction_verification_flow() -> anyhow::Result<()> {
    use rpc::common::TransactionVerificationResult;

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(2u64),
        "cert".into(),
    )
    .await?;

    let res1 = repo::verify_transaction(&ctx, tx_id.clone()).await?;
    assert!(matches!(res1, TransactionVerificationResult::Verified));

    let res2 = repo::verify_transaction(&ctx, tx_id.clone()).await?;
    assert!(matches!(
        res2,
        TransactionVerificationResult::AlreadyVerified
    ));

    let res3 = repo::verify_transaction(&ctx, "missing".into()).await?;
    assert!(matches!(res3, TransactionVerificationResult::NotFound));
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
async fn duplicate_certificate_insert_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let tab_id = Uuid::new_v4().to_string();
    let req_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let from_addr = Uuid::new_v4().to_string();
    let to_addr = Uuid::new_v4().to_string();

    for addr in [&user_addr, &from_addr, &to_addr] {
        let u_am = entities::user::ActiveModel {
            address: Set(addr.to_string()),
            collateral: Set(U256::from(0u64).to_string()),
            locked_collateral: Set(U256::from(0u64).to_string()),
            revenue: Set(U256::from(0u64).to_string()),
            version: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;
    }

    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    repo::store_certificate(
        &ctx,
        tab_id.clone(),
        req_id.clone(),
        from_addr.clone(),
        to_addr.clone(),
        U256::from(100u64),
        now,
        "cert".into(),
    )
    .await?;
    repo::store_certificate(
        &ctx,
        tab_id.clone(),
        req_id.clone(),
        from_addr,
        to_addr,
        U256::from(200u64),
        now,
        "cert2".into(),
    )
    .await?;

    let g = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .filter(guarantee::Column::ReqId.eq(req_id))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(g.value, U256::from(100u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn get_missing_certificate_returns_none() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let cert = repo::get_certificate(&ctx, "nope".into(), 123.to_string()).await?;
    assert!(cert.is_none());
    Ok(())
}

#[test(tokio::test)]
async fn remuneration_and_payment_recorded_as_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set(U256::from(0u64).to_string()),
        locked_collateral: Set(U256::from(0u64).to_string()),
        revenue: Set(U256::from(0u64).to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;

    let tab_id = Uuid::new_v4().to_string();
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(10u64)).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id))
        .all(&*ctx.db)
        .await?;

    assert_eq!(events.len(), 1);
    assert!(
        events
            .iter()
            .any(|e| e.amount == U256::from(10u64).to_string())
    );
    Ok(())
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
async fn duplicate_remuneration_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set(U256::from(0u64).to_string()),
        locked_collateral: Set(U256::from(0u64).to_string()),
        revenue: Set(U256::from(0u64).to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;

    let tab_id = Uuid::new_v4().to_string();
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(10u64)).await?;
    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(20u64)).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
        .all(&*ctx.db)
        .await?;

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].amount, U256::from(10u64).to_string());

    Ok(())
}
