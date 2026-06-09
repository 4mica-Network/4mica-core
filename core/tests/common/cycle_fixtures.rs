use alloy::primitives::{Address, U256};
use anyhow::Result;
use chrono::{Duration, Utc};
use core_service::{
    config::DEFAULT_ASSET_ADDRESS,
    persist::{CycleGuaranteeData, PersistCtx, repo},
    service::CoreService,
};
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;

use super::db::{clear_all_tables, setup_db_test_env};
use super::fixtures::{ensure_user, normalize_address, random_address};

pub async fn setup_cycle_service() -> Result<CoreService> {
    let (mut config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    config.ethereum_config.clearing_house_address = Address::ZERO.to_string();
    CoreService::new(config).await
}

pub async fn create_frozen_cycle(ctx: &PersistCtx, id: &str) -> Result<String> {
    let now = Utc::now().naive_utc();
    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            payment_submission_deadline: now + Duration::hours(1),
            payment_finality_deadline: now + Duration::hours(2),
        },
    )
    .await?;
    assert!(repo::freeze_cycle_on(ctx.db.as_ref(), id, now).await?);
    Ok(id.to_string())
}

pub async fn store_payable_guarantee(
    ctx: &PersistCtx,
    cycle_id: &str,
    from: &str,
    to: &str,
    amount: u64,
    req_id: u64,
) -> Result<String> {
    let from = normalize_address(from)?;
    let to = normalize_address(to)?;
    ensure_user(ctx, &from).await?;
    ensure_user(ctx, &to).await?;

    let guarantee_id = format!("{cycle_id}:{from}:{to}:{req_id}");
    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        CycleGuaranteeData {
            guarantee_id: guarantee_id.clone(),
            cycle_id: cycle_id.to_string(),
            req_id: U256::from(req_id),
            version: 2,
            from,
            to,
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(amount),
            start_ts: Utc::now().naive_utc(),
            cert: "{}".to_string(),
            request: None,
            settlement_status: GuaranteeSettlementStatus::FinalizedPayable,
        },
    )
    .await?;
    Ok(guarantee_id)
}

pub async fn store_pending_guarantee(
    ctx: &PersistCtx,
    cycle_id: &str,
    from: &str,
    to: &str,
    amount: u64,
    req_id: u64,
) -> Result<String> {
    let from = normalize_address(from)?;
    let to = normalize_address(to)?;
    ensure_user(ctx, &from).await?;
    ensure_user(ctx, &to).await?;

    let guarantee_id = format!("{cycle_id}:{from}:{to}:{req_id}:pending");
    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        CycleGuaranteeData {
            guarantee_id: guarantee_id.clone(),
            cycle_id: cycle_id.to_string(),
            req_id: U256::from(req_id),
            version: 2,
            from,
            to,
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(amount),
            start_ts: Utc::now().naive_utc(),
            cert: "{}".to_string(),
            request: None,
            settlement_status: GuaranteeSettlementStatus::PendingValidation,
        },
    )
    .await?;
    Ok(guarantee_id)
}

pub async fn build_three_party_cycle(service: &CoreService, cycle_id: &str) -> Result<Vec<String>> {
    let ctx = service.persist_ctx();
    create_frozen_cycle(ctx, cycle_id).await?;
    let alice = random_address();
    let bob = random_address();
    let carol = random_address();

    store_payable_guarantee(ctx, cycle_id, &alice, &bob, 10, 0).await?;
    store_payable_guarantee(ctx, cycle_id, &bob, &carol, 4, 1).await?;
    store_payable_guarantee(ctx, cycle_id, &carol, &alice, 1, 2).await?;

    Ok(vec![
        normalize_address(&alice)?,
        normalize_address(&bob)?,
        normalize_address(&carol)?,
    ])
}
