use alloy::primitives::{Address, U256};
use anyhow::Result;
use chrono::{Duration, Utc};
use core_service::{
    config::DEFAULT_ASSET_ADDRESS,
    evm,
    persist::{CycleGuaranteeData, PersistCtx, repo},
    service::CoreService,
};
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;

use super::db::{clear_all_tables, setup_db_test_env};
use super::fixtures::{
    ensure_user, ensure_user_with_collateral, normalize_address, random_address,
    set_locked_collateral,
};

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

/// Give `who` `amount` of collateral and lock all of it — the state a participant is
/// in after locking the gross value of its outgoing guarantee at issuance.
pub async fn lock_collateral(ctx: &PersistCtx, who: &str, amount: u64) -> Result<()> {
    ensure_user_with_collateral(ctx, who, U256::from(amount)).await?;
    set_locked_collateral(ctx, who, DEFAULT_ASSET_ADDRESS, U256::from(amount)).await?;
    Ok(())
}

/// Run the netting pipeline for a frozen cycle, leaving it `NettingComputed` with its
/// guarantees netted and participant positions materialised.
pub async fn net_cycle(service: &CoreService, cycle_id: &str) -> Result<()> {
    service.compute_cycle_exposure_edges(cycle_id).await?;
    service
        .compute_cycle_participant_positions(cycle_id)
        .await?;
    service.build_clearing_batch(cycle_id).await?;
    assert!(service.mark_cycle_netting_computed(cycle_id).await?);
    Ok(())
}

/// Net a frozen cycle and open its payment window, confirmed by the mirrored
/// `CycleCommitted` event — the common starting point for settlement-lifecycle tests.
pub async fn open_payment_window(service: &CoreService, cycle_id: &str) -> Result<()> {
    net_cycle(service, cycle_id).await?;

    let ctx = service.persist_ctx();
    let now = Utc::now().naive_utc();
    assert!(
        repo::mark_cycle_payment_window_open_on(
            ctx.db.as_ref(),
            cycle_id,
            Some("0xcommit".to_string()),
            now,
            now,
            now,
        )
        .await?
    );
    service
        .process_cycle_committed(evm::cycle_id_hash(cycle_id), "0xcommit")
        .await?;
    Ok(())
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
