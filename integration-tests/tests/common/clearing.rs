//! Direct DB manipulation to force a committed clearing cycle for pay-debit /
//! claim-credit e2e tests. There is no HTTP endpoint to commit a cycle — the
//! running core-service commits it on a time-based scheduler — so a test injects
//! a frozen, backdated cycle (all deadlines in the past) and lets the running
//! scheduler net and commit it on-chain on its next tick.

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::rows::StoreCycleGuaranteeInput;
use core_service::persist::{PersistCtx, repo};
use entities::sea_orm_active_enums::{GuaranteeSettlementStatus, SettlementCycleStatus};
use std::str::FromStr;
use std::time::{Duration as StdDuration, Instant};

fn normalize(addr: Address) -> String {
    format!("{addr:#x}")
}

/// Inject a frozen, backdated two-party clearing cycle (`debtor` owes `creditor`
/// `amount`) straight into core's DB, with the debtor's collateral locked to
/// cover the net debit — the state a participant is in after locking a
/// guarantee's gross value at issuance. The running core-service scheduler nets
/// this cycle and commits it on-chain on its next tick, because every deadline is
/// already in the past.
pub async fn inject_frozen_two_party_cycle(
    cycle_id: &str,
    debtor: Address,
    creditor: Address,
    amount: U256,
) -> Result<()> {
    super::load_core_env();
    let ctx = PersistCtx::new()
        .await
        .context("connect to core database")?;
    let now = Utc::now().naive_utc();

    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: cycle_id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.parse()?,
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            // Leave the payment/finality windows well in the future so the debtor
            // has time to pay and the creditor to claim before the scheduler moves
            // the cycle on to settlement.
            payment_submission_deadline: now + Duration::hours(6),
            payment_finality_deadline: now + Duration::hours(12),
        },
    )
    .await
    .context("create settlement cycle")?;
    if !repo::freeze_cycle_on(ctx.db.as_ref(), cycle_id, now).await? {
        bail!("failed to freeze injected cycle {cycle_id}");
    }

    let debtor = normalize(debtor);
    let creditor = normalize(creditor);

    // Both participants must exist before the guarantee references them.
    repo::ensure_user_exists_on(ctx.db.as_ref(), debtor.parse()?).await?;
    repo::ensure_user_exists_on(ctx.db.as_ref(), creditor.parse()?).await?;

    // Store the payable guarantee already FinalizedPayable so netting counts it
    // immediately (no validation lifecycle needed).
    let guarantee_id = format!("{cycle_id}:{debtor}:{creditor}:0");
    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        StoreCycleGuaranteeInput {
            guarantee_id,
            cycle_id: cycle_id.to_string(),
            req_id: U256::from(0u64),
            version: 2,
            from: debtor.parse()?,
            to: creditor.parse()?,
            asset: DEFAULT_ASSET_ADDRESS.parse()?,
            value: amount,
            start_ts: now,
            cert: "{}".to_string(),
            request: None,
            settlement_status: GuaranteeSettlementStatus::FinalizedPayable,
        },
    )
    .await
    .context("store payable guarantee")?;

    // Give the debtor total collateral covering the net debit, then lock all of
    // it — mirroring the post-issuance locked state the netting pipeline expects.
    repo::deposit(
        &ctx,
        debtor.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        amount,
    )
    .await
    .context("credit debtor collateral")?;
    let balance = repo::get_user_balance_on(
        ctx.db.as_ref(),
        debtor.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
    )
    .await?;
    let total = U256::from_str(&balance.total)
        .map_err(|e| anyhow::anyhow!("invalid debtor collateral {}: {e}", balance.total))?;
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        debtor.parse()?,
        DEFAULT_ASSET_ADDRESS.parse()?,
        balance.version,
        total,
        amount,
    )
    .await
    .context("lock debtor collateral")?;

    Ok(())
}

/// Poll core's DB until the running scheduler has committed the injected cycle
/// on-chain, i.e. it reaches `PaymentWindowOpen`. At that point `commit_cycle_to_chain`
/// has already awaited the commit transaction's receipt, so the ClearingHouse
/// holds the cycle open and the SDK's `pay_net_debit` / `claim_net_credit` calls
/// are valid on-chain.
///
/// We deliberately do NOT wait for `status_confirmed`: that flag flips only once
/// the event scanner mirrors `CycleCommitted`, which is core's own async
/// bookkeeping and irrelevant to whether the on-chain settlement calls succeed.
/// Fails fast if the cycle instead lands in a terminal non-payable state.
///
/// Each poll mines a block on `eth_rpc_url` so the scheduler's commit transaction
/// is mined even if anvil is not in instant-mining mode.
pub async fn wait_for_payment_window(cycle_id: &str, eth_rpc_url: &str) -> Result<()> {
    super::load_core_env();
    let ctx = PersistCtx::new().await?;
    let timeout = StdDuration::from_secs(120);
    let start = Instant::now();

    loop {
        mine_blocks(eth_rpc_url, 1).await?;

        if let Some(cycle) = repo::get_cycle_by_id_on(ctx.db.as_ref(), cycle_id).await? {
            if cycle.status == SettlementCycleStatus::PaymentWindowOpen {
                return Ok(());
            }
            if matches!(
                cycle.status,
                SettlementCycleStatus::Shortfall
                    | SettlementCycleStatus::Cancelled
                    | SettlementCycleStatus::Finalized
            ) {
                bail!(
                    "cycle {cycle_id} reached terminal state {:?} before opening its payment window",
                    cycle.status
                );
            }
        }

        if start.elapsed() > timeout {
            bail!("timed out waiting for cycle {cycle_id} to open its payment window");
        }
        tokio::time::sleep(StdDuration::from_secs(1)).await;
    }
}

/// Mine `blocks` blocks on an anvil RPC; a no-op on RPCs without `anvil_mine`.
async fn mine_blocks(eth_rpc_url: &str, blocks: u64) -> Result<()> {
    if blocks == 0 {
        return Ok(());
    }
    let response = reqwest::Client::new()
        .post(eth_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "anvil_mine",
            "params": [blocks]
        }))
        .send()
        .await?;
    let payload: serde_json::Value = response.json().await?;
    if let Some(err) = payload.get("error") {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or_default();
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if code == -32601 || message.contains("Method not found") {
            return Ok(());
        }
        bail!("anvil_mine failed: code={code}, message={message}");
    }
    Ok(())
}
