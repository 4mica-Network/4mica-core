#![cfg(any())]

//! End-to-end clearing tests: a real cycle is netted, committed to the on-chain
//! ClearingHouse, paid/claimed by participants, and finalized — with the event
//! scanner mirroring every step back into the database.
//!
//! Contract-internal logic (proof checks, accounting, reverts) is covered by the
//! Foundry suite; these tests prove the Rust<->contract round trip: that a
//! Rust-built Merkle root and proofs verify on-chain and that the resulting
//! events drive the database state machine.

use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::DynProvider;
use alloy::providers::ext::AnvilApi;
use anyhow::Context;
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleStatus, SettlementCycleStatus,
};
use entities::{guarantee, settlement_cycle};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use test_log::test;

mod common;
use common::chain::{OPERATOR_KEY, setup_e2e_environment};
use common::contract::{ClearingHouse, Core4Mica};
use common::cycle_fixtures::{create_frozen_cycle, store_payable_guarantee};
use common::fixtures::{
    ensure_user_with_collateral, read_locked_collateral, set_locked_collateral,
};
use core_service::persist::{PersistCtx, repo};

// Operator key = same key CoreService uses internally. A fresh HTTP provider (no
// nonce cache) is built from it for test-side calls so it always queries the
// chain for the current nonce, regardless of what CoreService's provider has done.
const DEBTOR_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CREDITOR_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
// Two extra anvil accounts for the interleaved-settlement test (a second
// debtor/creditor pair that funds the pool independently).
const SECOND_DEBTOR_KEY: &str =
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const SECOND_CREDITOR_KEY: &str =
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";

const NET_AMOUNT: u64 = 1_000_000_000_000;
const POLL_ATTEMPTS: u32 = 60;

fn lower(address: &Address) -> String {
    format!("{address:#x}")
}

async fn mine(provider: &DynProvider, blocks: u64) -> anyhow::Result<()> {
    provider.anvil_mine(Some(blocks), None).await?;
    Ok(())
}

/// Net a single payable guarantee (debtor -> creditor) into a frozen cycle and
/// commit it on-chain. Returns the stored guarantee id.
async fn commit_two_party_cycle(
    svc: &core_service::service::CoreService,
    cycle_id: &str,
    debtor: &Address,
    creditor: &Address,
) -> anyhow::Result<String> {
    let ctx = svc.persist_ctx();
    create_frozen_cycle(ctx, cycle_id).await?;
    let guarantee_id = store_payable_guarantee(
        ctx,
        cycle_id,
        &lower(debtor),
        &lower(creditor),
        NET_AMOUNT,
        0,
    )
    .await?;

    // Simulate the debtor having their net debit locked as collateral
    ensure_user_with_collateral(ctx, &lower(debtor), U256::from(NET_AMOUNT)).await?;
    set_locked_collateral(
        ctx,
        &lower(debtor),
        core_service::config::DEFAULT_ASSET_ADDRESS,
        U256::from(NET_AMOUNT),
    )
    .await?;

    svc.compute_cycle_exposure_edges(cycle_id).await?;
    svc.compute_cycle_participant_positions(cycle_id).await?;
    svc.build_clearing_batch(cycle_id).await?;
    assert!(svc.mark_cycle_netting_computed(cycle_id).await?);
    svc.commit_cycle_to_chain(cycle_id)
        .await
        .context("commit_cycle_to_chain")?;

    Ok(guarantee_id)
}

/// Net two independent debtor->creditor pairs (`d1->c` and `d2->e`) into one
/// frozen cycle and commit it on-chain. Both debtors lock their net debit.
/// Returns the `d1->c` guarantee id (the one whose debtor pays last).
async fn commit_interleaved_cycle(
    svc: &core_service::service::CoreService,
    cycle_id: &str,
    d1: &Address,
    c: &Address,
    d2: &Address,
    e: &Address,
) -> anyhow::Result<String> {
    let ctx = svc.persist_ctx();
    create_frozen_cycle(ctx, cycle_id).await?;
    let g_d1c =
        store_payable_guarantee(ctx, cycle_id, &lower(d1), &lower(c), NET_AMOUNT, 0).await?;
    store_payable_guarantee(ctx, cycle_id, &lower(d2), &lower(e), NET_AMOUNT, 1).await?;

    for debtor in [d1, d2] {
        ensure_user_with_collateral(ctx, &lower(debtor), U256::from(NET_AMOUNT)).await?;
        set_locked_collateral(
            ctx,
            &lower(debtor),
            core_service::config::DEFAULT_ASSET_ADDRESS,
            U256::from(NET_AMOUNT),
        )
        .await?;
    }

    svc.compute_cycle_exposure_edges(cycle_id).await?;
    svc.compute_cycle_participant_positions(cycle_id).await?;
    svc.build_clearing_batch(cycle_id).await?;
    assert!(svc.mark_cycle_netting_computed(cycle_id).await?);
    svc.commit_cycle_to_chain(cycle_id)
        .await
        .context("commit_cycle_to_chain")?;

    Ok(g_d1c)
}

async fn poll_position_status(
    ctx: &PersistCtx,
    cycle_id: &str,
    participant: &str,
    expected: ParticipantCycleStatus,
) -> anyhow::Result<()> {
    for _ in 0..POLL_ATTEMPTS {
        let positions =
            repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
        if positions
            .iter()
            .any(|p| p.participant == participant && p.status == expected)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("participant {participant} never reached {expected:?}");
}

async fn poll_cycle_status(
    ctx: &PersistCtx,
    cycle_id: &str,
    expected: SettlementCycleStatus,
) -> anyhow::Result<()> {
    for _ in 0..POLL_ATTEMPTS {
        if let Some(cycle) = repo::get_cycle_by_id(ctx, cycle_id).await?
            && cycle.status == expected
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("cycle {cycle_id} never reached {expected:?}");
}

async fn poll_guarantee_status(
    ctx: &PersistCtx,
    guarantee_id: &str,
    expected: GuaranteeSettlementStatus,
) -> anyhow::Result<()> {
    for _ in 0..POLL_ATTEMPTS {
        if let Some(g) = guarantee::Entity::find_by_id(guarantee_id.to_string())
            .one(ctx.db.as_ref())
            .await?
            && g.settlement_status == expected
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("guarantee {guarantee_id} never reached {expected:?}");
}

/// Happy path: debtor pays, creditor claims, and the cycle finalizes — each
/// on-chain event mirrored into participant, guarantee, and cycle state.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn cycle_commits_pays_claims_and_finalizes() -> anyhow::Result<()> {
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();

    let (_, op_provider) = common::chain::wallet_provider(&http, OPERATOR_KEY)?;
    let (debtor, debtor_provider) = common::chain::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, creditor_provider) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-roundtrip";
    let guarantee_id = commit_two_party_cycle(&svc, cycle_id, &debtor, &creditor).await?;
    mine(&provider, 2).await?;

    // Debtor pays its net debit with the proof the service generates.
    let debtor_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&debtor))
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), debtor_provider)
        .payNetDebit(
            debtor_proof.cycle_id,
            debtor_proof.amount,
            debtor_proof.proof,
        )
        .value(debtor_proof.amount)
        .send()
        .await
        .context("payNetDebit send")?
        .watch()
        .await
        .context("payNetDebit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(ctx, cycle_id, &lower(&debtor), ParticipantCycleStatus::Paid).await?;
    poll_guarantee_status(ctx, &guarantee_id, GuaranteeSettlementStatus::Settled).await?;

    // Creditor claims its net credit.
    let creditor_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&creditor))
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), creditor_provider)
        .claimNetCredit(
            creditor_proof.cycle_id,
            creditor_proof.amount,
            creditor_proof.proof,
        )
        .send()
        .await
        .context("claimNetCredit send")?
        .watch()
        .await
        .context("claimNetCredit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&creditor),
        ParticipantCycleStatus::Claimed,
    )
    .await?;

    // Advance past the finality deadline, then finalize on-chain.
    provider
        .anvil_set_block_timestamp_interval(5 * 60 * 60)
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), op_provider)
        .finalizeCycle(debtor_proof.cycle_id)
        .send()
        .await
        .context("finalizeCycle send")?
        .watch()
        .await
        .context("finalizeCycle confirm")?;
    mine(&provider, 2).await?;
    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Finalized).await?;

    Ok(())
}

/// Interleaved settlement under the full-funding claim gate: a creditor cannot
/// claim until the cycle's entire debit side is funded. A partial payment leaves
/// the claim blocked; the remaining debtor's own payment settles its guarantee
/// and releases its collateral, after which the creditor can finally claim.
/// Regression guard that a debtor's collateral is released by its own payment,
/// not by a creditor claim.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn creditor_claim_is_blocked_until_cycle_fully_funded() -> anyhow::Result<()> {
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();
    let asset = core_service::config::DEFAULT_ASSET_ADDRESS;

    // d1 -> c is the guarantee under test; d2 -> e is the other half of the cycle.
    let (d1, d1_provider) = common::chain::wallet_provider(&http, DEBTOR_KEY)?;
    let (c, c_provider) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;
    let (d2, d2_provider) = common::chain::wallet_provider(&http, SECOND_DEBTOR_KEY)?;
    let (e, _e_provider) = common::chain::wallet_provider(&http, SECOND_CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-interleave";
    let g_d1c = commit_interleaved_cycle(&svc, cycle_id, &d1, &c, &d2, &e).await?;
    mine(&provider, 2).await?;

    // Only d2 pays: the cycle is half-funded (d2 owes e, not c).
    let d2_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&d2))
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), d2_provider)
        .payNetDebit(d2_proof.cycle_id, d2_proof.amount, d2_proof.proof)
        .value(d2_proof.amount)
        .send()
        .await
        .context("d2 payNetDebit send")?
        .watch()
        .await
        .context("d2 payNetDebit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(ctx, cycle_id, &lower(&d2), ParticipantCycleStatus::Paid).await?;

    // c cannot claim yet: the cycle is not fully funded (d1 still owes). Send the
    // rejected attempt from a throwaway provider: a failed send still advances the
    // wallet's cached nonce, which would leave c's later real claim stuck behind a
    // nonce gap.
    let c_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&c))
        .await?;
    let (_, c_throwaway) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;
    let premature = ClearingHouse::new(*env.clearing_house.address(), c_throwaway)
        .claimNetCredit(c_proof.cycle_id, c_proof.amount, c_proof.proof.clone())
        .send()
        .await;
    assert!(
        premature.is_err(),
        "creditor claim must be rejected while the cycle is underfunded"
    );

    // d1->c stays Netted and d1 stays locked until d1 itself pays.
    let g = guarantee::Entity::find_by_id(g_d1c.clone())
        .one(ctx.db.as_ref())
        .await?
        .expect("d1->c guarantee exists");
    assert_eq!(g.settlement_status, GuaranteeSettlementStatus::Netted);
    assert_eq!(
        read_locked_collateral(ctx, &lower(&d1), asset).await?,
        U256::from(NET_AMOUNT),
        "d1 collateral must stay locked until d1 itself pays"
    );

    // d1 pays: settles d1->c, releases d1's collateral, and completes funding.
    let d1_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&d1))
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), d1_provider)
        .payNetDebit(d1_proof.cycle_id, d1_proof.amount, d1_proof.proof)
        .value(d1_proof.amount)
        .send()
        .await
        .context("d1 payNetDebit send")?
        .watch()
        .await
        .context("d1 payNetDebit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(ctx, cycle_id, &lower(&d1), ParticipantCycleStatus::Paid).await?;
    poll_guarantee_status(ctx, &g_d1c, GuaranteeSettlementStatus::Settled).await?;
    assert_eq!(
        read_locked_collateral(ctx, &lower(&d1), asset).await?,
        U256::ZERO,
        "d1 collateral released by its own payment"
    );

    // Fully funded now, so the creditor's claim succeeds.
    ClearingHouse::new(*env.clearing_house.address(), c_provider)
        .claimNetCredit(c_proof.cycle_id, c_proof.amount, c_proof.proof)
        .send()
        .await
        .context("c claimNetCredit send")?
        .watch()
        .await
        .context("c claimNetCredit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(ctx, cycle_id, &lower(&c), ParticipantCycleStatus::Claimed).await?;

    Ok(())
}

async fn commit_two_party_cycle_past_finality(
    svc: &core_service::service::CoreService,
    provider: &DynProvider,
    cycle_id: &str,
    debtor: &Address,
    creditor: &Address,
) -> anyhow::Result<String> {
    let guarantee_id = commit_two_party_cycle(svc, cycle_id, debtor, creditor).await?;

    // Move on-chain time past the finality deadline (so settleDefaults is allowed) and
    // backdate the off-chain finality deadline (so the settlement job sees the cycle as due).
    provider
        .anvil_set_block_timestamp_interval(5 * 60 * 60)
        .await?;
    backdate_cycle_finality(svc.persist_ctx(), cycle_id).await?;

    Ok(guarantee_id)
}

async fn commit_two_party_cycle_finality_soon(
    svc: &core_service::service::CoreService,
    cycle_id: &str,
    debtor: &Address,
    creditor: &Address,
    secs: i64,
) -> anyhow::Result<String> {
    use chrono::{Duration as ChronoDuration, Utc};
    use core_service::config::DEFAULT_ASSET_ADDRESS;

    let ctx = svc.persist_ctx();
    let now = Utc::now().naive_utc();
    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: cycle_id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            period_start: now - ChronoDuration::hours(3),
            period_end: now - ChronoDuration::hours(2),
            resolution_cutoff: now - ChronoDuration::hours(1),
            clearing_commit_deadline: now - ChronoDuration::minutes(30),
            payment_submission_deadline: now + ChronoDuration::seconds(secs),
            payment_finality_deadline: now + ChronoDuration::seconds(secs),
        },
    )
    .await?;
    assert!(repo::freeze_cycle_on(ctx.db.as_ref(), cycle_id, now).await?);

    let guarantee_id = store_payable_guarantee(
        ctx,
        cycle_id,
        &lower(debtor),
        &lower(creditor),
        NET_AMOUNT,
        0,
    )
    .await?;
    ensure_user_with_collateral(ctx, &lower(debtor), U256::from(NET_AMOUNT)).await?;
    set_locked_collateral(
        ctx,
        &lower(debtor),
        DEFAULT_ASSET_ADDRESS,
        U256::from(NET_AMOUNT),
    )
    .await?;

    svc.compute_cycle_exposure_edges(cycle_id).await?;
    svc.compute_cycle_participant_positions(cycle_id).await?;
    svc.build_clearing_batch(cycle_id).await?;
    assert!(svc.mark_cycle_netting_computed(cycle_id).await?);
    svc.commit_cycle_to_chain(cycle_id)
        .await
        .context("commit_cycle_to_chain")?;

    Ok(guarantee_id)
}

/// Backdate a cycle's off-chain finality deadline into the past so the settlement
/// job treats it as due. On-chain deadlines are advanced separately via anvil time.
async fn backdate_cycle_finality(ctx: &PersistCtx, cycle_id: &str) -> anyhow::Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let cycle = settlement_cycle::Entity::find_by_id(cycle_id.to_string())
        .one(ctx.db.as_ref())
        .await?
        .expect("cycle exists");
    let mut model: settlement_cycle::ActiveModel = cycle.into();
    model.payment_submission_deadline = Set(now - chrono::Duration::hours(2));
    model.payment_finality_deadline = Set(now - chrono::Duration::hours(1));
    model.update(ctx.db.as_ref()).await?;
    Ok(())
}

/// Paid-debtor / unclaimed-creditor path: every debtor pays voluntarily but a
/// creditor never claims. After finality the job funds the creditor from the pool
/// and finalizes — no defaults involved.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn fully_paid_cycle_with_unclaimed_creditor_is_settled_by_job() -> anyhow::Result<()> {
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();

    let (debtor, debtor_provider) = common::chain::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, _creditor_provider) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-unclaimed-creditor";
    // Future deadlines so the debtor can pay voluntarily on-chain.
    let guarantee_id = commit_two_party_cycle(&svc, cycle_id, &debtor, &creditor).await?;
    mine(&provider, 2).await?;

    // The debtor pays; the creditor never claims.
    let debtor_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&debtor))
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), debtor_provider)
        .payNetDebit(
            debtor_proof.cycle_id,
            debtor_proof.amount,
            debtor_proof.proof,
        )
        .value(debtor_proof.amount)
        .send()
        .await
        .context("payNetDebit send")?
        .watch()
        .await
        .context("payNetDebit confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(ctx, cycle_id, &lower(&debtor), ParticipantCycleStatus::Paid).await?;
    poll_guarantee_status(ctx, &guarantee_id, GuaranteeSettlementStatus::Settled).await?;

    // Push on-chain time past finality (so finalizeCycle is allowed) and backdate the
    // off-chain finality deadline (so the job sees the cycle as due).
    provider
        .anvil_set_block_timestamp_interval(5 * 60 * 60)
        .await?;
    backdate_cycle_finality(ctx, cycle_id).await?;

    // First job pass: no debtors to seize, but the unclaimed creditor is funded.
    let settled = svc.settle_due_cycles().await?;
    assert!(settled.iter().any(|c| c == cycle_id));
    mine(&provider, 2).await?;

    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Settling).await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&creditor),
        ParticipantCycleStatus::Claimed,
    )
    .await?;

    // The creditor's collateral was funded from the pool.
    let core = Core4Mica::new(*env.contract.address(), provider.clone());
    let creditor_balance = core
        .withdrawableBalance(creditor, Address::ZERO)
        .call()
        .await?;
    assert_eq!(
        creditor_balance,
        U256::from(NET_AMOUNT),
        "creditor collateral funded"
    );

    // Second job pass: the off-chain ledger is fully resolved, so the cycle finalizes.
    svc.settle_due_cycles().await?;
    mine(&provider, 2).await?;
    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Finalized).await?;

    Ok(())
}

/// Default path driven entirely by the off-chain settlement job: after finality the
/// job seizes the unpaid debtor's on-chain collateral into the pool, funds the
/// unclaimed creditor's collateral back out of the pool, and finalizes the cycle.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn defaulted_cycle_is_batch_settled_by_job() -> anyhow::Result<()> {
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();

    let (debtor, debtor_provider) = common::chain::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, _creditor_provider) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-batch-default";
    let guarantee_id =
        commit_two_party_cycle_past_finality(&svc, &provider, cycle_id, &debtor, &creditor).await?;

    // The debtor's collateral lives on-chain in Core4Mica so the pool can seize it.
    let amount = U256::from(NET_AMOUNT);
    Core4Mica::new(*env.contract.address(), debtor_provider)
        .deposit()
        .value(amount)
        .send()
        .await
        .context("debtor deposit send")?
        .watch()
        .await
        .context("debtor deposit confirm")?;
    mine(&provider, 2).await?;

    // First job pass: the debtor never paid, so finality handling seizes the
    // debtor's collateral, funds the creditor's collateral, and marks the cycle
    // settling (one-shot — finality and submission are folded into one phase).
    let settled = svc.settle_due_cycles().await?;
    assert!(settled.iter().any(|c| c == cycle_id));
    mine(&provider, 2).await?;

    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Settling).await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&debtor),
        ParticipantCycleStatus::Defaulted,
    )
    .await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&creditor),
        ParticipantCycleStatus::Claimed,
    )
    .await?;
    poll_guarantee_status(
        ctx,
        &guarantee_id,
        GuaranteeSettlementStatus::DefaultRemunerated,
    )
    .await?;

    // The debtor's collateral was seized; the creditor's collateral was funded.
    let core = Core4Mica::new(*env.contract.address(), provider.clone());
    let debtor_balance = core
        .withdrawableBalance(debtor, Address::ZERO)
        .call()
        .await?;
    let creditor_balance = core
        .withdrawableBalance(creditor, Address::ZERO)
        .call()
        .await?;
    assert_eq!(debtor_balance, U256::ZERO, "debtor collateral fully seized");
    assert_eq!(creditor_balance, amount, "creditor collateral funded");

    // Second job pass: the off-chain ledger is fully resolved, so the cycle finalizes.
    svc.settle_due_cycles().await?;
    mine(&provider, 2).await?;
    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Finalized).await?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn under_collateralized_cycle_is_socialized_to_shortfall_by_job() -> anyhow::Result<()> {
    unsafe {
        std::env::set_var("SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS", "5");
        std::env::set_var("SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS", "5");
    }
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    unsafe {
        std::env::remove_var("SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS");
        std::env::remove_var("SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS");
    }
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();

    let (debtor, debtor_provider) = common::chain::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, _creditor_provider) = common::chain::wallet_provider(&http, CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-shortfall";
    // Commit with a short (5s) future window rather than jumping anvil time, so wall-clock can
    // pass the on-chain finality deadline the shortfall driver reads.
    commit_two_party_cycle_finality_soon(&svc, cycle_id, &debtor, &creditor, 5).await?;

    // The debtor only posts HALF its net debit on-chain, so the pool can never be fully funded.
    let half = U256::from(NET_AMOUNT / 2);
    Core4Mica::new(*env.contract.address(), debtor_provider)
        .deposit()
        .value(half)
        .send()
        .await
        .context("debtor deposit send")?
        .watch()
        .await
        .context("debtor deposit confirm")?;
    mine(&provider, 2).await?;

    // Push on-chain block time past the finality deadline (so settleDefaults/markCycleShortfall
    // are allowed on-chain), let wall-clock pass finality + grace (so the driver's grace window
    // elapses), and backdate the off-chain deadline so the job treats the cycle as due.
    provider
        .anvil_set_block_timestamp_interval(3 * 60 * 60)
        .await?;
    mine(&provider, 1).await?;
    tokio::time::sleep(Duration::from_secs(9)).await;
    backdate_cycle_finality(ctx, cycle_id).await?;

    // One job pass: the seize recovers the partial collateral, the creditor-funding batch can't
    // fully fund, so the job drives the cycle terminal (Shortfall) and pays the creditor pro-rata.
    svc.settle_due_cycles().await?;
    mine(&provider, 2).await?;

    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Shortfall).await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&debtor),
        ParticipantCycleStatus::Defaulted,
    )
    .await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&creditor),
        ParticipantCycleStatus::Claimed,
    )
    .await?;

    // Debtor's collateral fully seized; creditor made whole only up to the recovered pool
    // (pro-rata = NET_AMOUNT * (NET_AMOUNT/2) / NET_AMOUNT = NET_AMOUNT/2).
    let core = Core4Mica::new(*env.contract.address(), provider.clone());
    let debtor_balance = core
        .withdrawableBalance(debtor, Address::ZERO)
        .call()
        .await?;
    let creditor_balance = core
        .withdrawableBalance(creditor, Address::ZERO)
        .call()
        .await?;
    assert_eq!(debtor_balance, U256::ZERO, "debtor collateral fully seized");
    assert_eq!(
        creditor_balance, half,
        "creditor made whole only up to its pro-rata share"
    );

    Ok(())
}
