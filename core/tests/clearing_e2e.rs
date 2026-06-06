//! End-to-end clearing tests: a real cycle is netted, committed to the on-chain
//! ClearingHouse, paid/claimed by participants, and finalized — with the event
//! scanner mirroring every step back into the database.
//!
//! Contract-internal logic (proof checks, accounting, reverts) is covered by the
//! Foundry suite; these tests prove the Rust<->contract round trip: that a
//! Rust-built Merkle root and proofs verify on-chain and that the resulting
//! events drive the database state machine.

use std::time::Duration;

use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::DynProvider;
use alloy::providers::ext::AnvilApi;
use anyhow::Context;
use entities::guarantee;
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleStatus, SettlementCycleStatus,
};
use sea_orm::EntityTrait;
use test_log::test;

mod common;
use common::contract::ClearingHouse;
use common::cycle_fixtures::{create_frozen_cycle, store_payable_guarantee};
use common::fixtures::{ensure_user_with_collateral, set_locked_collateral};
use common::setup::{OPERATOR_KEY, setup_e2e_environment};
use core_service::persist::{PersistCtx, repo};

// Operator key = same key CoreService uses internally. A fresh HTTP provider (no
// nonce cache) is built from it for test-side calls so it always queries the
// chain for the current nonce, regardless of what CoreService's provider has done.
const DEBTOR_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const CREDITOR_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

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
        if let Some(cycle) = repo::get_cycle_by_id(ctx, cycle_id).await? {
            if cycle.status == expected {
                return Ok(());
            }
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
        {
            if g.settlement_status == expected {
                return Ok(());
            }
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

    let (_, op_provider) = common::setup::wallet_provider(&http, OPERATOR_KEY)?;
    let (debtor, debtor_provider) = common::setup::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, creditor_provider) = common::setup::wallet_provider(&http, CREDITOR_KEY)?;

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
        .anvil_set_block_timestamp_interval(3 * 60 * 60)
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

/// Default path: debtor never pays, is marked defaulted after the finality
/// deadline, the default is covered from collateral, and the cycle finalizes.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn defaulted_cycle_is_covered_and_finalized() -> anyhow::Result<()> {
    let env = setup_e2e_environment()
        .await
        .context("setup_e2e_environment")?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let ctx = svc.persist_ctx();
    let http = env.cfg.ethereum_config.http_rpc_url.clone();

    let (_, op_provider) = common::setup::wallet_provider(&http, OPERATOR_KEY)?;
    let (debtor, _debtor_provider) = common::setup::wallet_provider(&http, DEBTOR_KEY)?;
    let (creditor, creditor_provider) = common::setup::wallet_provider(&http, CREDITOR_KEY)?;

    let cycle_id = "clearing-e2e-default";
    let guarantee_id = commit_two_party_cycle(&svc, cycle_id, &debtor, &creditor).await?;

    let debtor_proof = svc
        .get_participant_clearing_proof(cycle_id, &lower(&debtor))
        .await?;
    let amount = debtor_proof.amount;

    // Debtor never pays; advance past the finality deadline and mark defaulted.
    provider
        .anvil_set_block_timestamp_interval(3 * 60 * 60)
        .await?;
    ClearingHouse::new(*env.clearing_house.address(), op_provider.clone())
        .markDefaulted(
            debtor_proof.cycle_id,
            debtor,
            amount,
            debtor_proof.proof.clone(),
        )
        .send()
        .await
        .context("markDefaulted send")?
        .watch()
        .await
        .context("markDefaulted confirm")?;
    mine(&provider, 2).await?;
    poll_position_status(
        ctx,
        cycle_id,
        &lower(&debtor),
        ParticipantCycleStatus::Defaulted,
    )
    .await?;
    poll_cycle_status(ctx, cycle_id, SettlementCycleStatus::Defaulted).await?;

    // Operator covers the default from collateral.
    ClearingHouse::new(*env.clearing_house.address(), op_provider.clone())
        .settleDefaultFromCollateral(debtor_proof.cycle_id, debtor, amount, Bytes::new())
        .value(amount)
        .send()
        .await
        .context("settleDefaultFromCollateral send")?
        .watch()
        .await
        .context("settleDefaultFromCollateral confirm")?;
    mine(&provider, 2).await?;
    poll_guarantee_status(
        ctx,
        &guarantee_id,
        GuaranteeSettlementStatus::DefaultRemunerated,
    )
    .await?;

    // Creditor still claims against the covered liquidity, then the cycle finalizes.
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
