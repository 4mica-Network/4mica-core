//! Act 3 — the clearing layer, live.
//!
//! This is the demo driver for the investor call: it shows the one thing an
//! x402 facilitator (or any bilateral batching scheme) structurally cannot do —
//! *multilateral* netting across many participants at once, committed on-chain.
//!
//! It seeds a realistic machine-commerce payment graph (AI agents paying data /
//! compute merchants, merchants paying each other for upstream services) as a
//! frozen, backdated settlement cycle, then lets the *real running core-service
//! scheduler* net it and commit the clearing batch on-chain. There is no
//! endpoint to force a commit; the scheduler does it exactly as it would in
//! production. We then read the result straight back out of core's DB — the net
//! positions and the on-chain Merkle root are core's own output, not the script's.
//!
//! The headline it prints is the number that matters: gross payments in vs. net
//! movement out, i.e. the liquidity the clearing layer saved.
//!
//! Prereqs: the full local stack must be up (`make dev-up` in 4mica-core), which
//! runs Postgres, anvil, the deployed ClearingHouse, and core-service on :3000.
//!
//! Run it (nocapture so the narration prints):
//!
//!   SDK_LOCAL_E2E=1 cargo test -p integration-tests --test demo_clearing \
//!       -- --ignored --nocapture
//!
//! It is `#[ignore]` so it never runs in the normal `make test` sweep — it is a
//! demo, driven by hand.

use alloy::primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use std::collections::BTreeMap;
use std::str::FromStr;

use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::{CycleGuaranteeData, PersistCtx, repo};
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, SettlementCycleStatus,
};

mod common;

use crate::common::get_now;

/// One directed obligation in the payment graph: `from` owes `to` `amount`.
struct Edge {
    from: u8,
    to: u8,
    amount: u64,
}

/// Friendly label for a participant, keyed by the leading byte of its address so
/// the printed tables read as A1/M2/… instead of 0xa1a1…a1.
fn label(byte: u8) -> String {
    match byte {
        0xA1..=0xA5 => format!("Agent  A{}", byte - 0xA0),
        0xB1..=0xB3 => format!("Merch  M{}", byte - 0xB0),
        other => format!("0x{other:02x}"),
    }
}

/// A recognizable, deterministic address per participant (0xa1a1…a1, 0xb2b2…b2).
fn addr(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

fn norm(a: Address) -> String {
    format!("{a:#x}")
}

/// The machine-commerce settlement graph. Amounts are in the settlement asset's
/// base units; the exact scale is irrelevant to the netting story, so we keep
/// them as clean integers that make the arithmetic legible on screen.
///
/// It is deliberately *not* a set of independent buyer→seller pairs: merchants
/// both receive (from agents) and pay (upstream to each other), and one agent
/// gets a refund that makes it net perfectly flat. That cross-linking is exactly
/// what bilateral batching cannot collapse.
fn payment_graph() -> Vec<Edge> {
    vec![
        // Agents pay merchants for data / compute.
        Edge {
            from: 0xA1,
            to: 0xB1,
            amount: 50,
        },
        Edge {
            from: 0xA2,
            to: 0xB1,
            amount: 30,
        },
        Edge {
            from: 0xA3,
            to: 0xB2,
            amount: 40,
        },
        Edge {
            from: 0xA4,
            to: 0xB2,
            amount: 20,
        },
        Edge {
            from: 0xA5,
            to: 0xB3,
            amount: 60,
        },
        // Merchants pay each other for upstream services — the multilateral part.
        Edge {
            from: 0xB1,
            to: 0xB2,
            amount: 45,
        },
        Edge {
            from: 0xB2,
            to: 0xB3,
            amount: 55,
        },
        Edge {
            from: 0xB3,
            to: 0xB1,
            amount: 35,
        },
        // A refund back to A1 that nets it to exactly zero — fully eliminated.
        Edge {
            from: 0xB3,
            to: 0xA1,
            amount: 50,
        },
    ]
}

/// dotenv the core service's generated env so `PersistCtx::new()` (DATABASE_URL)
/// and the anvil RPC URL resolve, whether we run from the repo root or `core/`.
fn load_env() {
    dotenv::dotenv().ok();
    dotenv::from_filename("core/.env").ok();
    dotenv::from_filename("../core/.env").ok();
}

fn eth_rpc_url() -> String {
    std::env::var("ETHEREUM_HTTP_RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string())
}

#[tokio::test]
#[serial_test::file_serial]
#[ignore = "demo driver; run by hand against a local `make dev-up` stack"]
async fn demo_multilateral_clearing() -> Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    load_env();
    let ctx = PersistCtx::new()
        .await
        .context("connect to core database")?;

    let edges = payment_graph();
    let cycle_id = format!("demo-clearing:{}", get_now().as_nanos());

    print_gross_graph(&edges);
    inject_frozen_cycle(&ctx, &cycle_id, &edges).await?;

    println!("\n  Injected frozen cycle {cycle_id}.");
    println!("  Handing it to the live core-service scheduler to net & commit on-chain…\n");

    // No endpoint commits a cycle — the running scheduler does, exactly as in
    // production. Every deadline is backdated, so it nets and commits on its next
    // tick; this blocks until the on-chain commit lands and the payment window opens.
    common::clearing::wait_for_payment_window(&cycle_id, &eth_rpc_url())
        .await
        .context("scheduler never opened the payment window for the demo cycle")?;

    print_net_result(&ctx, &cycle_id, &edges).await?;
    Ok(())
}

/// Seed the whole graph as one frozen, backdated cycle: every obligation stored
/// as a `FinalizedPayable` guarantee so netting counts it immediately, and each
/// debtor's collateral locked to mirror the post-issuance state the pipeline
/// expects. Mirrors `common::clearing::inject_frozen_two_party_cycle`, generalized
/// to an arbitrary multi-party graph.
async fn inject_frozen_cycle(ctx: &PersistCtx, cycle_id: &str, edges: &[Edge]) -> Result<()> {
    let now = Utc::now().naive_utc();

    repo::create_settlement_cycle_on(
        ctx.db.as_ref(),
        repo::CreateSettlementCycleInput {
            id: cycle_id.to_string(),
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            period_start: now - Duration::hours(3),
            period_end: now - Duration::hours(2),
            resolution_cutoff: now - Duration::hours(1),
            clearing_commit_deadline: now - Duration::minutes(30),
            // Leave the payment windows well in the future so the cycle parks at
            // PaymentWindowOpen — the perfect place to read the net positions —
            // instead of racing on to settlement/seizure mid-demo.
            payment_submission_deadline: now + Duration::hours(6),
            payment_finality_deadline: now + Duration::hours(12),
        },
    )
    .await
    .context("create settlement cycle")?;
    if !repo::freeze_cycle_on(ctx.db.as_ref(), cycle_id, now).await? {
        bail!("failed to freeze injected cycle {cycle_id}");
    }

    // Every participant must exist before a guarantee references it.
    let mut participants = std::collections::BTreeSet::new();
    for e in edges {
        participants.insert(e.from);
        participants.insert(e.to);
    }
    for &p in &participants {
        repo::ensure_user_exists_on(ctx.db.as_ref(), &norm(addr(p))).await?;
    }

    // Store each obligation as an already-FinalizedPayable cycle guarantee.
    for (req_id, e) in edges.iter().enumerate() {
        let from = norm(addr(e.from));
        let to = norm(addr(e.to));
        let guarantee_id = format!("{cycle_id}:{from}:{to}:{req_id}");
        repo::store_cycle_guarantee_on(
            ctx.db.as_ref(),
            CycleGuaranteeData {
                guarantee_id,
                cycle_id: cycle_id.to_string(),
                req_id: U256::from(req_id as u64),
                version: 2,
                from,
                to,
                asset: DEFAULT_ASSET_ADDRESS.to_string(),
                value: U256::from(e.amount),
                start_ts: now,
                cert: "{}".to_string(),
                request: None,
                settlement_status: GuaranteeSettlementStatus::FinalizedPayable,
            },
        )
        .await
        .with_context(|| format!("store guarantee {}->{}", label(e.from), label(e.to)))?;
    }

    // Lock each participant's gross outgoing as collateral — always ≥ its net
    // debit, mirroring the locked state at issuance so the commit has backing.
    let mut outgoing: BTreeMap<u8, u64> = BTreeMap::new();
    for e in edges {
        *outgoing.entry(e.from).or_default() += e.amount;
    }
    for (&p, &gross_out) in &outgoing {
        if gross_out == 0 {
            continue;
        }
        let who = norm(addr(p));
        let amount = U256::from(gross_out);
        repo::deposit(ctx, who.clone(), DEFAULT_ASSET_ADDRESS.to_string(), amount)
            .await
            .context("credit participant collateral")?;
        let balance =
            repo::get_user_balance_on(ctx.db.as_ref(), &who, DEFAULT_ASSET_ADDRESS).await?;
        let total = U256::from_str(&balance.total)
            .map_err(|e| anyhow::anyhow!("invalid collateral {}: {e}", balance.total))?;
        repo::update_user_balance_and_version_on(
            ctx.db.as_ref(),
            &who,
            DEFAULT_ASSET_ADDRESS,
            balance.version,
            total,
            amount,
        )
        .await
        .context("lock participant collateral")?;
    }

    Ok(())
}

fn print_gross_graph(edges: &[Edge]) {
    let gross: u64 = edges.iter().map(|e| e.amount).sum();
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  ACT 3 — MULTILATERAL CLEARING (live, on-chain)");
    println!("══════════════════════════════════════════════════════════════\n");
    println!(
        "  BEFORE — {} gross obligations across the network:",
        edges.len()
    );
    println!("  ─────────────────────────────────────────────");
    for e in edges {
        println!(
            "    {}  →  {}    {:>4}",
            label(e.from),
            label(e.to),
            e.amount
        );
    }
    println!("  ─────────────────────────────────────────────");
    println!("    gross value moving if settled one-by-one:  {gross}");
    println!(
        "\n  A bilateral batcher (native x402 pooling) can only compress the\n  \
         individual A→M pairs. The M↔M cross-links stay as separate transfers."
    );
}

async fn print_net_result(ctx: &PersistCtx, cycle_id: &str, edges: &[Edge]) -> Result<()> {
    let cycle = repo::get_cycle_by_id_on(ctx.db.as_ref(), cycle_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("cycle {cycle_id} vanished"))?;
    let mut positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;

    // Debtors first, then creditors, then the eliminated (flat) participants.
    let role_rank = |r: &ParticipantCycleRole| match r {
        ParticipantCycleRole::NetDebtor => 0,
        ParticipantCycleRole::NetCreditor => 1,
        ParticipantCycleRole::Flat => 2,
    };
    positions.sort_by_key(|p| (role_rank(&p.role), p.participant.clone()));

    // Map normalized address → leading byte so we can relabel core's output.
    let byte_of = |a: &str| -> u8 { Address::from_str(a).map(|x| x.as_slice()[0]).unwrap_or(0) };

    let gross: u64 = edges.iter().map(|e| e.amount).sum();
    let net = U256::from_str(&cycle.net_settlement_amount).unwrap_or(U256::ZERO);
    let net_u = u64::try_from(net).unwrap_or(0);
    let debtors = positions
        .iter()
        .filter(|p| p.role == ParticipantCycleRole::NetDebtor)
        .count();
    let creditors = positions
        .iter()
        .filter(|p| p.role == ParticipantCycleRole::NetCreditor)
        .count();
    let eliminated = positions
        .iter()
        .filter(|p| p.role == ParticipantCycleRole::Flat)
        .count();

    println!("  AFTER — core netted the cycle to per-participant positions:");
    println!("  ─────────────────────────────────────────────");
    println!("    {:<11}{:>8}{:>8}{:>10}", "party", "in", "out", "net");
    for p in &positions {
        let gin = U256::from_str(&p.gross_incoming).unwrap_or(U256::ZERO);
        let gout = U256::from_str(&p.gross_outgoing).unwrap_or(U256::ZERO);
        let (tag, net_str) = match p.role {
            ParticipantCycleRole::NetDebtor => ("owes ", format!("-{}", p.net_debit)),
            ParticipantCycleRole::NetCreditor => ("gets ", format!("+{}", p.net_credit)),
            ParticipantCycleRole::Flat => ("flat ", "0 (eliminated)".to_string()),
        };
        println!(
            "    {:<11}{:>8}{:>8}   {} {}",
            label(byte_of(&p.participant)),
            gin.to_string(),
            gout.to_string(),
            tag,
            net_str,
        );
    }
    println!("  ─────────────────────────────────────────────");

    let saved = gross.saturating_sub(net_u);
    let pct = if gross > 0 {
        (saved as f64 / gross as f64) * 100.0
    } else {
        0.0
    };

    println!("\n  ── SETTLEMENT ─────────────────────────────────");
    println!("    gross obligations ......... {gross}");
    println!("    net movement on-chain ..... {net_u}");
    println!("    liquidity saved ........... {saved}  ({pct:.0}%)");
    println!("    net debtors {debtors}  ·  net creditors {creditors}  ·  eliminated {eliminated}");
    println!("  ───────────────────────────────────────────────");
    println!(
        "    on-chain Merkle root ...... {}",
        cycle.clearing_batch_hash.as_deref().unwrap_or("(pending)")
    );
    println!(
        "    commit tx ................. {}",
        cycle.commit_tx_hash.as_deref().unwrap_or("(pending)")
    );
    println!("    cycle status .............. {:?}", cycle.status);
    debug_assert_eq!(cycle.status, SettlementCycleStatus::PaymentWindowOpen);
    println!("\n  One Merkle root committed to the ClearingHouse settles the whole");
    println!("  network. This is the layer x402 cannot absorb.\n");

    Ok(())
}
