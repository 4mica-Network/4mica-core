//! Act 3 (real) — N participants, one per CPU core, each asking local core for
//! real payment guarantees over the SDK (no facilitator), then cleared
//! multilaterally by core's own settlement scheduler.
//!
//! This produces REAL data: every edge is a genuine V1 payment guarantee issued
//! by `core-service` (real EIP-712 signature, real BLS certificate, real
//! collateral lock), attached to the active settlement cycle. When the cycle
//! elapses, core's scheduler nets it and commits one clearing batch (one Merkle
//! root) on-chain — exactly the production path. We then read the net positions
//! straight out of core and write `~/4mica-demo/clearing-run.json`, which the
//! Clearing Terminal visual replays.
//!
//! The whole thing is the direct SDK guarantee path — `sign_payment` then
//! `issue_payment_guarantee` — never the x402 facilitator.
//!
//! ── Prereqs ────────────────────────────────────────────────────────────────
//! Run core locally with a SHORT settlement cycle so netting happens in seconds,
//! not a day. Deploy / launch core-service with these env vars (the rest of
//! `make dev-up` is unchanged):
//!
//!   SETTLEMENT_CYCLE_SECS=30
//!   SETTLEMENT_RESOLUTION_CUTOFF_SECS=4
//!   SETTLEMENT_CLEARING_COMMIT_DELAY_SECS=4
//!   SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS=3600
//!   SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS=7200
//!   CRON_JOB_SETTINGS="*/2 * * * * *"          # scheduler ticks every 2s
//!
//! With a 30s cycle the stampede finishes well inside one window; ~40s later the
//! scheduler has frozen, netted and committed it.
//!
//! ── Run ────────────────────────────────────────────────────────────────────
//!   SDK_LOCAL_E2E=1 cargo test -p integration-tests --test demo_guarantee_stampede \
//!       -- --ignored --nocapture
//!
//! Tunables (env): PARTICIPANTS (default = logical cores, capped 32),
//! EDGES_PER_PARTICIPANT (default 80).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use alloy::providers::{ProviderBuilder, ext::AnvilApi};
use anyhow::{Context, Result};
use sdk_4mica::{Client, Config, PaymentGuaranteeRequestClaims, SigningScheme, U256};

mod common;

use crate::common::{authed_recipient_client, deposit_collateral_and_await, eth_rpc_url, get_now};
use core_service::persist::{PersistCtx, repo};

const MAX_UNITS: u64 = 50; // per-payment amount is 1..=50 "cent" units of the settlement token
const FUND_WEI: u128 = 100_000_000_000_000_000_000; // 100 ETH gas float per participant

fn load_env() {
    dotenv::dotenv().ok();
    dotenv::from_filename("core/.env").ok();
    dotenv::from_filename("../core/.env").ok();
}

/// xorshift64 — a dependency-free PRNG so each core's participant picks payers and
/// amounts without pulling in `rand`.
#[inline]
fn nx(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

#[derive(serde::Serialize)]
struct ParticipantJson {
    index: usize,
    label: String,
    address: String,
}

#[derive(serde::Serialize)]
struct NetPositionJson {
    index: usize,
    label: String,
    role: String, // "debtor" | "creditor" | "flat"
    net_debit_wei: String,
    net_credit_wei: String,
    gross_out_wei: String,
    gross_in_wei: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RunJson {
    generated_unix: u64,
    cores: usize,
    participants: Vec<ParticipantJson>,
    unit: String,
    decimals: u32,
    /// gross[i][j] = wei that participant i paid participant j (for the chord viz).
    gross_pair_wei: Vec<Vec<String>>,
    pay_count: u64,
    issuance_failures: u64,
    gross_wei: String,
    net_wei: String,
    saved_pct: f64,
    legs: usize,
    net_positions: Vec<NetPositionJson>,
    cycle_id: String,
    merkle_root: String,
    commit_tx: Option<String>,
    via: String,
}

fn label_for(i: usize) -> String {
    format!("P{:02}", i + 1)
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::file_serial]
#[ignore = "real-data demo driver; run by hand against a local core deployed with short cycle params"]
async fn demo_guarantee_stampede() -> Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }
    load_env();

    let cores = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(8);
    let n: usize = std::env::var("PARTICIPANTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cores)
        .clamp(3, 32);
    let edges_per: usize = std::env::var("EDGES_PER_PARTICIPANT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  4MICA · GUARANTEE STAMPEDE → MULTILATERAL CLEARING (real)     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  logical cores ....... {cores}");
    println!("  participants ........ {n}  (one per core, capped 32)");
    println!(
        "  target guarantees ... {}  ({edges_per} issued by each participant)\n",
        n * edges_per
    );

    // ── 1. Bring up N participants: SIWE-authed recipient clients (each granted
    //       the guarantee:issue role), one throwaway key per participant. ──────
    println!("  [1/5] registering {n} participants with local core…");
    let mut clients: Vec<Client<_>> = Vec::with_capacity(n);
    let mut configs: Vec<Config<_>> = Vec::with_capacity(n);
    let mut addrs: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let key = format!("0x{:064x}", i + 1);
        let (config, client) = authed_recipient_client(&key)
            .await
            .with_context(|| format!("auth participant {i}"))?;
        addrs.push(format!("{:#x}", config.signer.address()));
        configs.push(config);
        clients.push(client);
    }

    // Settle in the deployed USDC token (ERC20), not native ETH.
    let supported = clients[0]
        .get_supported_tokens()
        .await
        .context("fetch supported tokens")?;
    let token = supported
        .tokens
        .iter()
        .find(|t| t.symbol.to_ascii_uppercase().contains("USDC"))
        .or_else(|| supported.tokens.first())
        .context("core advertises no ERC20 token to settle in")?;
    let usdc_addr = token.address.clone();
    let symbol = token.symbol.clone();
    let dec = token.decimals as u32;
    let one: u128 = 10u128.pow(dec); // 1 whole token in base units
    let unit_amt: u128 = one / 100; // 0.01 token per amount unit
    let deposit_base: u128 = 100 * one; // 100 tokens of collateral per participant
    println!("        settling in {symbol} ({usdc_addr}) · {dec} decimals");

    // ── 2. Fund gas + deposit collateral on-chain for every participant. ───────
    println!("  [2/5] funding gas and depositing {symbol} collateral on-chain…");
    let rpc_url = eth_rpc_url(&configs[0]).await?;
    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    for cfg in &configs {
        provider
            .anvil_set_balance(cfg.signer.address(), U256::from(FUND_WEI))
            .await
            .context("fund participant gas")?;
    }
    // Sequential, not concurrent: the ERC20 funding path mints by impersonating the
    // token owner, and every participant shares that one owner account — concurrent
    // mints would collide on its nonce ("nonce too low").
    for i in 0..n {
        deposit_collateral_and_await(
            &clients[i],
            &configs[i],
            Some(usdc_addr.clone()),
            U256::from(deposit_base),
        )
        .await
        .with_context(|| format!("deposit participant {i}"))?;
    }

    // Capture the active settlement cycle these guarantees will land in, BEFORE
    // the stampede, so we can wait for exactly this cycle to clear. (Issuing one
    // warm-up guarantee guarantees the active cycle exists.)
    let ctx = PersistCtx::new()
        .await
        .context("connect to core database")?;
    {
        let claims = PaymentGuaranteeRequestClaims::new(
            addrs[0].clone(),
            addrs[1 % n].clone(),
            U256::from(get_now().as_nanos()),
            U256::from(unit_amt),
            get_now().as_secs(),
            Some(usdc_addr.clone()),
        );
        let sig = clients[0]
            .user
            .sign_payment(claims.clone(), SigningScheme::Eip712)
            .await?;
        clients[1 % n]
            .recipient
            .issue_payment_guarantee(claims, sig.signature, SigningScheme::Eip712)
            .await
            .context("warm-up guarantee")?;
    }
    let cycle = repo::get_open_cycle_by_asset_on(ctx.db.as_ref(), &usdc_addr)
        .await?
        .context("no active settlement cycle after warm-up")?;
    let cycle_id = cycle.id.clone();
    println!("        active cycle: {cycle_id}");

    // ── 3. The stampede: N tasks (one per core), each participant issues real V1
    //       guarantees FROM random peers TO itself, straight to local core. ─────
    println!("  [3/5] issuing real guarantees across {n} cores…");
    let clients = Arc::new(clients);
    let addrs_arc = Arc::new(addrs.clone());
    let matrix = Arc::new(Mutex::new(vec![0u128; n * n])); // wei, matrix[i*n+j] = i→j
    let count = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let req_ctr = Arc::new(AtomicU64::new(get_now().as_nanos() as u64));
    let usdc = Arc::new(usdc_addr.clone());

    let started = std::time::Instant::now();
    let mut tasks = Vec::with_capacity(n);
    for j in 0..n {
        let clients = clients.clone();
        let addrs = addrs_arc.clone();
        let matrix = matrix.clone();
        let count = count.clone();
        let fail = fail.clone();
        let req_ctr = req_ctr.clone();
        let usdc = usdc.clone();
        tasks.push(tokio::spawn(async move {
            let mut s = ((j as u64).wrapping_add(1)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            if s == 0 {
                s = 0xDEAD_BEEF;
            }
            for _ in 0..edges_per {
                let mut i = (nx(&mut s) % n as u64) as usize;
                if i == j {
                    i = (i + 1) % n;
                }
                let units = 1 + (nx(&mut s) % MAX_UNITS);
                let amt = units as u128 * unit_amt;
                let req_id = U256::from(req_ctr.fetch_add(1, Ordering::Relaxed));
                let claims = PaymentGuaranteeRequestClaims::new(
                    addrs[i].clone(),
                    addrs[j].clone(),
                    req_id,
                    U256::from(amt),
                    get_now().as_secs(),
                    Some((*usdc).clone()),
                );
                let signed = clients[i]
                    .user
                    .sign_payment(claims.clone(), SigningScheme::Eip712)
                    .await;
                let ok = match signed {
                    Ok(sig) => clients[j]
                        .recipient
                        .issue_payment_guarantee(claims, sig.signature, SigningScheme::Eip712)
                        .await
                        .is_ok(),
                    Err(_) => false,
                };
                if ok {
                    matrix.lock().unwrap()[i * n + j] += amt;
                    count.fetch_add(1, Ordering::Relaxed);
                } else {
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for t in tasks {
        t.await.expect("issuance task panicked");
    }
    let issued = count.load(Ordering::Relaxed);
    let failures = fail.load(Ordering::Relaxed);
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "        {issued} guarantees issued in {:.1}s ({:.0}/s), {failures} failed",
        elapsed,
        issued as f64 / elapsed.max(0.001)
    );

    // ── 4. Let core's scheduler net + commit this cycle on-chain (short cycle). ─
    println!("  [4/5] waiting for the settlement scheduler to net & commit on-chain…");
    common::clearing::wait_for_payment_window(&cycle_id, &rpc_url)
        .await
        .context(
            "cycle did not reach its payment window — is core deployed with short cycle params?",
        )?;

    // ── 5. Read the real net positions + on-chain Merkle root and dump JSON. ────
    println!("  [5/5] reading net positions from core…");
    let cyc = repo::get_cycle_by_id_on(ctx.db.as_ref(), &cycle_id)
        .await?
        .context("settlement cycle vanished")?;
    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), &cycle_id).await?;

    let idx_of: std::collections::HashMap<String, usize> = addrs
        .iter()
        .enumerate()
        .map(|(i, a)| (a.to_ascii_lowercase(), i))
        .collect();

    let mut net_positions = Vec::new();
    let mut debtors = 0usize;
    let mut creditors = 0usize;
    for p in &positions {
        let idx = *idx_of
            .get(&p.participant.to_ascii_lowercase())
            .unwrap_or(&usize::MAX);
        let debit: u128 = p.net_debit.parse().unwrap_or(0);
        let credit: u128 = p.net_credit.parse().unwrap_or(0);
        let role = if debit > 0 {
            debtors += 1;
            "debtor"
        } else if credit > 0 {
            creditors += 1;
            "creditor"
        } else {
            "flat"
        };
        net_positions.push(NetPositionJson {
            index: idx,
            label: if idx == usize::MAX {
                p.participant.clone()
            } else {
                label_for(idx)
            },
            role: role.to_string(),
            net_debit_wei: p.net_debit.clone(),
            net_credit_wei: p.net_credit.clone(),
            gross_out_wei: p.gross_outgoing.clone(),
            gross_in_wei: p.gross_incoming.clone(),
        });
    }

    let gross_wei: u128 = cyc.gross_payable_amount.parse().unwrap_or(0);
    let net_wei: u128 = cyc.net_settlement_amount.parse().unwrap_or(0);
    let saved_pct = if gross_wei > 0 {
        (1.0 - (net_wei as f64 / gross_wei as f64)) * 100.0
    } else {
        0.0
    };
    let legs = debtors + creditors;

    let grid = matrix.lock().unwrap();
    let mut gross_pair_wei = vec![vec![String::from("0"); n]; n];
    for i in 0..n {
        for j in 0..n {
            gross_pair_wei[i][j] = grid[i * n + j].to_string();
        }
    }

    let run = RunJson {
        generated_unix: get_now().as_secs(),
        cores,
        participants: (0..n)
            .map(|i| ParticipantJson {
                index: i,
                label: label_for(i),
                address: addrs[i].clone(),
            })
            .collect(),
        unit: symbol.clone(),
        decimals: dec,
        gross_pair_wei,
        pay_count: issued,
        issuance_failures: failures,
        gross_wei: gross_wei.to_string(),
        net_wei: net_wei.to_string(),
        saved_pct,
        legs,
        net_positions,
        cycle_id: cycle_id.clone(),
        merkle_root: cyc.clearing_batch_hash.clone().unwrap_or_default(),
        commit_tx: cyc.commit_tx_hash.clone(),
        via: "sdk-direct-no-facilitator".to_string(),
    };

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = format!("{home}/4mica-demo");
    std::fs::create_dir_all(&dir).ok();
    let out_path = format!("{dir}/clearing-run.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&run)?)?;

    let money = |base: u128| format!("{:.4} {}", base as f64 / one as f64, symbol);
    println!("\n  ── RESULT ─────────────────────────────────────────");
    println!("    guarantees issued ......... {issued}");
    println!("    gross obligations ......... {}", money(gross_wei));
    println!("    net settlement ............ {}", money(net_wei));
    println!("    liquidity saved ........... {:.1}%", saved_pct);
    println!("    net debtors {debtors} · creditors {creditors} · legs {legs}");
    println!("    merkle root ............... {}", run.merkle_root);
    println!(
        "    commit tx ................. {}",
        run.commit_tx.as_deref().unwrap_or("(pending)")
    );
    println!("    cycle ..................... {cycle_id}");
    println!("  ───────────────────────────────────────────────────");
    println!("    wrote {out_path}");
    println!("    → the Clearing Terminal will replay this run.\n");

    Ok(())
}
