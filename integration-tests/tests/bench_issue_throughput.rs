//! Guarantee-issuance load test — find core's real max issuance throughput.
//!
//! The stampede driver is a *closed loop*: N tasks each block on one `issue`
//! call at a time, so throughput = N / per-request-latency (e.g. 12 / 54ms ≈
//! 220/s) — that number measures round-trip latency, not core's ceiling. To find
//! the ceiling you must push many more requests *in flight*.
//!
//! This sweeps concurrency (requests in flight) and reports, per level, achieved
//! throughput and p50/p95/p99 latency. Each concurrent worker uses its OWN payer
//! wallet, so no two workers contend on the same balance row — this isolates
//! core's genuine capacity (CPU: EIP-712 verify + BLS signing, plus Postgres),
//! not artificial per-payer lock serialization. Where throughput plateaus while
//! latency climbs is core's current max.
//!
//! All issuance is the direct SDK path (`sign_payment` → `issue_payment_guarantee`),
//! never the facilitator.
//!
//! ── Prereqs ────────────────────────────────────────────────────────────────
//! A running local stack (`make dev-up`). For a CLEAN throughput number, run
//! core with a NORMAL/long settlement cycle (the 86400s default) so the netting
//! scheduler isn't churning cycles mid-benchmark. (The short-cycle env from the
//! clearing demo adds background load and will understate the ceiling.)
//!
//! ── Run ────────────────────────────────────────────────────────────────────
//!   SDK_LOCAL_E2E=1 cargo test -p integration-tests --test bench_issue_throughput \
//!       -- --ignored --nocapture
//!
//! Tunables (env):
//!   BENCH_LEVELS        concurrency levels, CSV (default "4,8,16,32,64,96,128")
//!   BENCH_DURATION_SECS seconds per level      (default 6)
//!   BENCH_TIMEOUT_SECS  per-request timeout     (default 15)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::providers::{ProviderBuilder, ext::AnvilApi};
use anyhow::{Context, Result};
use sdk_4mica::{Client, PaymentGuaranteeRequestClaims, SigningScheme, U256};

mod common;

use crate::common::{authed_recipient_client, deposit_collateral_and_await, eth_rpc_url, get_now};

const AMOUNT_WEI: u128 = 1_000_000_000; // 1 gwei per guarantee — tiny, so deposits last
const DEPOSIT_WEI: u128 = 5_000_000_000_000_000_000; // 5 ETH per payer
const FUND_WEI: u128 = 100_000_000_000_000_000_000; // 100 ETH gas float

fn load_env() {
    dotenv::dotenv().ok();
    dotenv::from_filename("core/.env").ok();
    dotenv::from_filename("../core/.env").ok();
}

fn percentile(sorted_us: &[u64], p: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted_us.len() - 1) as f64).round() as usize;
    sorted_us[idx.min(sorted_us.len() - 1)] as f64 / 1000.0 // → ms
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::file_serial]
#[ignore = "load test; run by hand against a local stack"]
async fn bench_issue_throughput() -> Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }
    load_env();

    let levels: Vec<usize> = std::env::var("BENCH_LEVELS")
        .unwrap_or_else(|_| "4,8,16,32,64,96,128".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .filter(|&c: &usize| c > 0)
        .collect();
    let duration = Duration::from_secs(
        std::env::var("BENCH_DURATION_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6),
    );
    let req_timeout = Duration::from_secs(
        std::env::var("BENCH_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15),
    );
    let wallets_needed = *levels.iter().max().unwrap_or(&8);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  4MICA · GUARANTEE ISSUANCE LOAD TEST (direct SDK → core)      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  concurrency levels ... {levels:?}");
    println!("  duration per level ... {}s", duration.as_secs());
    println!("  wallets (1 payer / worker, distinct rows) ... {wallets_needed}\n");

    // ── setup: one authed wallet per worker slot; fund + deposit each ─────────
    println!("  [setup] registering + funding {wallets_needed} wallets…");
    let mut clients: Vec<Client<_>> = Vec::with_capacity(wallets_needed);
    let mut configs = Vec::with_capacity(wallets_needed);
    let mut addrs: Vec<String> = Vec::with_capacity(wallets_needed);
    for i in 0..wallets_needed {
        let key = format!("0x{:064x}", i + 1);
        let (config, client) = authed_recipient_client(&key)
            .await
            .with_context(|| format!("auth wallet {i}"))?;
        addrs.push(format!("{:#x}", config.signer.address()));
        configs.push(config);
        clients.push(client);
    }
    let rpc_url = eth_rpc_url(&configs[0]).await?;
    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    for cfg in &configs {
        provider
            .anvil_set_balance(cfg.signer.address(), U256::from(FUND_WEI))
            .await?;
    }
    let mut deposits = Vec::new();
    for i in 0..wallets_needed {
        let client = clients[i].clone();
        let config = configs[i].clone();
        deposits.push(tokio::spawn(async move {
            deposit_collateral_and_await(&client, &config, None, U256::from(DEPOSIT_WEI)).await
        }));
    }
    for (i, d) in deposits.into_iter().enumerate() {
        d.await
            .expect("deposit panicked")
            .with_context(|| format!("deposit wallet {i}"))?;
    }

    let clients = Arc::new(clients);
    let addrs = Arc::new(addrs);
    let req_ctr = Arc::new(AtomicU64::new(get_now().as_nanos() as u64));

    println!("  [warmup] priming tabs + active cycle…");
    run_level(
        &clients,
        &addrs,
        &req_ctr,
        wallets_needed.min(8),
        Duration::from_secs(2),
        req_timeout,
    )
    .await;

    // ── sweep ─────────────────────────────────────────────────────────────────
    println!("\n  ┌──────────┬────────────┬───────────┬──────────┬──────────┬──────────┬────────┐");
    println!("  │ in-flight│ throughput │  success  │  p50 ms  │  p95 ms  │  p99 ms  │  fail  │");
    println!("  ├──────────┼────────────┼───────────┼──────────┼──────────┼──────────┼────────┤");

    let mut best = (0usize, 0.0f64);
    for &c in &levels {
        if c > wallets_needed {
            continue;
        }
        let r = run_level(&clients, &addrs, &req_ctr, c, duration, req_timeout).await;
        let tput = r.success as f64 / r.elapsed_secs;
        if tput > best.1 {
            best = (c, tput);
        }
        println!(
            "  │ {:>8} │ {:>7.0}/s │ {:>9} │ {:>8.1} │ {:>8.1} │ {:>8.1} │ {:>6} │",
            c, tput, r.success, r.p50, r.p95, r.p99, r.fail
        );
        // brief cooldown so levels don't bleed into each other
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    println!("  └──────────┴────────────┴───────────┴──────────┴──────────┴──────────┴────────┘");
    println!(
        "\n  ► peak throughput ≈ {:.0} guarantees/s at {} in flight",
        best.1, best.0
    );
    println!("    (throughput plateaus while p95/p99 climb → that knee is core's current max)\n");

    Ok(())
}

struct LevelResult {
    success: u64,
    fail: u64,
    elapsed_secs: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

async fn run_level(
    clients: &Arc<Vec<Client<alloy::signers::local::PrivateKeySigner>>>,
    addrs: &Arc<Vec<String>>,
    req_ctr: &Arc<AtomicU64>,
    concurrency: usize,
    duration: Duration,
    req_timeout: Duration,
) -> LevelResult {
    let success = Arc::new(AtomicU64::new(0));
    let fail = Arc::new(AtomicU64::new(0));
    let lats = Arc::new(Mutex::new(Vec::<u64>::with_capacity(4096)));
    let n = clients.len();
    let deadline = Instant::now() + duration;
    let started = Instant::now();

    let mut workers = Vec::with_capacity(concurrency);
    for k in 0..concurrency {
        let clients = clients.clone();
        let addrs = addrs.clone();
        let req_ctr = req_ctr.clone();
        let success = success.clone();
        let fail = fail.clone();
        let lats = lats.clone();
        let payer = k; // dedicated payer per worker → no balance-row contention
        let recip = (k + 1) % n; // distinct recipient, distinct tab row
        workers.push(tokio::spawn(async move {
            let mut local = Vec::<u64>::with_capacity(1024);
            while Instant::now() < deadline {
                let req_id = U256::from(req_ctr.fetch_add(1, Ordering::Relaxed));
                let claims = PaymentGuaranteeRequestClaims::new(
                    addrs[payer].clone(),
                    addrs[recip].clone(),
                    req_id,
                    U256::from(AMOUNT_WEI),
                    get_now().as_secs(),
                    None,
                );
                let signed = clients[payer]
                    .user
                    .sign_payment(claims.clone(), SigningScheme::Eip712)
                    .await;
                let sig = match signed {
                    Ok(s) => s.signature,
                    Err(_) => {
                        fail.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let t0 = Instant::now();
                let issue = clients[recip].recipient.issue_payment_guarantee(
                    claims,
                    sig,
                    SigningScheme::Eip712,
                );
                match tokio::time::timeout(req_timeout, issue).await {
                    Ok(Ok(_)) => {
                        local.push(t0.elapsed().as_micros() as u64);
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            lats.lock().unwrap().extend(local);
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    let elapsed_secs = started.elapsed().as_secs_f64();

    let mut sorted = Arc::try_unwrap(lats).unwrap().into_inner().unwrap();
    sorted.sort_unstable();
    LevelResult {
        success: success.load(Ordering::Relaxed),
        fail: fail.load(Ordering::Relaxed),
        elapsed_secs,
        p50: percentile(&sorted, 50.0),
        p95: percentile(&sorted, 95.0),
        p99: percentile(&sorted, 99.0),
    }
}
