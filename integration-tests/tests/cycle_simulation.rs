//! Multi-cycle clearing simulation: N participants deposit USDC collateral, pay
//! each other over the x402 flow (guarantees issued through a real facilitator's
//! `/settle`), and the running core-service nets, commits, and settles each
//! cycle while the next one is already collecting payments. Some net debtors pay
//! voluntarily, the rest default and are seized from collateral; creditors are
//! paid out either by their own claim or by the operator's pool funding. Every
//! stage is verified against core's database, and each cycle gets a full
//! accounting audit at finalization.
//!
//! Needs, on top of the usual `SDK_LOCAL_E2E=1` stack:
//!
//! - a dev stack deployed with cycle windows long enough to actually pay inside
//!   (see the settlement envs in the repo README / `deployment/dev_stack.sh`;
//!   cycles shorter than 60s are skipped because the payment window is too
//!   tight for a multi-party simulation). For 10-minute cycles:
//!
//!   ```sh
//!   WITHDRAWAL_GRACE_PERIOD=1800 \
//!   SETTLEMENT_CYCLE_SECS=600 \
//!   SETTLEMENT_RESOLUTION_CUTOFF_SECS=60 \
//!   SETTLEMENT_CLEARING_COMMIT_DELAY_SECS=30 \
//!   SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS=120 \
//!   SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS=180 \
//!   SETTLEMENT_SEIZURE_MARGIN_SECS=120 \
//!   SETTLEMENT_SHORTFALL_GRACE_SECS=60 \
//!   SETTLEMENT_RETRY_DELAY_SECS=30 \
//!   make dev-up
//!   ```
//!
//!   `SETTLEMENT_RETRY_DELAY_SECS` matters more than it looks: a settlement
//!   tx that fails once (e.g. the seize losing the block-timestamp race right
//!   at the finality deadline) parks the cycle until the retry, and the
//!   production default of 1800s outlives this test's stage timeouts.
//!
//!   The grace period is deploy-time: core enforces
//!   `cycle + cutoff + commit delay + finality + seizure margin < withdrawalGracePeriod`,
//!   and the dev default of 60s cannot fit 10-minute cycles.
//!
//! - a running facilitator (facilitator-4mica repo) pointed at this core, named
//!   via `E2E_FACILITATOR_URL`. Its auth wallet needs the `facilitator` role
//!   with `guarantee:issue` + `payment:read`; the test seeds it for anvil #0
//!   (the facilitator repo's checked-in key — override with
//!   `SIM_FACILITATOR_WALLET`). Role and scopes are stamped into the token at
//!   login but re-read from the DB on refresh, so a facilitator that logged in
//!   before the seed picks them up within one access-token TTL — restart it to
//!   apply immediately.
//!
//! Run it with output streaming so the live board is visible (`RUST_LOG=warn`
//! keeps sqlx/alloy INFO noise out of the narration; raise it to debug a
//! failure):
//!
//! ```sh
//! SDK_LOCAL_E2E=1 RUST_LOG=warn E2E_FACILITATOR_URL=http://127.0.0.1:8080 \
//!   cargo test -p integration-tests --test cycle_simulation -- --nocapture
//! ```
//!
//! Knobs: `SIM_CYCLES` (5 — with 10-minute cycles the run takes about an
//! hour), `SIM_PARTICIPANTS` (10), `SIM_PAYMENTS_PER_CYCLE` (0 = fill the
//! window continuously; payments only pause while capacity is exhausted and
//! resume as older cycles release locks), `SIM_CONCURRENCY` (4 payments in
//! flight at once — same-payer collisions included, to exercise core's
//! optimistic balance locking), `SIM_PAYMENT_GAP_SECS` (2, between batches),
//! `SIM_SEED` (random, printed for reproduction). The run ends with a
//! per-cycle and per-participant summary table; participant deltas must sum
//! to zero.
//!
//! Forked stacks: a fork's upstream RPC (e.g. a public gateway) can throttle
//! mid-run and wedge individual requests inside anvil forever. The test bounds
//! all of its own calls, so that now surfaces as a timeout error rather than a
//! silent freeze — but for a soak this long prefer a bare (non-forked) stack,
//! or start anvil with `--timeout <ms> --retries <n>` so stalled fork fetches
//! fail fast.

mod common;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use alloy::providers::{ProviderBuilder, ext::AnvilApi};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, bail, ensure};
use axum::{Json, Router, extract::Query, http::StatusCode, routing::get};
use chrono::Utc;
use core_service::persist::{PersistCtx, repo};
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus,
};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sdk_4mica::x402::{PaymentRequirements, X402Flow, X402Requirements};
use sdk_4mica::{Address, BLSCert, Client, Config, U256};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::common::x402::ResourceResponse;
use crate::common::{OwnedERC20, deposit_collateral_and_await, eth_rpc_url};

/// Collateral each participant deposits, in whole tokens. Sized so two
/// overlapping cycles' worth of gross exposure fit under it and payments keep
/// flowing while the previous cycle is still settling.
const DEPOSIT_UNITS: u64 = 200;
/// Extra wallet balance for paying net debits, in whole tokens. Must cover the
/// worst case of `PER_CYCLE_OUT_CAP_UNITS` net debit per cycle, every cycle.
const WALLET_RESERVE_UNITS: u64 = 300;
/// Ceiling on one participant's gross outgoing per cycle, in whole tokens.
/// Keeps net debits payable from the wallet reserve across all cycles.
const PER_CYCLE_OUT_CAP_UNITS: u64 = 60;
/// Payment sizes, in hundredths of a token — small, so a cycle absorbs
/// hundreds of payments before capacity throttles.
const MIN_PAYMENT_CENTS: u64 = 50;
const MAX_PAYMENT_CENTS: u64 = 500;
/// Probability that a net debtor defaults instead of paying.
const DEFAULT_PROBABILITY: f64 = 0.35;
/// Extra patience beyond each cycle deadline before a stage times out.
const STAGE_SLACK_SECS: u64 = 300;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn now_unix() -> i64 {
    Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

struct Reporter {
    start: Instant,
}

impl Reporter {
    fn log(&self, scope: &str, msg: &str) {
        let elapsed = self.start.elapsed().as_secs();
        println!(
            "[{:>3}:{:02}] {scope:<12} {msg}",
            elapsed / 60,
            elapsed % 60
        );
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Phase {
    Collecting,
    Netting,
    PaymentWindow,
    Settling,
    Finalized,
}

struct BoardCycle {
    index: usize,
    id: String,
    phase: Phase,
    payments: usize,
    gross: U256,
    net: U256,
    debtors: usize,
    creditors: usize,
    paid: usize,
    defaulted: usize,
    claimed_wallet: usize,
    claimed_pool: usize,
}

struct Board {
    cycles: Vec<BoardCycle>,
}

// ---------------------------------------------------------------------------
// Simulation state
// ---------------------------------------------------------------------------

struct Participant {
    label: String,
    address: Address,
    client: Client<PrivateKeySigner>,
    config: Config<PrivateKeySigner>,
}

/// The test's own book of expectations, updated as payments are made and as
/// settlement drivers confirm releases/seizures/credits in the DB. DB
/// assertions poll against a fresh read of this book, so concurrent cycles
/// never race a stale snapshot.
struct Ledger {
    locked: Vec<U256>,
    collateral: Vec<U256>,
    wallet: Vec<U256>,
}

#[derive(Clone)]
struct PaymentRecord {
    payer: usize,
    payee: usize,
    amount: U256,
}

struct CyclePlan {
    index: usize,
    id: String,
    period_end: i64,
    payments: Vec<PaymentRecord>,
}

impl CyclePlan {
    fn gross_out(&self, participant: usize) -> U256 {
        self.payments
            .iter()
            .filter(|p| p.payer == participant)
            .fold(U256::ZERO, |acc, p| acc + p.amount)
    }

    fn gross_in(&self, participant: usize) -> U256 {
        self.payments
            .iter()
            .filter(|p| p.payee == participant)
            .fold(U256::ZERO, |acc, p| acc + p.amount)
    }
}

struct Sim {
    participants: Vec<Participant>,
    db: PersistCtx,
    usdc: Address,
    decimals: u32,
    rpc_url: String,
    facilitator_url: String,
    gateway_url: String,
    /// Shared HTTP client with a hard timeout: on a forked anvil a request can
    /// wedge forever inside the fork's upstream RPC, and an unbounded await
    /// here freezes a driver without ever tripping a poll deadline.
    http: reqwest::Client,
    ledger: Mutex<Ledger>,
    board: Mutex<Board>,
    reporter: Reporter,
    cycle_secs: u64,
}

/// Run `op` with a per-attempt timeout, retrying transient failures. Guards
/// every SDK/chain call a settlement driver makes: none of the underlying
/// clients carry timeouts, and a fork backend that stalls mid-request would
/// otherwise hang the driver forever.
async fn retrying<T, F, Fut>(what: &str, attempts: u32, mut op: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut last = None;
    for attempt in 1..=attempts {
        match tokio::time::timeout(Duration::from_secs(90), op()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(err)) => last = Some(err),
            Err(_) => last = Some(anyhow::anyhow!("timed out after 90s (wedged RPC?)")),
        }
        if attempt < attempts {
            eprintln!(
                "[cycle-sim] {what}: attempt {attempt}/{attempts} failed ({:#}), retrying…",
                last.as_ref().unwrap()
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    Err(last.unwrap()).with_context(|| format!("{what} failed after {attempts} attempt(s)"))
}

impl Sim {
    fn unit(&self) -> U256 {
        U256::from(10u64).pow(U256::from(self.decimals))
    }

    fn units(&self, whole: u64) -> U256 {
        U256::from(whole) * self.unit()
    }

    fn fmt(&self, amount: U256) -> String {
        let base = self.unit();
        let whole = (amount / base).to::<u64>();
        let cents = ((amount % base) * U256::from(100) / base).to::<u64>();
        format!("{whole}.{cents:02}")
    }

    fn label(&self, i: usize) -> &str {
        &self.participants[i].label
    }

    fn index_of(&self, address: Address) -> Option<usize> {
        self.participants.iter().position(|p| p.address == address)
    }

    async fn mine(&self, blocks: u64) {
        let _ = self
            .http
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "anvil_mine", "params": [blocks]
            }))
            .send()
            .await;
    }

    async fn db_balance(&self, i: usize) -> anyhow::Result<(U256, U256)> {
        let balance =
            repo::get_user_balance_on(self.db.db.as_ref(), self.participants[i].address, self.usdc)
                .await?;
        Ok((balance.total, balance.locked))
    }

    /// Poll until the participant's DB `locked` equals the ledger expectation.
    /// The target is re-read every iteration: a concurrent settlement driver
    /// may release locks (and update the ledger) while we wait.
    async fn wait_locked_matches(&self, i: usize, what: &str) -> anyhow::Result<()> {
        // Generous: the expectation converges only once every driver has
        // booked its releases, and a driver riding out wedged-RPC retries can
        // lag core by minutes.
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let expected = self.ledger.lock().await.locked[i];
            if let Ok((_, locked)) = self.db_balance(i).await
                && locked == expected
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                let (total, locked) = self.db_balance(i).await.unwrap_or_default();
                bail!(
                    "{}: {} locked never reached {} (db total={}, locked={})",
                    what,
                    self.label(i),
                    self.fmt(expected),
                    self.fmt(total),
                    self.fmt(locked)
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Poll until the participant's DB `total` equals the ledger expectation
    /// (the event scanner mirrors seizures and pool credits asynchronously).
    async fn wait_collateral_matches(&self, i: usize, what: &str) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let expected = self.ledger.lock().await.collateral[i];
            if let Ok((total, _)) = self.db_balance(i).await
                && total == expected
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                let (total, locked) = self.db_balance(i).await.unwrap_or_default();
                bail!(
                    "{}: {} collateral never reached {} (db total={}, locked={})",
                    what,
                    self.label(i),
                    self.fmt(expected),
                    self.fmt(total),
                    self.fmt(locked)
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn print_board(&self) {
        let board = self.board.lock().await;
        if board.cycles.is_empty() {
            return;
        }
        let mut lines =
            String::from("┌─ simulation board ─────────────────────────────────────────\n");
        for c in &board.cycles {
            let phase = match c.phase {
                Phase::Collecting => "COLLECTING",
                Phase::Netting => "NETTING",
                Phase::PaymentWindow => "PAY WINDOW",
                Phase::Settling => "SETTLING",
                Phase::Finalized => "FINALIZED",
            };
            let id_tail = &c.id[c.id.len().saturating_sub(12)..];
            lines.push_str(&format!(
                "│ cycle {} (…{id_tail}) [{phase:<10}] {} payments Σ {} | debtors {} (paid {}, defaulted {}) | creditors {} (wallet {}, pool {})\n",
                c.index,
                c.payments,
                self.fmt(c.gross),
                c.debtors,
                c.paid,
                c.defaulted,
                c.creditors,
                c.claimed_wallet,
                c.claimed_pool,
            ));
        }
        lines.push_str("└────────────────────────────────────────────────────────────");
        println!("{lines}");
    }

    async fn update_board(&self, cycle_index: usize, f: impl FnOnce(&mut BoardCycle)) {
        let mut board = self.board.lock().await;
        if let Some(c) = board.cycles.iter_mut().find(|c| c.index == cycle_index) {
            f(c);
        }
    }
}

// ---------------------------------------------------------------------------
// x402 payment gateway (the "resource server" every payee sells through)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct GatewayCfg {
    scheme: String,
    network: String,
    asset: String,
}

#[derive(serde::Deserialize)]
struct PayQuery {
    payee: String,
    amount: String,
}

fn build_gateway(cfg: GatewayCfg) -> Router {
    Router::new().route(
        "/pay",
        get(move |Query(q): Query<PayQuery>| {
            let cfg = cfg.clone();
            async move {
                let requirements = PaymentRequirements {
                    scheme: cfg.scheme.clone(),
                    network: cfg.network.clone(),
                    max_amount_required: q.amount.clone(),
                    resource: format!("sim://pay/{}", q.payee),
                    description: "cycle simulation payment".into(),
                    mime_type: None,
                    output_schema: None,
                    pay_to: q.payee.clone(),
                    max_timeout_seconds: 300,
                    asset: cfg.asset.clone(),
                    extra: None,
                };
                (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(ResourceResponse {
                        x402_version: 1,
                        accepts: vec![requirements],
                        error: "payment required".into(),
                    }),
                )
            }
        }),
    )
}

async fn spawn_gateway(cfg: GatewayCfg) -> anyhow::Result<(String, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = build_gateway(cfg);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });
    Ok((format!("http://{addr}"), handle))
}

async fn fetch_requirements(
    sim: &Sim,
    payee: Address,
    amount: U256,
) -> anyhow::Result<PaymentRequirements> {
    let url = format!("{}/pay?payee={payee:#x}&amount={amount}", sim.gateway_url);
    let response = sim.http.get(&url).send().await?;
    ensure!(
        response.status() == reqwest::StatusCode::PAYMENT_REQUIRED,
        "gateway returned {} instead of 402",
        response.status()
    );
    let body: ResourceResponse = response.json().await?;
    body.accepts
        .into_iter()
        .next()
        .context("gateway advertised no payment requirements")
}

/// One full x402 payment: 402 → payer signs → facilitator settles (issuing the
/// guarantee against core) → payee verifies the BLS cert → the payer's lock is
/// confirmed in core's DB, and the guarantee row is found in the expected cycle.
///
/// The caller has already reserved `amount` in the ledger; payments run
/// concurrently, so the DB lock assertion converges once every in-flight
/// payment for the payer has settled.
enum PayOutcome {
    Done(PaymentRecord),
    /// Core refused for lack of free collateral: the ledger learns about
    /// seizures a few seconds after core's DB does, so a payment planned in
    /// that window can lose the race. The reservation is already rolled back.
    Skipped {
        payer: usize,
        amount: U256,
    },
}

async fn x402_pay(
    sim: &Sim,
    cycle_index: usize,
    cycle_id: &str,
    payer: usize,
    payee: usize,
    amount: U256,
) -> anyhow::Result<PayOutcome> {
    let payer_p = &sim.participants[payer];
    let payee_p = &sim.participants[payee];

    let requirements = fetch_requirements(sim, payee_p.address, amount).await?;

    let flow = X402Flow::new(payer_p.client.clone())?;
    let signed = flow
        .sign_payment(requirements.clone(), format!("{:#x}", payer_p.address))
        .await?;
    let req_id = signed.payload.claims.req_id();

    // A settle whose response is lost may still have issued the guarantee, and
    // retrying it would double-issue — so on timeout consult the DB by req_id
    // before deciding: present means settled (skip the cert checks), absent is
    // a real failure.
    let settle = tokio::time::timeout(
        Duration::from_secs(60),
        flow.settle_payment(
            signed,
            X402Requirements::V1(requirements),
            &sim.facilitator_url,
        ),
    )
    .await;
    match settle {
        Ok(settled) => {
            let settled = settled?;
            if settled.settlement.get("success").and_then(|v| v.as_bool()) != Some(true) {
                let reason = settled
                    .settlement
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if reason.contains("Not enough free collateral") {
                    sim.ledger.lock().await.locked[payer] -= amount;
                    sim.reporter.log(
                        &format!("cycle {cycle_index}"),
                        &format!(
                            "{} → {}  {} USDC skipped — core reports no free collateral (seizure \
                             race)",
                            sim.label(payer),
                            sim.label(payee),
                            sim.fmt(amount),
                        ),
                    );
                    return Ok(PayOutcome::Skipped { payer, amount });
                }
                bail!("facilitator refused settlement: {}", settled.settlement);
            }
            let cert: BLSCert = serde_json::from_value(
                settled
                    .settlement
                    .get("certificate")
                    .cloned()
                    .context("settle response carried no certificate")?,
            )?;

            // The payee independently verifies the operator's BLS cert.
            let claims = payee_p.client.payment.verify_guarantee(&cert)?;
            ensure!(claims.amount == amount, "cert amount mismatch");
            ensure!(
                Address::from_str(&claims.user_address)? == payer_p.address,
                "cert payer mismatch"
            );
            ensure!(
                Address::from_str(&claims.recipient_address)? == payee_p.address,
                "cert payee mismatch"
            );
        }
        Err(_) => {
            let statuses = [GuaranteeSettlementStatus::FinalizedPayable];
            let issued = repo::list_guarantees_on(
                sim.db.db.as_ref(),
                repo::GuaranteeSelector::cycle(cycle_id, Some(payer_p.address), &statuses),
            )
            .await?
            .iter()
            .any(|g| g.req_id.0 == req_id);
            ensure!(issued, "x402 settle timed out and no guarantee was issued");
            sim.reporter.log(
                &format!("cycle {cycle_index}"),
                "settle response lost but the guarantee was issued — continuing without cert",
            );
        }
    }

    // The guarantee must sit in the cycle we planned it for; landing anywhere
    // else means the payment straddled a boundary and the ledger would drift.
    let statuses = [GuaranteeSettlementStatus::FinalizedPayable];
    let guarantees = repo::list_guarantees_on(
        sim.db.db.as_ref(),
        repo::GuaranteeSelector::cycle(cycle_id, Some(payer_p.address), &statuses),
    )
    .await?;
    let row = guarantees
        .iter()
        .find(|g| g.req_id.0 == req_id)
        .with_context(|| format!("guarantee for req_id {req_id} not found in cycle {cycle_id}"))?;
    ensure!(row.value == amount, "guarantee value mismatch");
    ensure!(row.payee == payee_p.address, "guarantee payee mismatch");

    // The guarantee row is core's lock receipt — it is written in the same
    // transaction that locks the payer's collateral. Exact ledger-vs-DB lock
    // equality is asserted at the audits instead: right here another cycle's
    // driver may lag booking a release core has already performed.
    let locked_now = sim.ledger.lock().await.locked[payer];
    sim.reporter.log(
        &format!("cycle {cycle_index}"),
        &format!(
            "{} → {}  {} USDC via x402 (guarantee ok, {} locked {}/{})",
            sim.label(payer),
            sim.label(payee),
            sim.fmt(amount),
            sim.label(payer),
            sim.fmt(locked_now),
            sim.fmt(sim.units(DEPOSIT_UNITS)),
        ),
    );

    Ok(PayOutcome::Done(PaymentRecord {
        payer,
        payee,
        amount,
    }))
}

// ---------------------------------------------------------------------------
// Cycle discovery
// ---------------------------------------------------------------------------

fn status_rank(status: &SettlementCycleStatus) -> u8 {
    match status {
        SettlementCycleStatus::Open => 0,
        SettlementCycleStatus::Frozen => 1,
        SettlementCycleStatus::NettingComputed => 2,
        SettlementCycleStatus::ClearingCommitted => 3,
        SettlementCycleStatus::PaymentWindowOpen => 3,
        SettlementCycleStatus::Settling => 4,
        SettlementCycleStatus::Finalized => 5,
        SettlementCycleStatus::Shortfall | SettlementCycleStatus::Cancelled => 6,
    }
}

const ALL_GUARANTEE_STATUSES: [GuaranteeSettlementStatus; 8] = [
    GuaranteeSettlementStatus::Issued,
    GuaranteeSettlementStatus::PendingValidation,
    GuaranteeSettlementStatus::FinalizedPayable,
    GuaranteeSettlementStatus::Disputed,
    GuaranteeSettlementStatus::Cancelled,
    GuaranteeSettlementStatus::Netted,
    GuaranteeSettlementStatus::Settled,
    GuaranteeSettlementStatus::DefaultRemunerated,
];

/// Propagate a settlement driver's failure the moment it lands instead of at
/// the end of the run; drivers that finished cleanly are dropped.
async fn reap_finished_drivers(
    drivers: &mut Vec<JoinHandle<anyhow::Result<()>>>,
) -> anyhow::Result<()> {
    let mut i = 0;
    while i < drivers.len() {
        if drivers[i].is_finished() {
            drivers.remove(i).await??;
        } else {
            i += 1;
        }
    }
    Ok(())
}

async fn wait_for_open_cycle(
    sim: &Sim,
    min_period_start: i64,
    required_remaining: i64,
    drivers: &mut Vec<JoinHandle<anyhow::Result<()>>>,
) -> anyhow::Result<entities::settlement_cycle::Model> {
    let deadline = Instant::now() + Duration::from_secs(2 * sim.cycle_secs + 120);
    let mut min_period_start = min_period_start;
    loop {
        reap_finished_drivers(drivers).await?;
        if let Some(row) = repo::get_open_cycle_by_asset_on(sim.db.db.as_ref(), sim.usdc).await? {
            let start = row.period_start.and_utc().timestamp();
            let end = row.period_end.and_utc().timestamp();
            if start >= min_period_start && end - now_unix() >= required_remaining {
                // An aborted earlier run can leave orphaned guarantees in the
                // current window (a settle that failed after core issued);
                // netting would then count strangers into our cycle. Take only
                // a window this run has to itself.
                let residue = repo::list_guarantees_on(
                    sim.db.db.as_ref(),
                    repo::GuaranteeSelector::cycle(&row.id, None, &ALL_GUARANTEE_STATUSES),
                )
                .await?;
                if residue.is_empty() {
                    return Ok(row);
                }
                sim.reporter.log(
                    "cycles",
                    &format!(
                        "window {} carries {} guarantee(s) from an earlier run — waiting for a \
                         clean one",
                        row.id,
                        residue.len()
                    ),
                );
                min_period_start = end;
            }
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for an open cycle starting at or after {min_period_start}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_cycle_rank(
    sim: &Sim,
    cycle_id: &str,
    min_rank: u8,
    timeout: Duration,
    what: &str,
) -> anyhow::Result<entities::settlement_cycle::Model> {
    let deadline = Instant::now() + timeout;
    loop {
        let row = repo::get_cycle_by_id_on(sim.db.db.as_ref(), cycle_id)
            .await?
            .with_context(|| format!("cycle {cycle_id} vanished"))?;
        if matches!(
            row.status,
            SettlementCycleStatus::Shortfall | SettlementCycleStatus::Cancelled
        ) && min_rank < 6
        {
            bail!(
                "cycle {cycle_id} reached {:?} while waiting for {what}",
                row.status
            );
        }
        if status_rank(&row.status) >= min_rank {
            return Ok(row);
        }
        if Instant::now() > deadline {
            bail!(
                "timed out waiting for {what} on cycle {cycle_id} (status {:?})",
                row.status
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// ---------------------------------------------------------------------------
// Settlement driver: walks one finished cycle to finalization while the next
// cycle is already collecting payments.
// ---------------------------------------------------------------------------

struct NetPosition {
    out: U256,
    inc: U256,
}

impl NetPosition {
    fn debit(&self) -> U256 {
        self.out.saturating_sub(self.inc)
    }
    fn credit(&self) -> U256 {
        self.inc.saturating_sub(self.out)
    }
}

async fn drive_settlement(sim: Arc<Sim>, plan: CyclePlan, seed: u64) -> anyhow::Result<()> {
    let scope = format!("cycle {}", plan.index);
    let log = |msg: &str| sim.reporter.log(&scope, msg);
    let mut rng = StdRng::seed_from_u64(seed);
    let stage_timeout = Duration::from_secs(sim.cycle_secs + STAGE_SLACK_SECS);

    let mut expected: BTreeMap<usize, NetPosition> = BTreeMap::new();
    for p in &plan.payments {
        expected
            .entry(p.payer)
            .or_insert(NetPosition {
                out: U256::ZERO,
                inc: U256::ZERO,
            })
            .out += p.amount;
        expected
            .entry(p.payee)
            .or_insert(NetPosition {
                out: U256::ZERO,
                inc: U256::ZERO,
            })
            .inc += p.amount;
    }
    let debtors: Vec<(usize, U256)> = expected
        .iter()
        .filter(|(_, pos)| pos.debit() > U256::ZERO)
        .map(|(&i, pos)| (i, pos.debit()))
        .collect();
    let creditors: Vec<(usize, U256)> = expected
        .iter()
        .filter(|(_, pos)| pos.credit() > U256::ZERO)
        .map(|(&i, pos)| (i, pos.credit()))
        .collect();
    let total_net_debit: U256 = debtors.iter().fold(U256::ZERO, |acc, (_, d)| acc + *d);

    sim.update_board(plan.index, |c| {
        c.phase = Phase::Netting;
        c.net = total_net_debit;
        c.debtors = debtors.len();
        c.creditors = creditors.len();
    })
    .await;
    log(&format!(
        "period over — waiting for netting ({} payments, Σ {} USDC gross)",
        plan.payments.len(),
        sim.fmt(plan.payments.iter().fold(U256::ZERO, |a, p| a + p.amount)),
    ));

    // --- netting -----------------------------------------------------------
    wait_for_cycle_rank(&sim, &plan.id, 2, stage_timeout, "netting").await?;
    verify_netting(&sim, &plan, &expected, total_net_debit).await?;
    log(&format!(
        "netted: {} net debtors (Σ {} USDC), {} net creditors — zero-sum verified",
        debtors.len(),
        sim.fmt(total_net_debit),
        creditors.len(),
    ));

    // A fully-offsetting (or empty) cycle short-circuits straight to FINALIZED
    // with no on-chain commit; all locks release at once.
    if total_net_debit == U256::ZERO {
        log("cycle nets to zero — expecting short-circuit finalization");
        wait_for_cycle_rank(
            &sim,
            &plan.id,
            5,
            stage_timeout,
            "short-circuit finalization",
        )
        .await?;
        release_flat_locks(&sim, &plan).await?;
        finalize_audit(&sim, &plan, &expected, &[], &[]).await?;
        sim.update_board(plan.index, |c| c.phase = Phase::Finalized)
            .await;
        log("✓ finalized (offsetting) — accounting verified");
        return Ok(());
    }

    // --- choose who pays and who defaults ----------------------------------
    let mut payers: Vec<(usize, U256)> = vec![];
    let mut defaulters: Vec<(usize, U256)> = vec![];
    for &(i, debit) in &debtors {
        if rng.random_bool(DEFAULT_PROBABILITY) {
            defaulters.push((i, debit));
        } else {
            payers.push((i, debit));
        }
    }
    // With two or more debtors, keep both behaviors represented; a lone
    // debtor keeps whatever the dice said.
    if debtors.len() >= 2 {
        if payers.is_empty() {
            payers.push(defaulters.pop().unwrap());
        }
        if defaulters.is_empty() {
            defaulters.push(payers.pop().unwrap());
        }
    }
    log(&format!(
        "settlement plan: pay [{}], default [{}]",
        payers
            .iter()
            .map(|(i, d)| format!("{} ({})", sim.label(*i), sim.fmt(*d)))
            .collect::<Vec<_>>()
            .join(", "),
        defaulters
            .iter()
            .map(|(i, d)| format!("{} ({})", sim.label(*i), sim.fmt(*d)))
            .collect::<Vec<_>>()
            .join(", "),
    ));

    // --- payment window -----------------------------------------------------
    wait_for_cycle_rank(&sim, &plan.id, 3, stage_timeout, "payment window").await?;
    sim.update_board(plan.index, |c| c.phase = Phase::PaymentWindow)
        .await;
    log("payment window open");

    // A payer whose transaction cannot get through in time is not a test
    // failure — it is an involuntary default, which the protocol covers by
    // seizure. Only failures after money moved stay fatal.
    let mut paid: Vec<(usize, U256)> = vec![];
    for &(i, debit) in &payers {
        // A wedged predecessor can eat the whole submission window; once it
        // has passed (or the cycle moved on), attempting to pay only burns
        // retries — the seizure path covers this payer from here.
        let window_open = repo::get_cycle_by_id_on(sim.db.db.as_ref(), &plan.id)
            .await?
            .map(|r| {
                r.status == SettlementCycleStatus::PaymentWindowOpen
                    && now_unix() <= r.payment_submission_deadline.and_utc().timestamp()
            })
            .unwrap_or(false);
        if !window_open {
            log(&format!(
                "{} missed the submission window — leaving them to be seized as a defaulter",
                sim.label(i)
            ));
            defaulters.push((i, debit));
            continue;
        }
        let participant = &sim.participants[i];
        let prepared: anyhow::Result<()> = async {
            let action = retrying("pay action", 3, || async {
                Ok(participant
                    .client
                    .settlement
                    .pay(plan.id.clone())
                    .action()
                    .await?)
            })
            .await?;
            ensure!(
                action.function_name == "payNetDebit",
                "unexpected pay action"
            );
            let action_amount = U256::from_str(&action.amount)?;
            ensure!(
                action_amount == debit,
                "net debit mismatch for {}",
                sim.label(i)
            );

            // The pinned builder resolves token, ClearingHouse and the exact
            // committed debit itself; approve() is non-consuming and harmless
            // to repeat, so it retries.
            let pay = participant
                .client
                .settlement
                .pay(plan.id.clone())
                .self_funded();
            retrying("pay approve", 3, || async { Ok(pay.approve().await?) }).await?;
            Ok(())
        }
        .await;
        if let Err(err) = prepared {
            log(&format!(
                "{} could not prepare their payment ({err:#}) — leaving them to be seized as a \
                 defaulter",
                sim.label(i)
            ));
            defaulters.push((i, debit));
            continue;
        }

        let receipt = retrying("pay net debit", 1, || async {
            Ok(participant
                .client
                .settlement
                .pay(plan.id.clone())
                .self_funded()
                .send()
                .await?)
        })
        .await;
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(err) => {
                // The transaction may or may not have landed; the position is
                // the truth. Paid → carry on as a payer; otherwise let the
                // seizure cover them.
                log(&format!(
                    "{} pay submission failed ({err:#}) — checking whether it landed anyway",
                    sim.label(i)
                ));
                sim.mine(2).await;
                let landed = tokio::time::timeout(
                    Duration::from_secs(60),
                    wait_for_position(&sim, &plan.id, i, ParticipantCycleStatus::Paid, "pay probe"),
                )
                .await;
                if matches!(landed, Ok(Ok(()))) {
                    sim.ledger.lock().await.wallet[i] -= debit;
                } else {
                    log(&format!(
                        "{} payment never landed — leaving them to be seized as a defaulter",
                        sim.label(i)
                    ));
                    defaulters.push((i, debit));
                    continue;
                }
                finish_voluntary_pay(&sim, &plan, i).await?;
                paid.push((i, debit));
                continue;
            }
        };
        sim.ledger.lock().await.wallet[i] -= debit;
        log(&format!(
            "{} paid net debit {} USDC from wallet (tx {})",
            sim.label(i),
            sim.fmt(debit),
            receipt.tx_hash
        ));
        sim.mine(2).await;

        wait_for_position(
            &sim,
            &plan.id,
            i,
            ParticipantCycleStatus::Paid,
            "voluntary pay",
        )
        .await?;
        finish_voluntary_pay(&sim, &plan, i).await?;
        paid.push((i, debit));
    }
    let payers = paid;

    // --- defaults: core seizes from collateral after the finality deadline --
    if !defaulters.is_empty() {
        sim.update_board(plan.index, |c| c.phase = Phase::Settling)
            .await;
        log(&format!(
            "waiting for finality deadline — {} defaulter(s) to be seized",
            defaulters.len()
        ));
        for &(i, debit) in &defaulters {
            wait_for_position(
                &sim,
                &plan.id,
                i,
                ParticipantCycleStatus::Defaulted,
                "default",
            )
            .await?;
            wait_for_payer_guarantees(
                &sim,
                &plan,
                i,
                GuaranteeSettlementStatus::DefaultRemunerated,
                "default sweep",
            )
            .await?;
            {
                let mut ledger = sim.ledger.lock().await;
                ledger.locked[i] -= plan.gross_out(i);
                ledger.collateral[i] -= debit;
            }
            sim.wait_locked_matches(i, "post-default lock release")
                .await?;
            sim.wait_collateral_matches(i, "collateral seizure").await?;
            sim.update_board(plan.index, |c| c.defaulted += 1).await;
            log(&format!(
                "{} DEFAULTED — {} USDC seized from collateral",
                sim.label(i),
                sim.fmt(debit)
            ));
        }
    }

    // --- creditors get paid --------------------------------------------------
    // Only once every debit is resolved does the ClearingHouse release credit.
    // A creditor either claims (payout to wallet) or, after defaults, the
    // operator's pool funding may land first (payout into collateral).
    for &(i, credit) in &creditors {
        let participant = &sim.participants[i];
        let claim = retrying("claim net credit", 1, || async {
            Ok(participant
                .client
                .settlement
                .claim(plan.id.clone())
                .self_funded()
                .send()
                .await?)
        })
        .await;
        let via_wallet = match claim {
            Ok(receipt) => {
                sim.ledger.lock().await.wallet[i] += credit;
                log(&format!(
                    "{} claimed net credit {} USDC to wallet (tx {})",
                    sim.label(i),
                    sim.fmt(credit),
                    receipt.tx_hash
                ));
                true
            }
            Err(err) => {
                // The pool-funding batch may have beaten us to it; the position
                // flipping to CLAIMED is the proof. Anything else is a failure.
                let outcome = wait_for_position(
                    &sim,
                    &plan.id,
                    i,
                    ParticipantCycleStatus::Claimed,
                    "pool funding after failed claim",
                )
                .await;
                if outcome.is_err() {
                    bail!(
                        "claim for {} failed ({err:#}) and pool funding never arrived",
                        sim.label(i)
                    );
                }
                sim.ledger.lock().await.collateral[i] += credit;
                log(&format!(
                    "{} credited {} USDC from settlement pool into collateral",
                    sim.label(i),
                    sim.fmt(credit)
                ));
                false
            }
        };
        sim.mine(2).await;
        wait_for_position(
            &sim,
            &plan.id,
            i,
            ParticipantCycleStatus::Claimed,
            "credit claim",
        )
        .await?;
        if via_wallet {
            sim.update_board(plan.index, |c| c.claimed_wallet += 1)
                .await;
        } else {
            sim.update_board(plan.index, |c| c.claimed_pool += 1).await;
            sim.wait_collateral_matches(i, "pool credit").await?;
        }
        // Claiming sweeps the creditor's own outgoing guarantees.
        if plan.gross_out(i) > U256::ZERO {
            wait_for_payer_guarantees(
                &sim,
                &plan,
                i,
                GuaranteeSettlementStatus::Settled,
                "creditor sweep",
            )
            .await?;
            sim.ledger.lock().await.locked[i] -= plan.gross_out(i);
            sim.wait_locked_matches(i, "post-claim lock release")
                .await?;
        }
    }

    // --- finalization + audit ------------------------------------------------
    wait_for_cycle_rank(&sim, &plan.id, 5, stage_timeout, "finalization").await?;
    release_flat_locks(&sim, &plan).await?;
    finalize_audit(&sim, &plan, &expected, &payers, &defaulters).await?;
    sim.update_board(plan.index, |c| c.phase = Phase::Finalized)
        .await;
    log(&format!(
        "✓ FINALIZED — accounting verified (Σ debits == Σ credits == {} USDC, all locks released)",
        sim.fmt(total_net_debit)
    ));
    Ok(())
}

/// Payers, defaulters, and creditors release their locks when their own leg
/// settles; flat participants (gross out == gross in) release only at the
/// finalization sweep. Wait for every guarantee to go terminal, then book the
/// flat releases.
async fn release_flat_locks(sim: &Sim, plan: &CyclePlan) -> anyhow::Result<()> {
    let terminal = [
        GuaranteeSettlementStatus::Settled,
        GuaranteeSettlementStatus::DefaultRemunerated,
    ];
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let rows = repo::list_guarantees_on(
            sim.db.db.as_ref(),
            repo::GuaranteeSelector::cycle(&plan.id, None, &terminal),
        )
        .await?;
        if rows.len() == plan.payments.len() {
            break;
        }
        if Instant::now() > deadline {
            bail!(
                "cycle {}: only {}/{} guarantees reached a terminal status",
                plan.id,
                rows.len(),
                plan.payments.len()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    for i in 0..sim.participants.len() {
        let out = plan.gross_out(i);
        if out == U256::ZERO || out != plan.gross_in(i) {
            continue;
        }
        sim.ledger.lock().await.locked[i] -= out;
        sim.wait_locked_matches(i, "finalization sweep").await?;
    }
    Ok(())
}

async fn verify_netting(
    sim: &Sim,
    plan: &CyclePlan,
    expected: &BTreeMap<usize, NetPosition>,
    total_net_debit: U256,
) -> anyhow::Result<()> {
    let db = sim.db.db.as_ref();

    let positions = repo::list_participant_positions_for_cycle_on(db, &plan.id).await?;
    ensure!(
        positions.len() == expected.len(),
        "cycle {}: {} positions in DB, {} participants active in the ledger",
        plan.id,
        positions.len(),
        expected.len()
    );
    for (&i, exp) in expected {
        let address = sim.participants[i].address;
        let position = positions
            .iter()
            .find(|p| p.participant == address)
            .with_context(|| format!("no position for {}", sim.label(i)))?;
        ensure!(
            position.gross_outgoing == exp.out,
            "{} gross out mismatch",
            sim.label(i)
        );
        ensure!(
            position.gross_incoming == exp.inc,
            "{} gross in mismatch",
            sim.label(i)
        );
        ensure!(
            position.net_debit == exp.debit(),
            "{} net debit mismatch",
            sim.label(i)
        );
        ensure!(
            position.net_credit == exp.credit(),
            "{} net credit mismatch",
            sim.label(i)
        );
        let expected_role = if exp.debit() > U256::ZERO {
            ParticipantCycleRole::NetDebtor
        } else if exp.credit() > U256::ZERO {
            ParticipantCycleRole::NetCreditor
        } else {
            ParticipantCycleRole::Flat
        };
        ensure!(
            position.role == expected_role,
            "{} role mismatch",
            sim.label(i)
        );
    }

    // Exposure edges must aggregate the raw payments exactly.
    let mut expected_edges: BTreeMap<(usize, usize), (U256, i64)> = BTreeMap::new();
    for p in &plan.payments {
        let e = expected_edges
            .entry((p.payer, p.payee))
            .or_insert((U256::ZERO, 0));
        e.0 += p.amount;
        e.1 += 1;
    }
    let edges = repo::list_exposure_edges_for_cycle_on(db, &plan.id).await?;
    ensure!(
        edges.len() == expected_edges.len(),
        "cycle {}: edge count mismatch",
        plan.id
    );
    for edge in &edges {
        let payer = sim.index_of(edge.payer).context("edge payer unknown")?;
        let payee = sim.index_of(edge.payee).context("edge payee unknown")?;
        let (amount, count) = expected_edges.get(&(payer, payee)).with_context(|| {
            format!(
                "unexpected edge {} → {}",
                sim.label(payer),
                sim.label(payee)
            )
        })?;
        ensure!(edge.gross_amount == *amount, "edge amount mismatch");
        ensure!(edge.guarantee_count == *count, "edge count mismatch");
    }

    // The committed batch must be zero-sum and match our totals.
    if total_net_debit > U256::ZERO {
        let batch = repo::get_clearing_batch_by_cycle_on(db, &plan.id)
            .await?
            .context("no clearing batch for a non-zero cycle")?;
        ensure!(
            batch.total_net_debit == total_net_debit,
            "batch debit total mismatch"
        );
        ensure!(
            batch.total_net_credit == total_net_debit,
            "batch credit total mismatch"
        );
    }
    Ok(())
}

/// The tail every successful voluntary pay shares: the guarantee sweep, the
/// collateral-lock release, and the bookkeeping.
async fn finish_voluntary_pay(sim: &Sim, plan: &CyclePlan, i: usize) -> anyhow::Result<()> {
    wait_for_payer_guarantees(
        sim,
        plan,
        i,
        GuaranteeSettlementStatus::Settled,
        "voluntary pay sweep",
    )
    .await?;
    sim.ledger.lock().await.locked[i] -= plan.gross_out(i);
    sim.wait_locked_matches(i, "post-pay lock release").await?;
    sim.update_board(plan.index, |c| c.paid += 1).await;
    sim.reporter.log(
        &format!("cycle {}", plan.index),
        &format!(
            "{} debt settled — guarantees swept, collateral lock released",
            sim.label(i)
        ),
    );
    Ok(())
}

async fn wait_for_position(
    sim: &Sim,
    cycle_id: &str,
    participant: usize,
    want: ParticipantCycleStatus,
    what: &str,
) -> anyhow::Result<()> {
    let address = sim.participants[participant].address;
    let deadline = Instant::now() + Duration::from_secs(sim.cycle_secs + STAGE_SLACK_SECS);
    loop {
        let positions =
            repo::list_participant_positions_for_cycle_on(sim.db.db.as_ref(), cycle_id).await?;
        if let Some(p) = positions.iter().find(|p| p.participant == address)
            && p.status == want
        {
            return Ok(());
        }
        if Instant::now() > deadline {
            let status = positions
                .iter()
                .find(|p| p.participant == address)
                .map(|p| format!("{:?}", p.status));
            bail!(
                "{what}: {} never reached {:?} in cycle {cycle_id} (status {:?})",
                sim.label(participant),
                want,
                status
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn wait_for_payer_guarantees(
    sim: &Sim,
    plan: &CyclePlan,
    payer: usize,
    want: GuaranteeSettlementStatus,
    what: &str,
) -> anyhow::Result<()> {
    let address = sim.participants[payer].address;
    let expected_count = plan.payments.iter().filter(|p| p.payer == payer).count();
    let statuses = [want.clone()];
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let rows = repo::list_guarantees_on(
            sim.db.db.as_ref(),
            repo::GuaranteeSelector::cycle(&plan.id, Some(address), &statuses),
        )
        .await?;
        if rows.len() == expected_count {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "{what}: {}/{} of {}'s guarantees reached {:?} in cycle {}",
                rows.len(),
                expected_count,
                sim.label(payer),
                want,
                plan.id
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn finalize_audit(
    sim: &Sim,
    plan: &CyclePlan,
    expected: &BTreeMap<usize, NetPosition>,
    payers: &[(usize, U256)],
    defaulters: &[(usize, U256)],
) -> anyhow::Result<()> {
    let db = sim.db.db.as_ref();

    let row = repo::get_cycle_by_id_on(db, &plan.id)
        .await?
        .context("finalized cycle vanished")?;
    ensure!(
        row.status == SettlementCycleStatus::Finalized,
        "cycle not finalized"
    );

    // Every guarantee terminal, and terminal the *right* way.
    let all_statuses = [
        GuaranteeSettlementStatus::Settled,
        GuaranteeSettlementStatus::DefaultRemunerated,
    ];
    let rows = repo::list_guarantees_on(
        db,
        repo::GuaranteeSelector::cycle(&plan.id, None, &all_statuses),
    )
    .await?;
    ensure!(
        rows.len() == plan.payments.len(),
        "not all guarantees terminal at finalization"
    );
    let defaulter_set: Vec<Address> = defaulters
        .iter()
        .map(|(i, _)| sim.participants[*i].address)
        .collect();
    for g in &rows {
        let want = if defaulter_set.contains(&g.payer) {
            GuaranteeSettlementStatus::DefaultRemunerated
        } else {
            GuaranteeSettlementStatus::Settled
        };
        ensure!(
            g.settlement_status == want,
            "guarantee {} ended {:?}, expected {:?}",
            g.guarantee_id,
            g.settlement_status,
            want
        );
    }

    // Every position terminal.
    let positions = repo::list_participant_positions_for_cycle_on(db, &plan.id).await?;
    for (&i, exp) in expected {
        let address = sim.participants[i].address;
        let position = positions
            .iter()
            .find(|p| p.participant == address)
            .with_context(|| format!("no final position for {}", sim.label(i)))?;
        let want = if defaulters.iter().any(|(d, _)| *d == i) {
            ParticipantCycleStatus::Defaulted
        } else if payers.iter().any(|(p, _)| *p == i) {
            ParticipantCycleStatus::Paid
        } else if exp.credit() > U256::ZERO {
            ParticipantCycleStatus::Claimed
        } else {
            ParticipantCycleStatus::Finalized
        };
        ensure!(
            position.status == want,
            "{} position ended {:?}, expected {:?}",
            sim.label(i),
            position.status,
            want
        );
    }

    // Balances line up with the ledger for everyone who took part.
    for &i in expected.keys() {
        sim.wait_locked_matches(i, "final audit").await?;
        sim.wait_collateral_matches(i, "final audit").await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_multi_cycle_clearing_simulation() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }
    let Some(facilitator_url) = std::env::var("E2E_FACILITATOR_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
    else {
        eprintln!(
            "[cycle-sim] skipped: set E2E_FACILITATOR_URL to a running facilitator \
             (see the facilitator-4mica repo) — the x402 legs settle through it"
        );
        return Ok(());
    };

    let n_cycles = env_u64("SIM_CYCLES", 5) as usize;
    let n_participants = env_u64("SIM_PARTICIPANTS", 10) as usize;
    // 0 (the default) fills the window continuously: payments never stop while
    // a cycle is open, throttling only when capacity is exhausted and resuming
    // as older cycles settle and release it.
    let payments_per_cycle = env_u64("SIM_PAYMENTS_PER_CYCLE", 0) as usize;
    let concurrency = (env_u64("SIM_CONCURRENCY", 4) as usize).max(1);
    let batch_gap_secs = env_u64("SIM_PAYMENT_GAP_SECS", 2);
    let seed = env_u64("SIM_SEED", common::get_now().as_nanos() as u64);
    let mut rng = StdRng::seed_from_u64(seed);
    println!("[cycle-sim] seed {seed} — rerun with SIM_SEED={seed} to reproduce");

    // --- discover the stack -------------------------------------------------
    dotenv::dotenv().ok();
    let db = PersistCtx::new()
        .await
        .context("connect to core database")?;

    // The facilitator issues guarantees for arbitrary recipients, which core
    // only allows for the `facilitator` role. Grant it to the facilitator's
    // auth wallet (the facilitator-4mica repo's checked-in .env uses anvil #0;
    // override with SIM_FACILITATOR_WALLET). Tokens carry role and scopes from
    // issuance but refresh re-reads them from the DB, so an already-running
    // facilitator converges within one access-token TTL.
    let facilitator_wallet = std::env::var("SIM_FACILITATOR_WALLET")
        .unwrap_or_else(|_| "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string());
    repo::upsert_wallet_role(
        &db,
        facilitator_wallet.parse()?,
        "facilitator",
        &["guarantee:issue".to_string(), "payment:read".to_string()],
        "active",
    )
    .await
    .context("grant the facilitator role")?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let supported: serde_json::Value = http
        .get(format!("{facilitator_url}/supported"))
        .send()
        .await
        .context("facilitator /supported unreachable — is it running?")?
        .json()
        .await?;
    let kind = supported["kinds"]
        .get(0)
        .context("facilitator advertises no payment kinds")?;
    let scheme = kind["scheme"]
        .as_str()
        .context("kind without scheme")?
        .to_string();
    let network = kind["network"]
        .as_str()
        .context("kind without network")?
        .to_string();
    println!("[cycle-sim] facilitator {facilitator_url} speaks {scheme} on {network}");

    // --- participants -------------------------------------------------------
    // Fresh random keys: no other suite's balances to race, and none of the
    // publicly-known anvil keys (which may carry 7702 delegations on forks).
    //
    // SIWE credentials, not a pinned bearer token: core's access tokens live
    // AUTH_ACCESS_TTL_SECS (default 900s) and this test runs far longer, so
    // the clients must be able to refresh mid-run. The SDK's auth session
    // handles login and proactive refresh; only the role row is seeded here.
    println!("[cycle-sim] creating {n_participants} participants…");
    let mut participants = Vec::with_capacity(n_participants);
    for i in 0..n_participants {
        let signer = PrivateKeySigner::random();
        let address = signer.address();
        repo::upsert_wallet_role(
            &db,
            address,
            "user",
            &["payment:read".to_string()],
            "active",
        )
        .await?;
        let config = sdk_4mica::ClientBuilder::default()
            .rpc_url(common::LOCAL_CORE_URL.to_string())
            .signer(signer)
            .credentials(sdk_4mica::Credentials::Siwe)
            .build()?;
        let client = Client::connect(config.clone()).await?;
        participants.push(Participant {
            label: format!("P{i}"),
            address,
            client,
            config,
        });
    }
    let rpc_url = eth_rpc_url(&participants[0].config).await?;

    // A ClearingHouse with no bytecode swallows every settlement call without
    // a trace: commits "succeed" with no logs, the scanner mirrors nothing,
    // and cycles hang unconfirmed forever. On a forked stack this happens
    // whenever anvil restarts — the locally deployed contract vanishes while
    // the forked Core4Mica survives. Fail in seconds, not after a full run.
    let clearing_house: Address = std::env::var("ETHEREUM_CLEARING_HOUSE_ADDRESS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|a: &Address| *a != Address::ZERO)
        .context("ETHEREUM_CLEARING_HOUSE_ADDRESS unset or zero — cycles cannot commit")?;
    let code: serde_json::Value = http
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
            "params": [format!("{clearing_house:#x}"), "latest"]
        }))
        .send()
        .await?
        .json()
        .await?;
    ensure!(
        code["result"].as_str().is_some_and(|c| c.len() > 2),
        "no ClearingHouse bytecode at {clearing_house:#x} on the current chain — redeploy the \
         stack (for the Base Sepolia fork: `source .dev/base-sepolia.env && make dev-up`) and \
         restart core-service"
    );

    let tokens = participants[0].client.tokens.supported().await?;
    let usdc_info = tokens
        .tokens
        .first()
        .context("core advertises no ERC-20 tokens")?;
    let usdc: Address = usdc_info.address.parse()?;
    let decimals = u32::from(usdc_info.decimals);
    println!(
        "[cycle-sim] settling in {} ({usdc:#x}, {decimals} decimals)",
        usdc_info.symbol
    );

    // Cycle length comes from the running core's actual windows, not from env
    // guesses: read it off the current open cycle.
    let probe = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(row) = repo::get_open_cycle_by_asset_on(db.db.as_ref(), usdc).await? {
                break row;
            }
            if Instant::now() > deadline {
                bail!("no open settlement cycle for {usdc:#x}; is core-service running?");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    let cycle_secs =
        (probe.period_end.and_utc().timestamp() - probe.period_start.and_utc().timestamp()) as u64;
    if cycle_secs < 60 {
        eprintln!(
            "[cycle-sim] skipped: cycles are {cycle_secs}s — too short for a multi-party \
             simulation. Redeploy the stack with SETTLEMENT_CYCLE_SECS >= 60 (see this file's \
             header for a 10-minute configuration)."
        );
        return Ok(());
    }
    let boundary_margin = (cycle_secs / 20).max(20) as i64;
    println!("[cycle-sim] cycle length {cycle_secs}s, boundary margin {boundary_margin}s");

    let (gateway_url, _gateway) = spawn_gateway(GatewayCfg {
        scheme,
        network,
        asset: format!("{usdc:#x}"),
    })
    .await?;

    // --- funding + deposits -------------------------------------------------
    let sim = Arc::new(Sim {
        db,
        usdc,
        decimals,
        rpc_url: rpc_url.clone(),
        facilitator_url,
        gateway_url,
        http,
        ledger: Mutex::new(Ledger {
            locked: vec![U256::ZERO; n_participants],
            collateral: vec![U256::ZERO; n_participants],
            wallet: vec![U256::ZERO; n_participants],
        }),
        board: Mutex::new(Board { cycles: vec![] }),
        reporter: Reporter {
            start: Instant::now(),
        },
        cycle_secs,
        participants,
    });

    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    let deposit = sim.units(DEPOSIT_UNITS);
    let reserve = sim.units(WALLET_RESERVE_UNITS);
    for i in 0..n_participants {
        let address = sim.participants[i].address;
        provider
            .anvil_set_balance(address, U256::from(10u64).pow(U256::from(19)))
            .await?;
        // Wallet reserve for paying net debits later; the deposit itself is
        // minted inside deposit_collateral_and_await.
        common::fund_user_with_erc20(&rpc_url, usdc, address, reserve).await?;
        repo::ensure_user_exists_on(sim.db.db.as_ref(), address).await?;

        deposit_collateral_and_await(
            &sim.participants[i].client,
            &sim.participants[i].config,
            Some(format!("{usdc:#x}")),
            deposit,
        )
        .await?;

        let (total, locked) = sim.db_balance(i).await?;
        ensure!(
            total == deposit,
            "{}: DB total {} after deposit",
            sim.label(i),
            sim.fmt(total)
        );
        ensure!(
            locked == U256::ZERO,
            "{}: fresh deposit already locked",
            sim.label(i)
        );
        {
            let mut ledger = sim.ledger.lock().await;
            ledger.collateral[i] = deposit;
            ledger.wallet[i] = reserve;
        }
        sim.reporter.log(
            "setup",
            &format!(
                "{} {address:#x} deposited {} USDC (DB verified: total {}, locked 0)",
                sim.label(i),
                sim.fmt(deposit),
                sim.fmt(total)
            ),
        );
    }

    // --- periodic board -----------------------------------------------------
    let done = Arc::new(AtomicBool::new(false));
    let board_task = {
        let sim = sim.clone();
        let done = done.clone();
        tokio::spawn(async move {
            while !done.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                sim.print_board().await;
            }
        })
    };
    // One steady block producer instead of every poll loop mining its own:
    // keeps the scanner's depth-1 confirmations flowing without hammering
    // anvil from half a dozen concurrent loops.
    let miner_task = {
        let sim = sim.clone();
        let done = done.clone();
        tokio::spawn(async move {
            while !done.load(Ordering::Relaxed) {
                sim.mine(1).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
    };

    // --- run the cycles -----------------------------------------------------
    let out_cap = sim.units(PER_CYCLE_OUT_CAP_UNITS);
    let cent = sim.unit() / U256::from(100);
    let payments_cap = if payments_per_cycle == 0 {
        usize::MAX
    } else {
        payments_per_cycle
    };
    let mut drivers: Vec<JoinHandle<anyhow::Result<()>>> = vec![];
    let mut min_period_start = 0i64;

    for k in 1..=n_cycles {
        let required_remaining = if k == 1 {
            // Don't start mid-window with too little room; wait for a fresh one.
            (cycle_secs as i64 * 2) / 5
        } else {
            boundary_margin
        };
        sim.reporter.log(
            &format!("cycle {k}"),
            &format!(
                "waiting for a cycle window with ≥{required_remaining}s left (cycles align to \
                 {cycle_secs}s wall-clock boundaries)"
            ),
        );
        let row =
            wait_for_open_cycle(&sim, min_period_start, required_remaining, &mut drivers).await?;
        let period_end = row.period_end.and_utc().timestamp();
        min_period_start = period_end;
        let mut plan = CyclePlan {
            index: k,
            id: row.id.clone(),
            period_end,
            payments: vec![],
        };
        sim.board.lock().await.cycles.push(BoardCycle {
            index: k,
            id: row.id.clone(),
            phase: Phase::Collecting,
            payments: 0,
            gross: U256::ZERO,
            net: U256::ZERO,
            debtors: 0,
            creditors: 0,
            paid: 0,
            defaulted: 0,
            claimed_wallet: 0,
            claimed_pool: 0,
        });
        sim.reporter.log(
            &format!("cycle {k}"),
            &format!(
                "OPEN ({}) — collecting x402 payments continuously until {}s before close",
                row.id, boundary_margin
            ),
        );

        let mut cycle_out = vec![U256::ZERO; n_participants];
        let mut last_throttle_log: Option<Instant> = None;
        while plan.payments.len() < payments_cap {
            reap_finished_drivers(&mut drivers).await?;
            let remaining = plan.period_end - now_unix() - boundary_margin;
            if remaining <= 0 {
                break;
            }

            // Assemble a batch of random payments, reserving capacity in the
            // ledger up front so concurrent payments (same payer included)
            // can never oversubscribe collateral or the per-cycle cap.
            let batch_target = concurrency.min(payments_cap - plan.payments.len());
            let mut batch = Vec::with_capacity(batch_target);
            {
                let mut ledger = sim.ledger.lock().await;
                for _ in 0..batch_target {
                    for _ in 0..20 {
                        let payer = rng.random_range(0..n_participants);
                        let payee = rng.random_range(0..n_participants);
                        if payer == payee {
                            continue;
                        }
                        let amount =
                            U256::from(rng.random_range(MIN_PAYMENT_CENTS..=MAX_PAYMENT_CENTS))
                                * cent;
                        // Cap by the payer's *current* collateral, not the
                        // initial deposit: seizures shrink it and pool credits
                        // grow it across cycles.
                        if ledger.locked[payer] + amount > ledger.collateral[payer]
                            || cycle_out[payer] + amount > out_cap
                        {
                            continue;
                        }
                        ledger.locked[payer] += amount;
                        cycle_out[payer] += amount;
                        batch.push((payer, payee, amount));
                        break;
                    }
                }
            }
            if batch.is_empty() {
                // Capacity is exhausted until an older cycle settles and
                // releases locks — keep the book open and resume then.
                if last_throttle_log.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
                    sim.reporter.log(
                        &format!("cycle {k}"),
                        "capacity exhausted — payments resume when older cycles release locks",
                    );
                    last_throttle_log = Some(Instant::now());
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            // Fire the whole batch concurrently — same-payer collisions are
            // deliberate: they exercise core's optimistic balance locking and
            // concurrent guarantee inserts into one cycle.
            let mut inflight = tokio::task::JoinSet::new();
            for (payer, payee, amount) in batch {
                let sim = sim.clone();
                let cycle_id = plan.id.clone();
                inflight
                    .spawn(async move { x402_pay(&sim, k, &cycle_id, payer, payee, amount).await });
            }
            while let Some(joined) = inflight.join_next().await {
                match joined?? {
                    PayOutcome::Done(record) => {
                        let amount = record.amount;
                        plan.payments.push(record);
                        sim.update_board(k, |c| {
                            c.payments += 1;
                            c.gross += amount;
                        })
                        .await;
                    }
                    PayOutcome::Skipped { payer, amount } => {
                        cycle_out[payer] -= amount;
                    }
                }
            }

            if plan.payments.len() < payments_cap {
                tokio::time::sleep(Duration::from_secs(batch_gap_secs)).await;
            }
        }

        sim.reporter.log(
            &format!("cycle {k}"),
            &format!(
                "book closed: {} payments, Σ {} USDC — settlement continues alongside cycle {}",
                plan.payments.len(),
                sim.fmt(plan.payments.iter().fold(U256::ZERO, |a, p| a + p.amount)),
                k + 1
            ),
        );

        // Settle this cycle in the background while the next one collects.
        let driver_sim = sim.clone();
        drivers.push(tokio::spawn(async move {
            drive_settlement(driver_sim, plan, seed.wrapping_add(k as u64)).await
        }));
    }

    for driver in drivers {
        driver.await??;
    }
    done.store(true, Ordering::Relaxed);
    board_task.abort();
    miner_task.abort();
    sim.print_board().await;

    // --- final audit across all cycles --------------------------------------
    let ledger = sim.ledger.lock().await;
    let mut participant_rows = Vec::with_capacity(n_participants);
    for i in 0..n_participants {
        assert_eq!(
            ledger.locked[i],
            U256::ZERO,
            "{} still has expected locks after all cycles settled",
            sim.label(i)
        );
        let (total, locked) = sim.db_balance(i).await?;
        assert_eq!(
            locked,
            U256::ZERO,
            "{} DB locked non-zero at the end",
            sim.label(i)
        );
        assert_eq!(
            total,
            ledger.collateral[i],
            "{} final collateral diverges from the ledger",
            sim.label(i)
        );
        let wallet = OwnedERC20::new(usdc, &provider)
            .balanceOf(sim.participants[i].address)
            .call()
            .await?;
        assert_eq!(
            wallet,
            ledger.wallet[i],
            "{} final wallet balance diverges from the ledger",
            sim.label(i)
        );
        participant_rows.push((i, total, wallet));
    }
    drop(ledger);

    // --- summary -------------------------------------------------------------
    let funded = sim.units(DEPOSIT_UNITS + WALLET_RESERVE_UNITS);
    let cents = |v: U256| (v * U256::from(100) / sim.unit()).to::<i128>();
    let mut lines = String::from("\n══════════════ simulation summary ══════════════\n");
    lines.push_str(&format!(
        "{:<7} {:>9} {:>12} {:>12} {:>14} {:>16}  {}\n",
        "cycle", "payments", "gross USDC", "net USDC", "debtors p/d", "creditors w/p", "outcome"
    ));
    let board = sim.board.lock().await;
    let (mut t_pay, mut t_gross, mut t_net) = (0usize, U256::ZERO, U256::ZERO);
    let (mut t_paid, mut t_def, mut t_wal, mut t_pool) = (0usize, 0usize, 0usize, 0usize);
    for c in &board.cycles {
        lines.push_str(&format!(
            "{:<7} {:>9} {:>12} {:>12} {:>14} {:>16}  {:?} ✓\n",
            c.index,
            c.payments,
            sim.fmt(c.gross),
            sim.fmt(c.net),
            format!("{}/{}", c.paid, c.defaulted),
            format!("{}/{}", c.claimed_wallet, c.claimed_pool),
            c.phase,
        ));
        t_pay += c.payments;
        t_gross += c.gross;
        t_net += c.net;
        t_paid += c.paid;
        t_def += c.defaulted;
        t_wal += c.claimed_wallet;
        t_pool += c.claimed_pool;
    }
    drop(board);
    lines.push_str(&format!(
        "{:<7} {:>9} {:>12} {:>12} {:>14} {:>16}\n",
        "total",
        t_pay,
        sim.fmt(t_gross),
        sim.fmt(t_net),
        format!("{t_paid}/{t_def}"),
        format!("{t_wal}/{t_pool}"),
    ));

    lines.push_str(&format!(
        "\n{:<4} {:<44} {:>12} {:>12} {:>10}\n",
        "", "participant", "collateral", "wallet", "Δ USDC"
    ));
    let mut sum_delta: i128 = 0;
    for (i, total, wallet) in &participant_rows {
        let delta = cents(*total + *wallet) - cents(funded);
        sum_delta += delta;
        lines.push_str(&format!(
            "{:<4} {:<44} {:>12} {:>12} {:>+10.2}\n",
            sim.label(*i),
            format!("{:#x}", sim.participants[*i].address),
            sim.fmt(*total),
            sim.fmt(*wallet),
            delta as f64 / 100.0,
        ));
    }
    lines.push_str(&format!(
        "\nΣΔ across participants: {:+.2} USDC (a closed system nets to zero)\n",
        sum_delta as f64 / 100.0
    ));
    lines.push_str("all cycles finalized, every balance matches the ledger ✓");
    println!("{lines}");
    ensure!(
        sum_delta == 0,
        "value leaked: participant deltas sum to {sum_delta} cents"
    );
    Ok(())
}
