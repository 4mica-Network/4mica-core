//! The settlement cycle from end to end: open and freeze cycles, commit a netted cycle
//! on-chain, drive it through payment, seizure and shortfall, and mirror the resulting chain
//! events back into the ledger.
//!
//! What gets cleared is [`NettingService`](super::netting::NettingService)'s job; moving a cycle
//! along its timeline is this one's.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::{Address, B256, U256};
use anyhow::anyhow;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus,
};
use entities::settlement_cycle;
use log::{error, info, warn};
use sea_orm::TransactionTrait;

use crate::error::{ServiceError, ServiceResult};
use crate::ethereum::{
    ClearingCommitInput, CreditorSettlement, DebtorSettlement, event_data::EventMeta,
};
use crate::evm;
use crate::persist::repo;
use crate::persist::rows::ParticipantPosition;
use crate::service::ctx::Ctx;
use crate::service::shared::clearing_proofs::{ClearingProofOps, ParticipantLeaf};
use crate::service::shared::cycle::CycleOps;
use crate::service::shared::{map_transaction_error, settlement_ledger};

pub struct ClearingService {
    ctx: Arc<Ctx>,
    cycle_ops: Arc<CycleOps>,
    proof_ops: Arc<ClearingProofOps>,
}

impl ClearingService {
    pub fn new(ctx: Arc<Ctx>, cycle_ops: Arc<CycleOps>, proof_ops: Arc<ClearingProofOps>) -> Self {
        Self {
            ctx,
            cycle_ops,
            proof_ops,
        }
    }

    /// The cycle an operation at `now` belongs to, opening one (and freezing the elapsed
    /// predecessor) if needed.
    pub async fn get_or_create_active_cycle(
        &self,
        asset_address: Address,
        now: DateTime<Utc>,
    ) -> ServiceResult<settlement_cycle::Model> {
        self.cycle_ops
            .get_or_create_active_cycle(asset_address, now)
            .await
    }

    pub async fn ensure_active_cycles(&self) -> ServiceResult<Vec<String>> {
        let now = Utc::now();
        let assets = self.cycle_ops.supported_settlement_assets().await?;
        let mut cycle_ids = Vec::with_capacity(assets.len());
        for asset in assets {
            match self.cycle_ops.get_or_create_active_cycle(asset, now).await {
                Ok(cycle) => cycle_ids.push(cycle.id),
                Err(err) => warn!("failed to ensure active cycle for asset {asset}: {err:?}"),
            }
        }
        Ok(cycle_ids)
    }

    pub async fn freeze_elapsed_cycles(&self) -> ServiceResult<Vec<String>> {
        let now = Utc::now().naive_utc();
        let due = repo::list_open_cycles_ending_before_on(self.ctx.db(), now).await?;
        let mut frozen = Vec::new();
        for cycle in due {
            let cycle_id = cycle.id.clone();
            if let Err(err) = self.cycle_ops.freeze_cycle(&cycle_id).await {
                warn!("failed to freeze settlement cycle {cycle_id}: {err:?}");
                continue;
            }
            frozen.push(cycle_id);
        }
        Ok(frozen)
    }

    pub async fn commit_due_clearing_batches(&self) -> ServiceResult<Vec<String>> {
        let now = Utc::now().naive_utc();
        let mut due = repo::list_netting_computed_cycles_commit_due_on(self.ctx.db(), now).await?;

        // Also re-drive cycles committed optimistically whose CycleCommitted event never
        // arrived within the retry window — the commit tx was likely reorged out.
        let stale_before = self.settlement_stale_before(now)?;
        due.extend(repo::list_commit_retry_due_on(self.ctx.db(), stale_before).await?);

        let mut committed = Vec::new();
        for cycle in due {
            let cycle_id = cycle.id.clone();
            if let Err(err) = self.commit_cycle_to_chain(&cycle_id).await {
                warn!("failed to commit clearing batch for settlement cycle {cycle_id}: {err:?}");
                continue;
            }
            committed.push(cycle_id);
        }
        Ok(committed)
    }

    pub async fn commit_cycle_to_chain(&self, cycle_id: &str) -> ServiceResult<()> {
        let cycle = repo::get_cycle_by_id(&self.ctx.persist, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;

        let committable = cycle.status == SettlementCycleStatus::NettingComputed
            || (cycle.status == SettlementCycleStatus::PaymentWindowOpen
                && !cycle.status_confirmed);
        if !committable {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected NettingComputed or unconfirmed PaymentWindowOpen",
                cycle.status
            )));
        }

        let batch = repo::get_clearing_batch_by_cycle_on(self.ctx.db(), cycle_id)
            .await?
            .ok_or_else(|| {
                ServiceError::InvalidParams(format!(
                    "settlement cycle {cycle_id} has no clearing batch"
                ))
            })?;
        let _clearing_house_address = evm::parse_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.ctx.config.ethereum_config.clearing_house_address,
        )
        .and_then(|address| {
            if address == Address::ZERO {
                Err(ServiceError::InvalidParams(
                    "ETHEREUM_CLEARING_HOUSE_ADDRESS must be configured before committing clearing batches"
                        .to_string(),
                ))
            } else {
                Ok(address)
            }
        })?;

        let cycle_config = &self.ctx.config.settlement_cycle;
        let submission_window = Duration::seconds(
            i64::try_from(cycle_config.payment_submission_window_secs)
                .map_err(|e| ServiceError::Other(anyhow!(e)))?,
        );
        let finality_window = Duration::seconds(
            i64::try_from(cycle_config.payment_finality_window_secs)
                .map_err(|e| ServiceError::Other(anyhow!(e)))?,
        );
        let committed_at = Utc::now();
        let payment_submission_deadline = (committed_at + submission_window).naive_utc();
        let payment_finality_deadline = (committed_at + finality_window).naive_utc();

        let input = ClearingCommitInput {
            cycle_id: evm::cycle_id_hash(&cycle.id),
            asset: batch.asset_address,
            merkle_root: batch.merkle_root,
            total_net_debit: batch.total_net_debit,
            total_net_credit: batch.total_net_credit,
            payment_submission_deadline: crate::util::timestamp_to_u64(
                "payment submission deadline",
                payment_submission_deadline,
            )?,
            payment_finality_deadline: crate::util::timestamp_to_u64(
                "payment finality deadline",
                payment_finality_deadline,
            )?,
        };

        let commit = self
            .ctx
            .chain
            .commit_clearing_cycle(input)
            .await
            .map_err(|err| ServiceError::Other(anyhow!(err)))?;
        let tx_hash = commit.tx_hash.to_string();
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_on(
            self.ctx.db(),
            cycle_id,
            Some(tx_hash.clone()),
            payment_submission_deadline,
            payment_finality_deadline,
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(self.ctx.db(), cycle_id, tx_hash.clone(), now)
            .await?;
        if changed {
            info!(
                "committed settlement cycle {} to ClearingHouse in tx {}",
                cycle_id, tx_hash
            );
        }
        Ok(())
    }

    /// Open settlement for confirmed payment-window cycles past their finality deadline:
    /// seize/fund on-chain and mark `Settling`, or drive an under-funded cycle toward
    /// Shortfall. Returns cycle ids that had an on-chain tx submitted.
    pub async fn settle_due_cycles(&self) -> ServiceResult<Vec<String>> {
        let Some(_tick) = self.acquire_settlement_tick() else {
            return Ok(Vec::new());
        };

        let now = Utc::now().naive_utc();
        let stale_before = self.settlement_stale_before(now)?;
        let mut acted = Vec::new();

        // Fresh confirmed cycles at finality, plus unconfirmed Settling cycles whose seize/fund
        // never resolved within the retry window — both re-driven through open_cycle_settlement.
        let mut due = repo::list_payment_window_cycles_finality_due_on(self.ctx.db(), now).await?;
        due.extend(repo::list_settling_retry_due_on(self.ctx.db(), stale_before).await?);
        for cycle in due {
            let cycle_id = cycle.id.clone();
            match self
                .open_cycle_settlement(&cycle_id, cycle.payment_finality_deadline, now)
                .await
            {
                Ok(true) => acted.push(cycle_id),
                Ok(false) => {}
                Err(err) => {
                    warn!("failed to open settlement for settlement cycle {cycle_id}: {err:?}")
                }
            }
        }

        Ok(acted)
    }

    /// Re-drive cycles left optimistically in `Shortfall` whose pro-rata distribution hasn't
    /// fully resolved within the retry window (a mark/fund tx was likely reorged out).
    pub async fn retry_shortfall_cycles(&self) -> ServiceResult<Vec<String>> {
        let Some(_tick) = self.acquire_settlement_tick() else {
            return Ok(Vec::new());
        };

        let now = Utc::now().naive_utc();
        let stale_before = self.settlement_stale_before(now)?;
        let mut acted = Vec::new();

        let retry = repo::list_shortfall_retry_due_on(self.ctx.db(), stale_before).await?;
        for cycle in retry {
            let cycle_id = cycle.id.clone();
            match self.drive_cycle_shortfall(&cycle_id, now).await {
                Ok(true) => acted.push(cycle_id),
                Ok(false) => {}
                Err(err) => {
                    error!("failed to re-drive shortfall for settlement cycle {cycle_id}: {err:?}")
                }
            }
        }

        Ok(acted)
    }

    /// Finalize confirmed (fully-resolved) `Settling` cycles, then re-submit `finalizeCycle` for
    /// cycles left optimistically `Finalized` whose `CycleFinalized` event never arrived within
    /// the retry window. Also refreshes the hanging-cycles gauge.
    pub async fn finalize_due_cycles(&self) -> ServiceResult<Vec<String>> {
        let Some(_tick) = self.acquire_settlement_tick() else {
            return Ok(Vec::new());
        };

        let now = Utc::now().naive_utc();
        let stale_before = self.settlement_stale_before(now)?;
        let mut acted = Vec::new();

        let settling = repo::list_confirmed_settling_cycles_on(self.ctx.db()).await?;
        for cycle in settling {
            let cycle_id = cycle.id.clone();
            match self.finalize_settling_cycle(&cycle_id, now).await {
                Ok(true) => acted.push(cycle_id),
                Ok(false) => {}
                Err(err) => {
                    error!("failed to finalize settling settlement cycle {cycle_id}: {err:?}")
                }
            }
        }

        let finalize_retry = repo::list_finalize_retry_due_on(self.ctx.db(), stale_before).await?;
        for cycle in finalize_retry {
            let cycle_id = cycle.id.clone();
            match self.retry_unconfirmed_finalize(&cycle_id, now).await {
                Ok(true) => acted.push(cycle_id),
                Ok(false) => {}
                Err(err) => {
                    error!("failed to re-drive finalize for settlement cycle {cycle_id}: {err:?}")
                }
            }
        }

        Ok(acted)
    }

    pub fn settlement_stale_before(&self, now: NaiveDateTime) -> ServiceResult<NaiveDateTime> {
        let retry_delay = Duration::seconds(
            i64::try_from(self.ctx.config.settlement_cycle.settlement_retry_delay_secs)
                .map_err(|e| ServiceError::Other(anyhow!(e)))?,
        );
        Ok(now - retry_delay)
    }

    /// Publish per-status counts of cycles stuck unconfirmed well past when their confirming event
    /// should have arrived — a signal for operator attention.
    pub async fn record_hanging_cycles_gauge(&self) -> ServiceResult<()> {
        use entities::settlement_cycle::Column;
        use sea_orm::ActiveEnum;

        let now = Utc::now().naive_utc();
        let cfg = &self.ctx.config.settlement_cycle;
        let secs = |n: u64| -> ServiceResult<Duration> {
            Ok(Duration::seconds(
                i64::try_from(n).map_err(|e| ServiceError::Other(anyhow!(e)))?,
            ))
        };
        let retry_window = secs(
            cfg.settlement_retry_delay_secs
                .saturating_mul(cfg.hanging_retry_windows),
        )?;
        let grace = secs(cfg.shortfall_grace_secs)?;

        // (state, anchor deadline, slack past that anchor before we call it hanging).
        // PaymentWindowOpen confirms after commit; Settling after finality; Shortfall only starts
        // once the grace elapses; Finalized passes through both settle and finalize retry phases.
        let buckets = [
            (
                SettlementCycleStatus::PaymentWindowOpen,
                Column::ClearingCommitDeadline,
                retry_window,
            ),
            (
                SettlementCycleStatus::Settling,
                Column::PaymentFinalityDeadline,
                retry_window,
            ),
            (
                SettlementCycleStatus::Shortfall,
                Column::PaymentFinalityDeadline,
                grace + retry_window,
            ),
            (
                SettlementCycleStatus::Finalized,
                Column::PaymentFinalityDeadline,
                retry_window * 2,
            ),
        ];
        for (status, anchor, slack) in buckets {
            let count = repo::count_unconfirmed_cycles_before_on(
                self.ctx.db(),
                status.clone(),
                anchor,
                now - slack,
            )
            .await?;
            crate::metrics::record_hanging_unconfirmed_cycles(&status.to_value(), count);
        }
        Ok(())
    }

    /// Guard so only one settlement tick runs at a time. The scheduler does not suppress
    /// overlapping fires, and each tick makes many serial on-chain round-trips; without this a
    /// slow tick could overlap the next and redundantly re-submit the same settlement txs. (The
    /// on-chain contract is idempotent, so the risk is wasted gas and spurious revert logs, not
    /// double settlement.) `None` means a tick is already in flight and the caller should skip.
    fn acquire_settlement_tick(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        match self.ctx.settlement_tick.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                warn!("settlement tick still running; skipping this fire to avoid overlap");
                None
            }
        }
    }

    /// Seize unpaid debtors' collateral, then fund unclaimed creditors, marking the cycle
    /// `Settling` (unconfirmed). A creditor batch that reverts `CycleUnderfunded` means the
    /// recovered pool can't cover claims: socialize the loss via Shortfall once the grace window
    /// past finality has elapsed, otherwise keep the cycle in `Settling` to retry seizures.
    async fn open_cycle_settlement(
        &self,
        cycle_id: &str,
        finality_deadline: NaiveDateTime,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        let unpaid = repo::list_unpaid_debtors_for_cycle_on(self.ctx.db(), cycle_id).await?;
        let claimable =
            repo::list_claimable_creditors_for_cycle_on(self.ctx.db(), cycle_id).await?;
        if unpaid.is_empty() && claimable.is_empty() {
            // Nothing to submit — every participant resolved on-chain already. Mark Settling and
            // confirm inline, since no further events will arrive to trigger confirmation.
            return self
                .ctx
                .persist
                .db
                .transaction::<_, _, ServiceError>(|txn| {
                    let cycle_id = cycle_id.to_owned();
                    Box::pin(async move {
                        let marked = repo::mark_cycle_settling_on(txn, &cycle_id, now).await?;
                        repo::confirm_cycle_resolved_on(txn, &cycle_id, now).await?;
                        if marked {
                            info!("cycle {cycle_id} fully resolved at finality; ready to finalize");
                        }
                        Ok(marked)
                    })
                })
                .await
                .map_err(map_transaction_error);
        }

        let batch_size = self.ctx.config.settlement_cycle.default_batch_size.max(1) as usize;
        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);

        // Fetch the Merkle proofs once and join both sides through the shared helper so the
        // open-settlement and shortfall paths apply the same missing-proof policy.
        let proofs = self
            .proof_ops
            .get_cycle_participant_proofs(cycle_id)
            .await?;
        let debtor_entries = Self::join_role_settlements(
            cycle_id,
            &unpaid,
            &proofs,
            ParticipantCycleRole::NetDebtor,
            "debtor",
            |debtor, net_debit, proof| DebtorSettlement {
                debtor,
                net_debit,
                proof,
            },
        )?;
        let creditor_entries = Self::join_role_settlements(
            cycle_id,
            &claimable,
            &proofs,
            ParticipantCycleRole::NetCreditor,
            "creditor",
            |creditor, net_credit, proof| CreditorSettlement {
                creditor,
                net_credit,
                proof,
            },
        )?;

        // A missing proof can never finalize on-chain; defer and surface it rather
        // than half-settling into a stuck state.
        if debtor_entries.len() != unpaid.len() || creditor_entries.len() != claimable.len() {
            warn!(
                "incomplete clearing proofs for settlement cycle {cycle_id} (debtors {}/{}, creditors {}/{}); deferring settlement",
                debtor_entries.len(),
                unpaid.len(),
                creditor_entries.len(),
                claimable.len()
            );
            return Ok(false);
        }

        repo::mark_cycle_settling_on(self.ctx.db(), cycle_id, now).await?;

        for chunk in debtor_entries.chunks(batch_size) {
            self.ctx
                .chain
                .settle_defaults_from_collateral_batch(onchain_cycle_id, chunk.to_vec())
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        for chunk in creditor_entries.chunks(batch_size) {
            match self
                .ctx
                .chain
                .fund_creditors_from_pool_batch(onchain_cycle_id, chunk.to_vec())
                .await
            {
                Ok(_) => {}
                Err(err) if is_cycle_underfunded(&err) => {
                    if self.past_shortfall_grace(finality_deadline, now) {
                        self.drive_cycle_shortfall(cycle_id, now).await?;
                    } else {
                        info!(
                            "settlement cycle {cycle_id} under-funded; retrying seizures until shortfall grace elapses"
                        );
                    }
                    return Ok(true);
                }
                Err(err) => return Err(ServiceError::Other(anyhow!(err))),
            }
        }

        info!(
            "opened settlement for cycle {cycle_id}: {} debtor seizure(s), {} creditor funding(s)",
            debtor_entries.len(),
            creditor_entries.len()
        );
        Ok(true)
    }

    fn past_shortfall_grace(&self, finality_deadline: NaiveDateTime, now: NaiveDateTime) -> bool {
        let grace = self.ctx.config.settlement_cycle.shortfall_grace_secs;
        let grace_deadline = (finality_deadline.and_utc().timestamp() as u64).saturating_add(grace);
        (now.and_utc().timestamp() as u64) > grace_deadline
    }

    /// Submit `finalizeCycle` for a confirmed (fully-resolved) `Settling` cycle and mark it
    /// `Finalized` (unconfirmed) optimistically; the `CycleFinalized` event confirms it and
    /// releases residual guarantees. A submit failure leaves the cycle confirmed-`Settling` for
    /// the next finalize tick to retry.
    async fn finalize_settling_cycle(
        &self,
        cycle_id: &str,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);
        match self
            .ctx
            .chain
            .finalize_clearing_cycle(onchain_cycle_id)
            .await
        {
            Ok(tx) => {
                let marked =
                    repo::mark_cycle_finalized_optimistic_on(self.ctx.db(), cycle_id, now).await?;
                if marked {
                    info!(
                        "submitted finalizeCycle for settlement cycle {cycle_id} in tx {:?}; awaiting confirmation",
                        tx.tx_hash
                    );
                }
                Ok(marked)
            }
            Err(err) => {
                error!("failed to finalize the settlement cycle {cycle_id}: {err}");
                Ok(false)
            }
        }
    }

    /// Re-submit `finalizeCycle` for a cycle left optimistically `Finalized` (unconfirmed) whose
    /// `CycleFinalized` event never arrived — the finalize tx was likely reorged out. The tx is
    /// idempotent (reverts harmlessly if already finalized on-chain); either way reset the retry
    /// window and keep waiting for the event.
    async fn retry_unconfirmed_finalize(
        &self,
        cycle_id: &str,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);
        if let Err(err) = self
            .ctx
            .chain
            .finalize_clearing_cycle(onchain_cycle_id)
            .await
        {
            warn!("finalizeCycle re-submit for settlement cycle {cycle_id} did not apply: {err}");
        }
        Ok(repo::touch_cycle_finalize_retry_on(self.ctx.db(), cycle_id, now).await?)
    }

    /// Join the still-actionable `positions` (all expected to be of `role`) with their Merkle
    /// proofs into on-chain settlement entries. A participant whose proof is missing is skipped
    /// with a warning; callers compare `entries.len()` against `positions.len()` to detect that
    /// and defer, because a cycle with a missing proof can never settle on-chain. Shared by the
    /// open-settlement and shortfall paths so both apply the same missing-proof policy.
    fn join_role_settlements<T>(
        cycle_id: &str,
        positions: &[ParticipantPosition],
        proofs: &[(ParticipantLeaf, Vec<B256>)],
        role: ParticipantCycleRole,
        role_label: &str,
        build: impl Fn(Address, U256, Vec<B256>) -> T,
    ) -> ServiceResult<Vec<T>> {
        let mut by_addr: HashMap<Address, (U256, &Vec<B256>)> = HashMap::new();
        for (leaf, proof) in proofs {
            if leaf.role == role {
                by_addr.insert(leaf.participant, (leaf.amount, proof));
            }
        }

        let mut entries = Vec::with_capacity(positions.len());
        for pos in positions {
            let participant = pos.participant;
            match by_addr.get(&participant) {
                Some((amount, proof)) => {
                    entries.push(build(participant, *amount, (*proof).clone()))
                }
                None => warn!(
                    "missing {role_label} proof for {participant} in settlement cycle {cycle_id}; skipping"
                ),
            }
        }
        Ok(entries)
    }

    /// Build the on-chain creditor-funding entries (with Merkle proofs) for a cycle's
    /// still-claimable net creditors. Returns the entries and the expected count; when
    /// `entries.len() < expected` a creditor's proof was missing (and they must self-claim).
    async fn creditor_settlements(
        &self,
        cycle_id: &str,
    ) -> ServiceResult<(Vec<CreditorSettlement>, usize)> {
        let claimable =
            repo::list_claimable_creditors_for_cycle_on(self.ctx.db(), cycle_id).await?;
        if claimable.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let proofs = self
            .proof_ops
            .get_cycle_participant_proofs(cycle_id)
            .await?;
        let entries = Self::join_role_settlements(
            cycle_id,
            &claimable,
            &proofs,
            ParticipantCycleRole::NetCreditor,
            "creditor",
            |creditor, net_credit, proof| CreditorSettlement {
                creditor,
                net_credit,
                proof,
            },
        )?;
        Ok((entries, claimable.len()))
    }

    /// Socialize a genuinely under-collateralised cycle: mark it `Shortfall` on-chain and fund
    /// creditors their pro-rata share. Also marks the cycle `Shortfall` (unconfirmed)
    /// in the DB; full resolution confirms it later.
    async fn drive_cycle_shortfall(
        &self,
        cycle_id: &str,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);

        let marked = repo::mark_cycle_shortfall_on(self.ctx.db(), cycle_id, now).await?;
        if marked {
            info!("settlement cycle {cycle_id} entered Shortfall; pro-rata distribution submitted");
        }

        if let Err(err) = self.ctx.chain.mark_cycle_shortfall(onchain_cycle_id).await {
            warn!(
                "markCycleShortfall for settlement cycle {cycle_id} did not apply (may already be in shortfall): {err}"
            );
        }

        let (creditor_entries, creditor_expected) = self.creditor_settlements(cycle_id).await?;
        if creditor_entries.len() != creditor_expected {
            warn!(
                "incomplete creditor proofs for shortfall settlement cycle {cycle_id} ({}/{}); the unproven creditors must self-claim on-chain",
                creditor_entries.len(),
                creditor_expected
            );
        }
        let batch_size = self.ctx.config.settlement_cycle.default_batch_size.max(1) as usize;
        for chunk in creditor_entries.chunks(batch_size) {
            self.ctx
                .chain
                .fund_creditors_from_pool_batch(onchain_cycle_id, chunk.to_vec())
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        Ok(marked)
    }

    // --- chain event mirroring --------------------------------------------------------------

    pub async fn process_cycle_committed(
        &self,
        onchain_cycle_id: B256,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle commit event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let changed = repo::confirm_cycle_committed_on(
            self.ctx.db(),
            &cycle_id,
            Some(tx_hash.to_string()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(self.ctx.db(), &cycle_id, tx_hash.to_string(), now)
            .await?;
        if changed {
            info!("confirmed ClearingHouse CycleCommitted for cycle {cycle_id}");
        }
        Ok(())
    }

    pub async fn process_cycle_shortfall(&self, onchain_cycle_id: B256) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle shortfall event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let changed = repo::ensure_cycle_shortfall_on(self.ctx.db(), &cycle_id, now).await?;
        if changed {
            info!("mirrored ClearingHouse CycleShortfall for cycle {cycle_id}");
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: Address,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor payment event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let changed = self
            .ctx
            .persist
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();

                let tx_hash = tx_hash.to_string();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        debtor,
                        ParticipantCycleStatus::Unpaid,
                        ParticipantCycleStatus::Paid,
                        Some(tx_hash),
                        now,
                    )
                    .await?;
                    if changed {
                        settlement_ledger::settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            debtor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                        )
                        .await?;
                        settlement_ledger::maybe_confirm_resolved_cycle(txn, &cycle_id, now)
                            .await?;
                    }
                    Ok(changed)
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!("mirrored DebtorPaid: cycle={cycle_id}, debtor={debtor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_credit_claim(
        &self,
        onchain_cycle_id: B256,
        creditor: Address,
        tx_meta: EventMeta,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("credit claim event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let tx_hash = tx_meta.tx_hash.clone();

        let changed = self
            .ctx
            .persist
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();

                let tx_hash = tx_meta.tx_hash.clone();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        creditor,
                        ParticipantCycleStatus::Claimable,
                        ParticipantCycleStatus::Claimed,
                        Some(tx_hash),
                        now,
                    )
                    .await?;
                    if changed {
                        // A net creditor's own outgoing guarantees were fully
                        // offset by its incoming exposure, so settling its claim
                        // also discharges those obligations.
                        settlement_ledger::settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            creditor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                        )
                        .await?;
                        settlement_ledger::maybe_confirm_resolved_cycle(txn, &cycle_id, now)
                            .await?;
                    }
                    Ok(changed)
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!("mirrored CreditorClaimed: cycle={cycle_id}, creditor={creditor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_defaulted_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: Address,
        tx_meta: EventMeta,
    ) -> ServiceResult<()> {
        let tx_hash = tx_meta.tx_hash.clone();

        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor default event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();

        let guarantees = self
            .ctx
            .persist
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();

                let tx_hash = tx_meta.tx_hash.clone();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        debtor,
                        ParticipantCycleStatus::Unpaid,
                        ParticipantCycleStatus::Defaulted,
                        Some(tx_hash),
                        now,
                    )
                    .await?;

                    if !changed {
                        return Ok(0);
                    }

                    let guarantees = settlement_ledger::settle_netted_guarantees_for_payer(
                        txn,
                        &cycle_id,
                        debtor,
                        GuaranteeSettlementStatus::DefaultRemunerated,
                        now,
                    )
                    .await?;

                    settlement_ledger::maybe_confirm_resolved_cycle(txn, &cycle_id, now).await?;

                    Ok(guarantees)
                })
            })
            .await
            .map_err(map_transaction_error)?;

        if guarantees > 0 {
            info!(
                "mirrored DebtorDefaulted: cycle={}, debtor={}, guarantees={}, tx_hash={}",
                cycle_id, debtor, guarantees, tx_hash
            );
        }
        Ok(())
    }

    pub async fn process_cycle_finalized(&self, onchain_cycle_id: B256) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle finalized event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        self.finalize_cycle(&cycle_id).await
    }

    pub async fn finalize_cycle(&self, cycle_id: &str) -> ServiceResult<()> {
        let now = Utc::now().naive_utc();
        let cycle_id_owned = cycle_id.to_string();
        let (changed, settled) = self
            .ctx
            .persist
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id_owned.clone();
                Box::pin(async move {
                    let changed = repo::confirm_cycle_finalized_on(txn, &cycle_id, now).await?;
                    let settled = if changed {
                        settlement_ledger::settle_remaining_netted_guarantees_for_cycle(
                            txn, &cycle_id, now,
                        )
                        .await?
                    } else {
                        0
                    };
                    Ok((changed, settled))
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if changed {
            info!(
                "finalized settlement cycle {} (settled {} residual netted guarantee(s))",
                cycle_id, settled
            );
        }
        Ok(())
    }

    async fn resolve_onchain_cycle_id(
        &self,
        onchain_cycle_id: B256,
    ) -> ServiceResult<Option<String>> {
        // Indexed point lookup on the persisted on-chain cycle-id hash, replacing
        // a full-table scan (removing both the DoS surface and the silent-drop
        // risk when a cycle leaves a candidate window).
        Ok(repo::get_cycle_id_by_onchain_hash_on(self.ctx.db(), onchain_cycle_id).await?)
    }
}

/// True when `err` is the ClearingHouse `CycleUnderfunded` revert — the recovered pool can't
/// cover the cycle's creditor claims, so the claims batch was rejected atomically.
fn is_cycle_underfunded(err: &crate::error::CoreContractApiError) -> bool {
    use crate::error::CoreContractApiError;
    use crate::ethereum::contract_abi::ClearingHouse;
    use alloy::sol_types::SolError;
    matches!(
        err,
        CoreContractApiError::ContractRevert(revert)
            if revert.selector.0 == ClearingHouse::CycleUnderfunded::SELECTOR
    )
}
