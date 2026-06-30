use std::collections::HashMap;

use alloy::primitives::{Address, B256, U256};
use anyhow::anyhow;
use chrono::{NaiveDateTime, Utc};
use entities::cycle_participant_position;
use entities::sea_orm_active_enums::{
    CollateralEventType, GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus,
    SettlementCycleStatus,
};
use log::{error, info, warn};
use sea_orm::TransactionTrait;

use crate::{
    error::{ServiceError, ServiceResult},
    ethereum::{ClearingCommitInput, CreditorSettlement, DebtorSettlement, event_data::EventMeta},
    evm,
    persist::repo::{self, common::parse_address},
    service::{CoreService, netting::ParticipantLeaf},
};

impl CoreService {
    pub async fn commit_cycle_to_chain(&self, cycle_id: &str) -> ServiceResult<()> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != SettlementCycleStatus::NettingComputed {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status,
                SettlementCycleStatus::NettingComputed
            )));
        }

        let batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;
        let _clearing_house_address = evm::parse_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
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

        let input = ClearingCommitInput {
            cycle_id: evm::cycle_id_hash(&cycle.id),
            asset: evm::parse_address("cycle asset", &batch.asset_address)?,
            merkle_root: evm::parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?,
            total_net_debit: evm::parse_u256(
                "clearing batch total net debit",
                &batch.total_net_debit,
            )?,
            total_net_credit: evm::parse_u256(
                "clearing batch total net credit",
                &batch.total_net_credit,
            )?,
            payment_submission_deadline: crate::util::timestamp_to_u64(
                "payment submission deadline",
                cycle.payment_submission_deadline,
            )?,
            payment_finality_deadline: crate::util::timestamp_to_u64(
                "payment finality deadline",
                cycle.payment_finality_deadline,
            )?,
        };

        let commit = self
            .inner
            .contract_api
            .commit_clearing_cycle(input)
            .await
            .map_err(|err| ServiceError::Other(anyhow!(err)))?;
        let tx_hash = commit.tx_hash.to_string();
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Some(tx_hash.clone()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            tx_hash.clone(),
            now,
        )
        .await?;
        if changed {
            info!(
                "committed settlement cycle {} to ClearingHouse in tx {}",
                cycle_id, tx_hash
            );
        }
        Ok(())
    }

    /// Settle every cycle past its finality deadline: open settlement for
    /// payment-window cycles (mark `Settling`), then finalize `Settling` cycles whose
    /// ledger is fully resolved. Returns cycle ids that had an on-chain tx submitted.
    pub async fn settle_due_cycles(&self) -> ServiceResult<Vec<String>> {
        // Only one settlement tick may run at a time. The scheduler does not suppress overlapping
        // fires, and each tick makes many serial on-chain round-trips; without this guard a slow
        // tick could overlap the next and redundantly re-submit the same settlement txs. (The
        // on-chain contract is idempotent, so the risk is wasted gas and spurious revert logs, not
        // double settlement.)
        let _tick = match self.inner.settlement_tick.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                warn!("settlement tick still running; skipping this fire to avoid overlap");
                return Ok(Vec::new());
            }
        };

        let now = Utc::now().naive_utc();
        let mut acted = Vec::new();

        let due = repo::list_payment_window_cycles_finality_due_on(
            self.inner.persist_ctx.db.as_ref(),
            now,
        )
        .await?;
        for cycle in due {
            let cycle_id = cycle.id.clone();
            let opened = self.open_cycle_settlement(&cycle_id, now).await;
            match opened {
                Ok(true) => {
                    acted.push(cycle_id);
                    continue;
                }
                Ok(false) => {}
                Err(ref err) => {
                    warn!("failed to open settlement for settlement cycle {cycle_id}: {err:?}");
                }
            }
            // Settlement did not complete (under-funded, or a seize/fund hiccup). An under-funded
            // cycle can never fund its creditors and would retry forever; let the shortfall driver
            // socialize it once the grace window passes. Seizures already
            // submitted are idempotent, and the driver no-ops unless the cycle is genuinely
            // resolved-but-under-funded past grace.
            match self.drive_cycle_shortfall(&cycle_id, now).await {
                Ok(true) => acted.push(cycle_id),
                Ok(false) => {}
                Err(e) => {
                    error!("failed to evaluate shortfall for settlement cycle {cycle_id}: {e:?}")
                }
            }
        }

        let settling = repo::list_settling_cycles_on(self.inner.persist_ctx.db.as_ref()).await?;
        for cycle in settling {
            let cycle_id = cycle.id.clone();
            match self.finalize_settling_cycle(&cycle_id).await {
                Ok(true) => {
                    if !acted.contains(&cycle_id) {
                        acted.push(cycle_id);
                    }
                }
                Ok(false) => match self.drive_cycle_shortfall(&cycle_id, now).await {
                    Ok(true) => {
                        if !acted.contains(&cycle_id) {
                            acted.push(cycle_id);
                        }
                    }
                    Ok(false) => {}
                    Err(err) => {
                        error!(
                            "failed to evaluate shortfall for settlement cycle {cycle_id}: {err:?}"
                        )
                    }
                },
                Err(err) => {
                    error!("failed to finalize settling settlement cycle {cycle_id}: {err:?}")
                }
            }
        }

        Ok(acted)
    }

    /// Seize unpaid debtors' collateral and fund unclaimed creditors on-chain, then
    /// mark the cycle `Settling`.
    /// TODO: Optimize overlapped executions
    async fn open_cycle_settlement(
        &self,
        cycle_id: &str,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        let unpaid =
            repo::list_unpaid_debtors_for_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?;
        let claimable = repo::list_claimable_creditors_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        if unpaid.is_empty() && claimable.is_empty() {
            // Fully resolved on-chain; nothing to submit, just hand off to finalize.
            let marked =
                repo::mark_cycle_settling_on(self.inner.persist_ctx.db.as_ref(), cycle_id, now)
                    .await?;
            if marked {
                info!(
                    "settlement cycle {cycle_id} fully resolved at finality; awaiting finalization"
                );
            }
            return Ok(marked);
        }

        let batch_size = self.inner.config.settlement_cycle.default_batch_size.max(1) as usize;
        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);

        // Fetch the Merkle proofs once and join both sides through the shared helper so the
        // open-settlement and shortfall paths apply the same missing-proof policy.
        let proofs = self.get_cycle_participant_proofs(cycle_id).await?;
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

        for chunk in debtor_entries.chunks(batch_size) {
            self.inner
                .contract_api
                .settle_defaults_from_collateral_batch(onchain_cycle_id, chunk.to_vec())
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        // After seizing, only fund creditors if the pool can actually cover them. Submitting a
        // batch against an under-funded cycle would revert (CycleUnderfunded) and waste gas — and
        // the terminal Shortfall path handles distribution instead. Defer here;
        // the settlement job will drive the cycle to Shortfall once the grace window passes.
        let onchain = self
            .inner
            .contract_api
            .get_clearing_cycle(onchain_cycle_id)
            .await
            .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        if onchain.funded() < onchain.total_net_credit {
            info!(
                "settlement cycle {cycle_id} under-funded (funded {} < required {}); deferring creditor funding to shortfall handling",
                onchain.funded(),
                onchain.total_net_credit
            );
            return Ok(false);
        }

        for chunk in creditor_entries.chunks(batch_size) {
            self.inner
                .contract_api
                .fund_creditors_from_pool_batch(onchain_cycle_id, chunk.to_vec())
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        repo::mark_cycle_settling_on(self.inner.persist_ctx.db.as_ref(), cycle_id, now).await?;
        info!(
            "opened settlement for cycle {cycle_id}: {} debtor seizure(s), {} creditor funding(s)",
            debtor_entries.len(),
            creditor_entries.len()
        );
        Ok(true)
    }

    /// Finalize a `Settling` cycle on-chain once its ledger shows no outstanding
    /// debtors or creditors (events mirrored), so the tx won't revert.
    async fn finalize_settling_cycle(&self, cycle_id: &str) -> ServiceResult<bool> {
        let unpaid =
            repo::list_unpaid_debtors_for_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?;
        let claimable = repo::list_claimable_creditors_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        if !unpaid.is_empty() || !claimable.is_empty() {
            return Ok(false);
        }

        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);
        match self
            .inner
            .contract_api
            .finalize_clearing_cycle(onchain_cycle_id)
            .await
        {
            Ok(tx) => {
                info!(
                    "finalized settlement cycle {cycle_id} on-chain in tx {:?}",
                    tx.tx_hash
                );
                Ok(true)
            }
            Err(err) => {
                error!("failed to finalize the settlement cycle {cycle_id}: {err}");
                Ok(false)
            }
        }
    }

    /// Join the still-actionable `positions` (all expected to be of `role`) with their Merkle
    /// proofs into on-chain settlement entries. A participant whose proof is missing is skipped
    /// with a warning; callers compare `entries.len()` against `positions.len()` to detect that
    /// and defer, because a cycle with a missing proof can never settle on-chain. Shared by the
    /// open-settlement and shortfall paths so both apply the same missing-proof policy.
    fn join_role_settlements<T>(
        cycle_id: &str,
        positions: &[cycle_participant_position::Model],
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
            let participant = evm::parse_optional_address("cycle participant", &pos.participant)?;
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
        let claimable = repo::list_claimable_creditors_for_cycle_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
        )
        .await?;
        if claimable.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let proofs = self.get_cycle_participant_proofs(cycle_id).await?;
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

    /// Drive an under-funded, fully-resolved cycle to the terminal Shortfall state once the
    /// retry/grace window past payment finality has elapsed, then fund its creditors their
    /// pro-rata share so a transient or genuine collateral shortfall can never freeze the cycle
    /// forever. Returns true if it acted.
    async fn drive_cycle_shortfall(
        &self,
        cycle_id: &str,
        now: NaiveDateTime,
    ) -> ServiceResult<bool> {
        // On-chain CycleStatus enum ordinals.
        const CYCLE_STATUS_FINALIZED: u8 = 2;
        const CYCLE_STATUS_SHORTFALL: u8 = 4;

        let onchain_cycle_id = evm::cycle_id_hash(cycle_id);
        let view = self
            .inner
            .contract_api
            .get_clearing_cycle(onchain_cycle_id)
            .await
            .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        if !view.exists || view.status == CYCLE_STATUS_FINALIZED {
            return Ok(false);
        }

        // Stay within the retry window: keep resubmitting seizures rather than socializing a
        // loss that may still resolve.
        let grace_deadline = view
            .payment_finality_deadline
            .saturating_add(self.inner.config.settlement_cycle.shortfall_grace_secs);
        if (now.and_utc().timestamp() as u64) <= grace_deadline {
            return Ok(false);
        }

        // Only socialize a genuinely under-collateralised cycle: every debtor resolved but the
        // recovered pool still can't cover creditor claims.
        if view.status != CYCLE_STATUS_SHORTFALL && !view.is_under_funded_and_resolved() {
            return Ok(false);
        }

        if view.status != CYCLE_STATUS_SHORTFALL {
            warn!(
                "settlement cycle {cycle_id} under-funded after grace window (funded {} < required {}); entering Shortfall",
                view.funded(),
                view.total_net_credit
            );
            self.inner
                .contract_api
                .mark_cycle_shortfall(onchain_cycle_id)
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        // Pay remaining creditors their pro-rata share (no Aave liquidity needed); creditors may
        // also self-claim on-chain.
        let (creditor_entries, creditor_expected) = self.creditor_settlements(cycle_id).await?;
        if creditor_entries.len() != creditor_expected {
            warn!(
                "incomplete creditor proofs for shortfall settlement cycle {cycle_id} ({}/{}); the unproven creditors must self-claim on-chain",
                creditor_entries.len(),
                creditor_expected
            );
        }
        let batch_size = self.inner.config.settlement_cycle.default_batch_size.max(1) as usize;
        for chunk in creditor_entries.chunks(batch_size) {
            self.inner
                .contract_api
                .fund_creditors_from_pool_batch(onchain_cycle_id, chunk.to_vec())
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        }

        let marked =
            repo::mark_cycle_shortfall_on(self.inner.persist_ctx.db.as_ref(), cycle_id, now)
                .await?;
        if marked {
            info!("settlement cycle {cycle_id} closed in Shortfall after pro-rata distribution");
        }
        Ok(marked)
    }

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
        let changed = repo::mark_cycle_payment_window_open_by_id_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            Some(tx_hash.to_string()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            tx_hash.to_string(),
            now,
        )
        .await?;
        if changed {
            info!("mirrored ClearingHouse CycleCommitted for cycle {cycle_id}");
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor payment event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let debtor = parse_address(debtor)?.into_inner();
        let changed = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let debtor = debtor.clone();
                let tx_hash = tx_hash.to_string();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        &debtor,
                        ParticipantCycleStatus::Unpaid,
                        ParticipantCycleStatus::Paid,
                        Some(tx_hash),
                        now,
                    )
                    .await?;
                    if changed {
                        settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            &debtor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                        )
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
        creditor: String,
        asset: String,
        amount: U256,
        tx_meta: EventMeta,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("credit claim event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let creditor = parse_address(creditor)?.into_inner();
        let asset = parse_address(asset)?.into_inner();
        let tx_hash = tx_meta.tx_hash.clone();

        let changed = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let creditor = creditor.clone();
                Box::pin(async move {
                    let changed = repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        &creditor,
                        ParticipantCycleStatus::Claimable,
                        ParticipantCycleStatus::Claimed,
                        Some(tx_meta.tx_hash.clone()),
                        now,
                    )
                    .await?;
                    if changed {
                        // A net creditor's own outgoing guarantees were fully
                        // offset by its incoming exposure, so settling its claim
                        // also discharges those obligations.
                        settle_netted_guarantees_for_payer(
                            txn,
                            &cycle_id,
                            &creditor,
                            GuaranteeSettlementStatus::Settled,
                            now,
                        )
                        .await?;
                        repo::credit_collateral_with_event_on(
                            txn,
                            creditor,
                            asset.to_owned(),
                            amount,
                            CollateralEventType::Credit,
                            Some(tx_meta),
                        )
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

    /// Mirror a `DebtorDefaulted` event: the debtor's collateral has been seized into
    /// the pool, so mark the position defaulted, remunerate the netted guarantees
    /// and debit the collateral
    pub async fn process_defaulted_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: String,
        asset: String,
        amount: U256,
        tx_meta: EventMeta,
    ) -> ServiceResult<()> {
        let debtor = parse_address(debtor)?.into_inner();
        let asset = parse_address(asset)?.into_inner();
        let tx_hash = tx_meta.tx_hash.clone();

        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor default event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();

        let guarantees = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id.clone();
                let debtor = debtor.clone();
                Box::pin(async move {
                    repo::mark_participant_position_status_on(
                        txn,
                        &cycle_id,
                        &debtor,
                        ParticipantCycleStatus::Unpaid,
                        ParticipantCycleStatus::Defaulted,
                        Some(tx_meta.tx_hash.clone()),
                        now,
                    )
                    .await?;

                    let guarantees = settle_netted_guarantees_for_payer(
                        txn,
                        &cycle_id,
                        &debtor,
                        GuaranteeSettlementStatus::DefaultRemunerated,
                        now,
                    )
                    .await?;

                    // Settling the netted guarantees above released the collateral
                    // those guarantees had locked. The seized amount equals the
                    // resolved net debit, which never exceeds that locked (now
                    // unlocked) balance, so this debit always succeeds.
                    repo::debit_collateral_with_event_on(
                        txn,
                        debtor,
                        asset,
                        amount,
                        CollateralEventType::Default,
                        Some(tx_meta),
                    )
                    .await?;

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
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id_owned.clone();
                Box::pin(async move {
                    let changed = repo::mark_cycle_finalized_on(txn, &cycle_id, now).await?;
                    let settled = if changed {
                        settle_remaining_netted_guarantees_for_cycle(txn, &cycle_id, now).await?
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

    /// Finalize a fully-offsetting cycle without an on-chain commit: settle its
    /// netted guarantees and release the collateral they locked. Returns whether
    /// the cycle transitioned to `Finalized`.
    pub async fn short_circuit_offsetting_cycle(&self, cycle_id: &str) -> ServiceResult<bool> {
        let now = Utc::now().naive_utc();
        let cycle_id_owned = cycle_id.to_string();
        let (finalized, settled) = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let cycle_id = cycle_id_owned.clone();
                Box::pin(async move {
                    let finalized =
                        repo::short_circuit_frozen_cycle_on(txn, &cycle_id, now).await?;
                    let settled = if finalized {
                        repo::mark_cycle_guarantees_netted_on(txn, &cycle_id, now).await?;
                        settle_remaining_netted_guarantees_for_cycle(txn, &cycle_id, now).await?
                    } else {
                        0
                    };
                    Ok((finalized, settled))
                })
            })
            .await
            .map_err(map_transaction_error)?;
        if finalized {
            info!(
                "short-circuited fully-offsetting settlement cycle {} (settled {} netted guarantee(s), no on-chain commit)",
                cycle_id, settled
            );
        }
        Ok(finalized)
    }

    async fn resolve_onchain_cycle_id(
        &self,
        onchain_cycle_id: B256,
    ) -> ServiceResult<Option<String>> {
        // Indexed point lookup on the persisted on-chain cycle-id hash, replacing
        // a full-table scan (removing both the DoS surface and the silent-drop
        // risk when a cycle leaves a candidate window).
        let hash = evm::bytes32_hex(onchain_cycle_id);
        Ok(
            repo::get_cycle_id_by_onchain_hash_on(self.inner.persist_ctx.db.as_ref(), &hash)
                .await?,
        )
    }
}

async fn settle_netted_guarantees_for_payer<C: sea_orm::ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payer: &str,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> ServiceResult<u64> {
    let guarantees = repo::list_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer).await?;
    let changed =
        repo::transition_netted_guarantees_for_cycle_payer_on(conn, cycle_id, payer, target, now)
            .await?;

    if changed > 0 {
        for guarantee in guarantees {
            repo::release_locked_collateral_for_guarantee_on(conn, &guarantee).await?;
        }
    }

    Ok(changed)
}

/// Settle every guarantee still in `Netted` for a cycle and release the
/// collateral each one locked, keyed on the payer (`from`) side.
///
/// This is the finalization backstop for guarantees that no role event reached:
/// flat participants (whose exposure netted to zero and who therefore emit no
/// on-chain event), creditors that never claimed, and creditor->debtor edges.
async fn settle_remaining_netted_guarantees_for_cycle<C: sea_orm::ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> ServiceResult<u64> {
    let guarantees = repo::list_netted_guarantees_for_cycle_on(conn, cycle_id).await?;
    if guarantees.is_empty() {
        return Ok(0);
    }
    let changed = repo::transition_all_netted_guarantees_for_cycle_on(
        conn,
        cycle_id,
        GuaranteeSettlementStatus::Settled,
        now,
    )
    .await?;
    if changed > 0 {
        for guarantee in &guarantees {
            repo::release_locked_collateral_for_guarantee_on(conn, guarantee).await?;
        }
    }
    Ok(changed)
}

fn map_transaction_error(err: sea_orm::TransactionError<ServiceError>) -> ServiceError {
    match err {
        sea_orm::TransactionError::Transaction(inner) => inner,
        sea_orm::TransactionError::Connection(err) => {
            crate::error::PersistDbError::DatabaseFailure(err).into()
        }
    }
}
