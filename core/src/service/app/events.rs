//! Chain event handler: decodes scanner logs and dispatches them to the domain services.

use std::sync::Arc;

use alloy::rpc::types::Log;
use alloy_primitives::Address;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use metrics_4mica::measure;

use crate::error::BlockchainListenerError;
use crate::ethereum::{contract::*, event_data::EventMeta, event_handler::EthereumEventHandler};
use crate::metrics::misc::record_event_handler_time;
use crate::persist::repo;
use crate::service::ctx::Ctx;
use crate::service::domain::clearing::ClearingService;

pub struct EventHandlerService {
    ctx: Arc<Ctx>,
    clearing: Arc<ClearingService>,
}

impl EventHandlerService {
    pub fn new(ctx: Arc<Ctx>, clearing: Arc<ClearingService>) -> Self {
        Self { ctx, clearing }
    }
}

#[async_trait]
impl EthereumEventHandler for EventHandlerService {
    fn note_scan_progress(&self) {
        self.ctx.record_scan_progress();
    }

    #[measure(record_event_handler_time, name = "collateral_deposited")]
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited {
            user,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Deposit by {user:?} of {amount}, asset={asset}");

        let block_number = block_number_from_log(&log)?;
        self.sync_balance_from_chain(user, asset, block_number)
            .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "collateral_withdrawn")]
    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn {
            user,
            asset,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Collateral withdrawn by {user:?}: {amount}");

        let meta = self.event_meta_from_log(&log)?;
        let block_number = block_number_from_log(&log)?;
        if self.ctx.chain.stablecoin_a_token(asset).await?.is_some() {
            repo::mark_withdrawal_executed_with_event(
                &self.ctx.persist,
                user,
                asset,
                amount,
                Some(&meta),
            )
            .await?;
            self.sync_balance_from_chain(user, asset, block_number)
                .await?;
        } else {
            repo::finalize_withdrawal_with_event(
                &self.ctx.persist,
                user,
                asset,
                amount,
                Some(&meta),
            )
            .await?;
            self.sync_balance_from_chain(user, asset, block_number)
                .await?;
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_requested")]
    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            asset,
            when,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Withdrawal requested: {user:?}, asset={asset}, when={when}, amount={amount}");

        let meta = self.event_meta_from_log(&log)?;
        repo::request_withdrawal_with_event(
            &self.ctx.persist,
            user,
            asset,
            when.to(),
            amount,
            Some(&meta),
        )
        .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_canceled")]
    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user, asset, .. } = *log.log_decode()?.data();
        info!("Withdrawal canceled by {user:?}, asset={asset}");

        let meta = self.event_meta_from_log(&log)?;
        repo::cancel_withdrawal_with_event(&self.ctx.persist, user, asset, Some(&meta)).await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "cycle_committed")]
    async fn handle_cycle_committed(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CycleCommitted { cycleId, .. } = *log.log_decode()?.data();
        let tx_hash = tx_hash_from_log(&log)?;
        self.clearing
            .process_cycle_committed(cycleId, &tx_hash)
            .await
            .map_err(BlockchainListenerError::from)
    }

    #[measure(record_event_handler_time, name = "debtor_paid")]
    async fn handle_debtor_paid(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let DebtorPaid {
            cycleId, debtor, ..
        } = *log.log_decode()?.data();
        let tx_hash = tx_hash_from_log(&log)?;
        self.clearing
            .process_paid_debtor(cycleId, debtor, &tx_hash)
            .await
            .map_err(BlockchainListenerError::from)
    }

    #[measure(record_event_handler_time, name = "creditor_claimed")]
    async fn handle_creditor_claimed(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CreditorClaimed {
            cycleId,
            creditor,
            asset,
            ..
        } = *log.log_decode()?.data();

        let meta = self.event_meta_from_log(&log)?;
        let block_number = block_number_from_log(&log)?;
        self.clearing
            .process_credit_claim(cycleId, creditor, meta)
            .await
            .map_err(BlockchainListenerError::from)?;
        // Reconcile the creditor's total from chain
        // after the settlement transaction has released its locked collateral.
        self.sync_balance_from_chain(creditor, asset, block_number)
            .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "debtor_defaulted")]
    async fn handle_debtor_defaulted(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let DebtorDefaulted {
            cycleId,
            debtor,
            asset,
            ..
        } = *log.log_decode()?.data();

        let meta = self.event_meta_from_log(&log)?;
        let block_number = block_number_from_log(&log)?;
        self.clearing
            .process_defaulted_debtor(cycleId, debtor, meta)
            .await
            .map_err(BlockchainListenerError::from)?;
        // Reconcile the debtor's total from chain
        // after the seizure has been mirrored and its locked collateral released.
        self.sync_balance_from_chain(debtor, asset, block_number)
            .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "cycle_finalized")]
    async fn handle_cycle_finalized(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CycleFinalized { cycleId, .. } = *log.log_decode()?.data();
        self.clearing
            .process_cycle_finalized(cycleId)
            .await
            .map_err(BlockchainListenerError::from)
    }

    #[measure(record_event_handler_time, name = "cycle_shortfall")]
    async fn handle_cycle_shortfall(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CycleShortfall { cycleId, .. } = *log.log_decode()?.data();
        self.clearing
            .process_cycle_shortfall(cycleId)
            .await
            .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    /// Surface a participant the ClearingHouse skipped during settlement, classified by reason so
    /// the operator can tell a benign skip from a transient one from a genuine bug. This is
    /// observability only: it never mutates domain state and always succeeds, so a skip can never
    /// wedge the scanner. Recovery of transient skips is handled by the settlement driver, which
    /// keeps an under-funded cycle in the payment window and re-submits the seize each tick.
    #[measure(record_event_handler_time, name = "settlement_skipped")]
    async fn handle_settlement_skipped(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let SettlementSkipped {
            cycleId,
            participant,
            reason,
        } = log.log_decode::<SettlementSkipped>()?.data().clone();
        let cycle_id = format!("{cycleId:#x}");

        match reason.as_str() {
            // The participant was already paid/defaulted in an earlier batch; expected on retries.
            "already resolved" => {
                debug!(
                    "SettlementSkipped (benign): cycle {cycle_id} participant {participant} already resolved"
                );
            }
            // The operator's Merkle proof did not verify against the committed root. This is
            // deterministic — re-submitting the same proof fails forever — and signals an off-chain
            // proof-generation bug or off-chain/on-chain netting divergence. It needs operator
            // action (regenerate the proof / reconcile the commit), not a blind retry.
            "invalid proof" => {
                error!(
                    "SettlementSkipped (INVALID PROOF): cycle {cycle_id} participant {participant}; \
                     proof did not verify against the committed root — this is deterministic and will \
                     not self-heal. Investigate proof generation / netting divergence."
                );
            }
            // Transient/expected: the seize or credit reverted, or Aave was momentarily illiquid.
            // The driver keeps the cycle under-funded and re-submits on the next tick.
            "seize failed" | "insufficient liquidity" | "credit failed" => {
                warn!(
                    "SettlementSkipped (transient): cycle {cycle_id} participant {participant} reason '{reason}'; \
                     settlement driver will re-attempt while the cycle stays under-funded"
                );
            }
            other => {
                warn!(
                    "SettlementSkipped (unrecognized reason): cycle {cycle_id} participant {participant} reason '{other}'"
                );
            }
        }

        Ok(())
    }

    #[measure(record_event_handler_time, name = "admin_event")]
    async fn handle_admin_event(
        &self,
        log: Log,
        event_name: &str,
    ) -> Result<(), BlockchainListenerError> {
        match event_name {
            "WithdrawalGracePeriodUpdated" => {
                let WithdrawalGracePeriodUpdated {
                    newGracePeriod: new_grace_period,
                    ..
                } = *log.log_decode()?.data();
                let new_grace_period = new_grace_period.to();
                info!("WithdrawalGracePeriodUpdated: {}s", new_grace_period);
                self.ctx.set_withdrawal_grace_period(new_grace_period);

                // Surface a governance change that breaks the
                // delayed-withdrawal solvency invariant; health checks will report it.
                if let Err(err) = self.ctx.check_settlement_timing_invariant() {
                    warn!(
                        "settlement timing invariant violated after grace-period update: {err:#}"
                    );
                }
            }
            "VerificationKeyUpdated" => {
                let ev = log.log_decode::<VerificationKeyUpdated>()?;
                info!("{:?}", ev);
            }
            "GuaranteeVersionUpdated" => {
                let ev = log.log_decode::<GuaranteeVersionUpdated>()?;
                info!("{:?}", ev);
            }
            _ => {
                info!("Unknown simple event: {}", event_name);
            }
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "unknown")]
    async fn handle_unknown_event(&self, log: Log) -> Result<(), BlockchainListenerError> {
        info!("Unknown event: {:?}", log);
        Ok(())
    }
}

fn tx_hash_from_log(log: &Log) -> Result<String, BlockchainListenerError> {
    log.transaction_hash
        .map(|hash| format!("{hash:#x}"))
        .ok_or_else(|| {
            BlockchainListenerError::EventHandlerError("log missing tx_hash".to_string())
        })
}

fn block_number_from_log(log: &Log) -> Result<u64, BlockchainListenerError> {
    log.block_number.ok_or_else(|| {
        BlockchainListenerError::EventHandlerError("log missing block_number".to_string())
    })
}

impl EventHandlerService {
    async fn sync_balance_from_chain(
        &self,
        user: Address,
        asset: Address,
        block_number: u64,
    ) -> Result<(), BlockchainListenerError> {
        let Some(on_chain_total) = self
            .ctx
            .chain
            .guaranteeable_collateral(user, asset, block_number)
            .await?
        else {
            // Not a supported collateral asset; nothing to reconcile.
            return Ok(());
        };

        // A deposit may be a user's first interaction, so ensure the user row exists before writing
        // its balance (sync is the sole balance writer on the deposit path now).
        repo::ensure_user_exists_on(self.ctx.db(), user).await?;

        repo::sync_user_asset_total(&self.ctx.persist, user, asset, on_chain_total).await?;

        Ok(())
    }

    fn event_meta_from_log(&self, log: &Log) -> Result<EventMeta, BlockchainListenerError> {
        let chain_id = self.ctx.config.ethereum_config.chain_id;
        let Some(block_hash) = log.block_hash else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing block_hash".to_owned(),
            ));
        };
        let Some(tx_hash) = log.transaction_hash else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing tx_hash".to_owned(),
            ));
        };
        let Some(log_index) = log.log_index else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing log_index".to_owned(),
            ));
        };

        Ok(EventMeta {
            chain_id,
            block_hash: format!("{:#x}", block_hash),
            tx_hash: format!("{:#x}", tx_hash),
            log_index,
        })
    }
}
