use crate::ethereum::event_data::StoredEventData;
use crate::metrics::EventTxStatus;
use crate::metrics::misc::record_task_time;
use crate::{
    config::EthereumConfig,
    error::{BlockchainListenerError, PersistDbError},
    ethereum::{contract::*, event_handler::EthereumEventHandler},
    persist::{PersistCtx, repo},
    scheduler::{Task, async_trait},
};
use alloy::hex::FromHexError;
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::DynProvider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::{StreamExt, stream};
use log::{error, info, warn};
use metrics_4mica::measure;
use serde_json;
use std::sync::Arc;
use std::time::Duration;

/// Max in-loop retries for a *retryable* handler failure before the scan is aborted and the range
/// is retried on the next tick. Deterministic failures are never retried; they are dead-lettered.
const MAX_HANDLER_RETRIES: usize = 5;
const RETRY_BASE_DELAY_MS: u64 = 200;

pub struct EthereumEventScanner {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    provider: DynProvider,
    handler: Arc<dyn EthereumEventHandler>,
}

struct ScanArgs<P>
where
    P: alloy::providers::Provider + 'static,
{
    provider: P,
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    handler: Arc<dyn EthereumEventHandler>,
}

#[async_trait]
impl Task for EthereumEventScanner {
    fn cron_pattern(&self) -> String {
        self.config.event_scanner_cron.clone()
    }

    #[measure(record_task_time, name = "scan_events")]
    async fn run(&self) -> anyhow::Result<()> {
        Self::scan_events(ScanArgs {
            provider: self.provider.clone(),
            config: self.config.clone(),
            persist_ctx: self.persist_ctx.clone(),
            handler: self.handler.clone(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("Event scan failed: {e}"))
    }
}

impl EthereumEventScanner {
    pub fn new(
        config: EthereumConfig,
        persist_ctx: PersistCtx,
        provider: DynProvider,
        handler: Arc<dyn EthereumEventHandler>,
    ) -> Self {
        Self {
            config,
            persist_ctx,
            provider,
            handler,
        }
    }

    async fn scan_events<P>(args: ScanArgs<P>) -> Result<(), BlockchainListenerError>
    where
        P: alloy::providers::Provider + 'static,
    {
        let ScanArgs {
            provider,
            config,
            persist_ctx,
            handler,
        } = args;
        let max_log_block_range = config.max_log_block_range;

        let core_address: Address = config
            .contract_address
            .parse()
            .map_err(|e: FromHexError| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
        let clearing_house_address: Address = config
            .clearing_house_address
            .parse()
            .map_err(|e: FromHexError| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
        let addresses = if clearing_house_address == Address::ZERO {
            vec![core_address]
        } else {
            vec![core_address, clearing_house_address]
        };

        let base_filter = Filter::new()
            .address(addresses.clone())
            .events(all_event_signatures());

        let confirmed_head = match Self::confirmed_head(&provider, &config).await {
            Ok(Some(head)) => head,
            Ok(None) => {
                warn!("Confirmed head unavailable; skipping scan");
                return Ok(());
            }
            Err(e) => {
                error!("Failed to resolve confirmed head: {e}");
                return Err(e);
            }
        };

        let cursor = repo::get_blockchain_event_cursor(&persist_ctx, config.chain_id).await?;

        let start_block = match cursor.as_ref() {
            Some(cursor) => (cursor.last_confirmed_block_number as u64).saturating_add(1),
            None => confirmed_head.saturating_sub(config.initial_event_scan_lookback_blocks),
        };

        if let Some(cursor_model) = cursor.as_ref() {
            match Self::maybe_handle_reorg(&provider, &persist_ctx, config.chain_id, cursor_model)
                .await
            {
                Ok(()) => (),
                Err(e) => {
                    warn!("{e}");
                    return Err(e);
                }
            }
        }

        if start_block > confirmed_head {
            return Ok(());
        }

        info!(
            "Fetching confirmed logs from block {start_block} to {confirmed_head} for addresses {addresses:?}"
        );

        let logs = Self::fetch_logs_chunked(
            &provider,
            &base_filter,
            start_block,
            confirmed_head,
            &addresses,
            max_log_block_range,
        )
        .await?;

        if !logs.is_empty() {
            info!("Fetched {} confirmed log(s)", logs.len());
        }

        let mut logs = logs;
        logs.sort_by(|a, b| {
            let block_cmp = a.block_number.cmp(&b.block_number);
            if block_cmp == std::cmp::Ordering::Equal {
                a.log_index.cmp(&b.log_index)
            } else {
                block_cmp
            }
        });

        let confirmed_head_hash = Self::store_block_hashes(
            &provider,
            &persist_ctx,
            config.chain_id,
            start_block,
            confirmed_head,
        )
        .await?;

        let mut log_stream = stream::iter(logs);
        Self::process_events(&handler, &persist_ctx, config.chain_id, &mut log_stream).await?;

        repo::upsert_blockchain_event_cursor(
            &persist_ctx,
            config.chain_id,
            confirmed_head,
            confirmed_head_hash,
        )
        .await?;

        crate::metrics::record_scanned_event_tx_block(confirmed_head);

        // The cursor advanced and all events in range were applied, so the cached on-chain
        // withdrawalGracePeriod now reflects chain state up to this head. Record liveness so the
        // settlement-timing invariant can detect a wedged scanner and stop trusting a stale grace.
        handler.note_scan_progress();

        Ok(())
    }

    async fn fetch_logs_chunked(
        provider: &impl alloy::providers::Provider,
        base_filter: &Filter,
        start_block: u64,
        end_block: u64,
        addresses: &[Address],
        max_log_block_range: u64,
    ) -> Result<Vec<Log>, BlockchainListenerError> {
        let mut all_logs = Vec::new();
        let mut chunk_start = start_block;

        while chunk_start <= end_block {
            let chunk_end =
                end_block.min(chunk_start.saturating_add(max_log_block_range.saturating_sub(1)));
            let filter = base_filter
                .clone()
                .from_block(chunk_start)
                .to_block(BlockNumberOrTag::Number(chunk_end));

            info!(
                "Fetching confirmed logs chunk from block {chunk_start} to {chunk_end} for addresses {addresses:?}"
            );

            let chunk_logs = provider.get_logs(&filter).await.map_err(|e| {
                error!(
                    "Failed to fetch confirmed logs chunk from block {chunk_start} to {chunk_end}: {e}"
                );
                BlockchainListenerError::Other(anyhow::anyhow!(e))
            })?;

            if !chunk_logs.is_empty() {
                info!(
                    "Fetched {} confirmed log(s) in chunk {chunk_start}-{chunk_end}",
                    chunk_logs.len()
                );
            }

            all_logs.extend(chunk_logs);
            if chunk_end == end_block {
                break;
            }
            chunk_start = chunk_end.saturating_add(1);
        }

        Ok(all_logs)
    }

    async fn confirmed_head(
        provider: &impl alloy::providers::Provider,
        config: &EthereumConfig,
    ) -> Result<Option<u64>, BlockchainListenerError> {
        let head = match config.confirmation_mode()? {
            crate::config::ConfirmationMode::Depth => {
                let latest = provider
                    .get_block_number()
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                Some(latest.saturating_sub(config.number_of_blocks_to_confirm))
            }
            crate::config::ConfirmationMode::Safe => {
                let block = provider
                    .get_block_by_number(BlockNumberOrTag::Safe)
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                block.map(|b| b.header.number)
            }
            crate::config::ConfirmationMode::Finalized => {
                let block = provider
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                block.map(|b| b.header.number)
            }
        };

        if let Some(head) = head {
            crate::metrics::record_blockchain_safe_head(head);
        }
        Ok(head)
    }

    async fn process_events(
        handler: &Arc<dyn EthereumEventHandler>,
        persist_ctx: &PersistCtx,
        chain_id: u64,
        stream: &mut (impl futures_util::Stream<Item = Log> + Unpin),
    ) -> Result<(), BlockchainListenerError> {
        while let Some(log) = stream.next().await {
            let Some(block_number) = log.block_number else {
                warn!("Log has no block number, skipping...");
                continue;
            };
            let Some(log_index) = log.log_index else {
                warn!("Log has no log index, skipping...");
                continue;
            };

            let Some(signature) = log.topic0().map(|hash| format!("{:x}", hash)) else {
                warn!("Log has no signature, skipping...");
                continue;
            };
            let Some(block_hash) = log.block_hash else {
                warn!("Log has no block hash, skipping...");
                continue;
            };
            let Some(tx_hash) = log.transaction_hash else {
                warn!("Log has no tx hash, skipping...");
                continue;
            };

            let event_data: StoredEventData = (&log).try_into()?;
            let data_json = serde_json::to_string(&event_data)
                .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;

            let block_hash_str = format!("{:#x}", block_hash);
            let tx_hash_str = format!("{:#x}", tx_hash);
            let address_str = format!("{:#x}", log.address());

            info!(
                "Storing blockchain event: {signature} at block {block_number} with log index {log_index}"
            );

            // A row that is already stored (including one previously dead-lettered) is skipped
            // here, so its handler never re-runs — this is what makes a dead-lettered poison event
            // stay skipped and the scanner advance past it (4MCA-M04).
            match repo::store_blockchain_event(
                persist_ctx,
                chain_id,
                &signature,
                block_number,
                &block_hash_str,
                &tx_hash_str,
                log_index,
                &address_str,
                &data_json,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    info!(
                        "Blockchain event already stored: {signature} at block {block_number} with log index {log_index}, skipping..."
                    );
                    continue;
                }
                Err(e) => {
                    error!("Failed to store blockchain event: {e}");
                    return Err(e.into());
                }
            }

            crate::metrics::record_processed_event_tx(
                EventTxStatus::Confirmed,
                &signature,
                crate::metrics::secs_since_unix(log.block_timestamp),
            );

            let mut attempts = 0;
            loop {
                let result = match log.topic0() {
                    Some(&CollateralDeposited::SIGNATURE_HASH) => {
                        handler.handle_collateral_deposited(log.clone()).await
                    }
                    Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                        handler.handle_collateral_withdrawn(log.clone()).await
                    }
                    Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                        handler.handle_withdrawal_requested(log.clone()).await
                    }
                    Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                        handler.handle_withdrawal_canceled(log.clone()).await
                    }
                    Some(&CycleCommitted::SIGNATURE_HASH) => {
                        handler.handle_cycle_committed(log.clone()).await
                    }
                    Some(&DebtorPaid::SIGNATURE_HASH) => {
                        handler.handle_debtor_paid(log.clone()).await
                    }
                    Some(&CreditorClaimed::SIGNATURE_HASH) => {
                        handler.handle_creditor_claimed(log.clone()).await
                    }
                    Some(&DebtorDefaulted::SIGNATURE_HASH) => {
                        handler.handle_debtor_defaulted(log.clone()).await
                    }
                    Some(&CycleFinalized::SIGNATURE_HASH) => {
                        handler.handle_cycle_finalized(log.clone()).await
                    }
                    Some(&SettlementSkipped::SIGNATURE_HASH) => {
                        handler.handle_settlement_skipped(log.clone()).await
                    }
                    Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "WithdrawalGracePeriodUpdated")
                            .await
                    }
                    Some(&VerificationKeyUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "VerificationKeyUpdated")
                            .await
                    }
                    Some(&GuaranteeVersionUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "GuaranteeVersionUpdated")
                            .await
                    }
                    _ => handler.handle_unknown_event(log.clone()).await,
                };

                match result {
                    Ok(()) => break,
                    Err(e) => match classify_handler_failure(&e, attempts) {
                        // Transient failure with retries left: back off and retry in place.
                        HandlerFailureAction::Retry => {
                            attempts += 1;
                            let delay = Duration::from_millis(
                                RETRY_BASE_DELAY_MS.saturating_mul(attempts as u64),
                            );
                            warn!(
                                "Event handler error (attempt {attempts}/{MAX_HANDLER_RETRIES}): {e}. Retrying in {delay:?}..."
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        // Retryable but retries exhausted: a sustained infra outage (DB/RPC down),
                        // not a property of this event. Abort the batch and let the next scan retry
                        // the whole range; delete the stored row so the handler runs again then (a
                        // kept row would be skipped as already-stored).
                        HandlerFailureAction::Abort => {
                            error!(
                                "Event handler exhausted {MAX_HANDLER_RETRIES} retries; aborting scan: {e}"
                            );
                            Self::delete_stored_event_best_effort(
                                persist_ctx,
                                chain_id,
                                block_number,
                                &block_hash_str,
                                log_index,
                            )
                            .await;
                            return Err(e);
                        }
                        // Deterministic failure: dead-letter and skip so a single un-handleable
                        // event cannot wedge the whole pipeline. Keep the (now-marked)
                        // row so the next scan skips it instead of re-running the doomed handler.
                        HandlerFailureAction::DeadLetter => {
                            error!(
                                "Dead-lettering un-handleable event {signature} at block {block_number} \
                                 log_index {log_index}: {e}"
                            );
                            match repo::mark_blockchain_event_dead_lettered(
                                persist_ctx,
                                chain_id,
                                block_number,
                                &block_hash_str,
                                log_index,
                                attempts as i32,
                                &e.to_string(),
                            )
                            .await
                            {
                                Ok(()) => {
                                    crate::metrics::record_dead_lettered_event(&signature);
                                    break;
                                }
                                Err(mark_err) => {
                                    // Could not persist the dead-letter (DB issue). Delete the row
                                    // so the event is reprocessed next scan rather than silently
                                    // skipped-but-unrecorded, then abort.
                                    error!(
                                        "Failed to record dead-letter for {signature}: {mark_err}"
                                    );
                                    Self::delete_stored_event_best_effort(
                                        persist_ctx,
                                        chain_id,
                                        block_number,
                                        &block_hash_str,
                                        log_index,
                                    )
                                    .await;
                                    return Err(e);
                                }
                            }
                        }
                    },
                }
            }
        }

        Ok(())
    }

    async fn delete_stored_event_best_effort(
        persist_ctx: &PersistCtx,
        chain_id: u64,
        block_number: u64,
        block_hash: &str,
        log_index: u64,
    ) {
        if let Err(err) = repo::delete_blockchain_event(
            persist_ctx,
            chain_id,
            block_number,
            block_hash,
            log_index,
        )
        .await
        {
            error!("Failed to delete blockchain event: {err}");
        }
    }

    async fn block_hash_at(
        provider: &impl alloy::providers::Provider,
        block_number: u64,
    ) -> Result<Option<String>, BlockchainListenerError> {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await
            .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
        Ok(block.map(|b| format!("{:#x}", b.hash())))
    }

    async fn store_block_hashes(
        provider: &impl alloy::providers::Provider,
        persist_ctx: &PersistCtx,
        chain_id: u64,
        start_block: u64,
        end_block: u64,
    ) -> Result<Option<String>, BlockchainListenerError> {
        let mut confirmed_head_hash = None;
        for number in start_block..=end_block {
            let block = provider
                .get_block_by_number(BlockNumberOrTag::Number(number))
                .await
                .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
            let Some(block) = block else {
                continue;
            };
            let hash = format!("{:#x}", block.hash());
            repo::upsert_blockchain_block(persist_ctx, chain_id, number, &hash).await?;
            if number == end_block {
                confirmed_head_hash = Some(hash);
            }
        }
        Ok(confirmed_head_hash)
    }

    async fn maybe_handle_reorg(
        provider: &impl alloy::providers::Provider,
        persist_ctx: &PersistCtx,
        chain_id: u64,
        cursor: &entities::blockchain_event_cursor::Model,
    ) -> Result<(), BlockchainListenerError> {
        let Some(stored_hash) = cursor.last_confirmed_block_hash.as_deref() else {
            return Ok(());
        };
        let chain_hash =
            Self::block_hash_at(provider, cursor.last_confirmed_block_number as u64).await?;
        if chain_hash.as_deref() == Some(stored_hash) {
            return Ok(());
        }

        repo::delete_blockchain_event_cursor(persist_ctx, chain_id).await?;
        Err(BlockchainListenerError::Other(anyhow::anyhow!(
            "Finalized block hash mismatch at {} (stored {}, chain {:?}); deleting cursor to rescan in the next run",
            cursor.last_confirmed_block_number,
            stored_hash,
            chain_hash
        )))
    }
}

fn is_retryable_handler_error(err: &BlockchainListenerError) -> bool {
    matches!(
        err,
        BlockchainListenerError::Db(PersistDbError::UserBalanceLockConflict { .. })
            | BlockchainListenerError::Db(PersistDbError::DatabaseFailure(_))
            | BlockchainListenerError::DatabaseFailure(_)
            | BlockchainListenerError::RpcFailure(_)
    )
}

/// What the scanner should do with a failed event handler (4MCA-M04).
#[derive(Debug, PartialEq, Eq)]
enum HandlerFailureAction {
    /// Transient failure with retries remaining — back off and retry in place.
    Retry,
    /// Transient failure whose retries are exhausted — a sustained infra outage, not a property of
    /// the event. Abort the batch and retry the whole range next scan.
    Abort,
    /// Deterministic failure that will fail identically on every rescan — dead-letter it and skip so
    /// one poison event cannot halt all indexing.
    DeadLetter,
}

/// Decide how to handle a failed event handler: retryable errors are retried up to
/// `MAX_HANDLER_RETRIES` and then abort the scan; deterministic errors are dead-lettered
/// immediately so they can never wedge the pipeline.
fn classify_handler_failure(
    err: &BlockchainListenerError,
    attempts: usize,
) -> HandlerFailureAction {
    if is_retryable_handler_error(err) {
        if attempts < MAX_HANDLER_RETRIES {
            HandlerFailureAction::Retry
        } else {
            HandlerFailureAction::Abort
        }
    } else {
        HandlerFailureAction::DeadLetter
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HandlerFailureAction, MAX_HANDLER_RETRIES, classify_handler_failure,
        is_retryable_handler_error,
    };
    use crate::error::{BlockchainListenerError, PersistDbError, ServiceError};

    #[test]
    fn rpc_failures_are_retryable() {
        assert!(is_retryable_handler_error(
            &BlockchainListenerError::RpcFailure("provider timeout".into())
        ));
    }

    #[test]
    fn transient_db_failures_are_retryable() {
        assert!(is_retryable_handler_error(
            &BlockchainListenerError::DatabaseFailure(sea_orm::DbErr::Custom(
                "connection reset".into()
            ))
        ));
        assert!(is_retryable_handler_error(&BlockchainListenerError::Db(
            PersistDbError::UserBalanceLockConflict {
                user: "0xabc".into(),
                asset_address: "0xdef".into(),
                expected_version: 1,
            }
        )));
    }

    #[test]
    fn deterministic_errors_are_not_retryable() {
        assert!(!is_retryable_handler_error(
            &BlockchainListenerError::EventHandlerError("collateral underflow".into())
        ));
        assert!(!is_retryable_handler_error(
            &BlockchainListenerError::UserNotFound("0xabc".into())
        ));
    }

    #[test]
    fn settlement_optimistic_lock_conflict_is_retryable() {
        let err = BlockchainListenerError::from(ServiceError::OptimisticLockConflict);
        assert!(is_retryable_handler_error(&err));
    }

    #[test]
    fn settlement_db_failure_is_retryable() {
        let err = BlockchainListenerError::from(ServiceError::Db(PersistDbError::DatabaseFailure(
            sea_orm::DbErr::Custom("connection reset".into()),
        )));
        assert!(is_retryable_handler_error(&err));
    }

    #[test]
    fn settlement_domain_errors_are_not_retryable() {
        let invariant = BlockchainListenerError::from(ServiceError::Db(
            PersistDbError::InvariantViolation("leaf sum mismatch".into()),
        ));
        assert!(!is_retryable_handler_error(&invariant));

        let invalid = BlockchainListenerError::from(ServiceError::InvalidParams("bad".into()));
        assert!(!is_retryable_handler_error(&invalid));
    }

    // The terminal-branch decision: which of retry / abort / dead-letter the scanner takes for a
    // given handler failure and retry count (4MCA-M04).

    #[test]
    fn retryable_error_retries_until_exhausted_then_aborts() {
        let err = BlockchainListenerError::RpcFailure("provider timeout".into());
        // Retries remain -> retry in place.
        assert_eq!(
            classify_handler_failure(&err, 0),
            HandlerFailureAction::Retry
        );
        assert_eq!(
            classify_handler_failure(&err, MAX_HANDLER_RETRIES - 1),
            HandlerFailureAction::Retry
        );
        // Retries exhausted -> abort the batch (sustained outage), never dead-letter.
        assert_eq!(
            classify_handler_failure(&err, MAX_HANDLER_RETRIES),
            HandlerFailureAction::Abort
        );
    }

    #[test]
    fn deterministic_error_is_dead_lettered_without_retrying() {
        // A deterministic failure is dead-lettered immediately, regardless of the attempt count,
        // so a poison event can never wedge the pipeline.
        let err = BlockchainListenerError::EventHandlerError("collateral underflow".into());
        assert_eq!(
            classify_handler_failure(&err, 0),
            HandlerFailureAction::DeadLetter
        );
        assert_eq!(
            classify_handler_failure(&err, MAX_HANDLER_RETRIES),
            HandlerFailureAction::DeadLetter
        );
    }
}
