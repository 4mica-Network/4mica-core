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

        let address: Address = config
            .contract_address
            .parse()
            .map_err(|e: FromHexError| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;

        let base_filter = Filter::new()
            .address(address)
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

        let filter = base_filter
            .clone()
            .from_block(start_block)
            .to_block(BlockNumberOrTag::Number(confirmed_head));

        info!(
            "Fetching confirmed logs from block {start_block} to {confirmed_head} for address {address:?}"
        );

        let logs = provider.get_logs(&filter).await.map_err(|e| {
            error!("Failed to fetch confirmed logs: {e}");
            BlockchainListenerError::Other(anyhow::anyhow!(e))
        })?;

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

        Ok(())
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
                    .full()
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                block.map(|b| b.header.number)
            }
            crate::config::ConfirmationMode::Finalized => {
                if config.finalized_head_depth > 0 {
                    let latest = provider
                        .get_block_number()
                        .await
                        .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                    Some(latest.saturating_sub(config.finalized_head_depth))
                } else {
                    let block = provider
                        .get_block_by_number(BlockNumberOrTag::Finalized)
                        .full()
                        .await
                        .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                    block.map(|b| b.header.number)
                }
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
        const MAX_HANDLER_RETRIES: usize = 5;
        const RETRY_BASE_DELAY_MS: u64 = 200;

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

            let inserted = match repo::store_blockchain_event(
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
                Ok(inserted) => {
                    if !inserted {
                        info!(
                            "Blockchain event already stored: {signature} at block {block_number} with log index {log_index}, skipping..."
                        );
                        continue;
                    }
                    true
                }
                Err(e) => {
                    error!("Failed to store blockchain event: {e}");
                    return Err(e.into());
                }
            };

            crate::metrics::record_event_status_change(
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
                    Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                        handler.handle_recipient_remunerated(log.clone()).await
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
                    Some(&PaymentRecorded::SIGNATURE_HASH) => {
                        handler.handle_payment_recorded(log.clone()).await
                    }
                    Some(&TabPaid::SIGNATURE_HASH) => handler.handle_tab_paid(log.clone()).await,
                    Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "WithdrawalGracePeriodUpdated")
                            .await
                    }
                    Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "RemunerationGracePeriodUpdated")
                            .await
                    }
                    Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "TabExpirationTimeUpdated")
                            .await
                    }
                    Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => {
                        handler
                            .handle_admin_event(log.clone(), "SynchronizationDelayUpdated")
                            .await
                    }
                    _ => handler.handle_unknown_event(log.clone()).await,
                };

                match result {
                    Ok(()) => break,
                    Err(e) => {
                        if attempts < MAX_HANDLER_RETRIES && is_retryable_handler_error(&e) {
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

                        error!("Event handler error: {e}");
                        if inserted
                            && let Err(err) = repo::delete_blockchain_event(
                                persist_ctx,
                                chain_id,
                                block_number,
                                &block_hash_str,
                                log_index,
                            )
                            .await
                        {
                            error!("Failed to delete blockchain event: {err}");
                        }

                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn block_hash_at(
        provider: &impl alloy::providers::Provider,
        block_number: u64,
    ) -> Result<Option<String>, BlockchainListenerError> {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
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
                .full()
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
    )
}
