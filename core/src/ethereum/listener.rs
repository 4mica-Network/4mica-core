use crate::ethereum::event_data::StoredEventData;
use crate::{
    config::EthereumConfig,
    error::{BlockchainListenerError, PersistDbError},
    ethereum::{contract::*, event_handler::EthereumEventHandler},
    persist::{PersistCtx, repo},
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::DynProvider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::{StreamExt, stream};
use log::{error, info, warn};
use serde_json;
use std::{sync::Arc, time::Duration};
use tokio::{self, sync::oneshot, task::JoinHandle};

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    provider: DynProvider,
    handler: Arc<dyn EthereumEventHandler>,
}

struct ListenLoopArgs<P>
where
    P: alloy::providers::Provider + 'static,
{
    provider: P,
    base_filter: Filter,
    address: Address,
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    handler: Arc<dyn EthereumEventHandler>,
    ready_tx: Option<oneshot::Sender<()>>,
    initial_backfill_blocks: u64,
}

impl EthereumListener {
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

    pub async fn run(
        &self,
        ready_tx: Option<oneshot::Sender<()>>,
    ) -> Result<JoinHandle<()>, BlockchainListenerError> {
        let address: Address = self
            .config
            .contract_address
            .parse()
            .map_err(anyhow::Error::from)?;

        let base_filter = Filter::new()
            .address(address)
            .events(all_event_signatures());

        let persist_ctx = self.persist_ctx.clone();
        let config = self.config.clone();
        let initial_backfill_blocks = self
            .config
            .number_of_blocks_to_confirm
            .saturating_add(self.config.number_of_pending_blocks);
        let handle = tokio::spawn(Self::listen_loop(ListenLoopArgs {
            provider: self.provider.clone(),
            base_filter,
            address,
            config,
            persist_ctx,
            handler: self.handler.clone(),
            ready_tx,
            initial_backfill_blocks,
        }));
        Ok(handle)
    }

    async fn listen_loop<P>(args: ListenLoopArgs<P>)
    where
        P: alloy::providers::Provider + 'static,
    {
        let ListenLoopArgs {
            provider,
            base_filter,
            address,
            config,
            persist_ctx,
            handler,
            mut ready_tx,
            initial_backfill_blocks,
        } = args;
        let mut delay = Duration::from_secs(5);

        loop {
            let confirmed_head = match Self::confirmed_head(&provider, &config).await {
                Ok(Some(head)) => head,
                Ok(None) => {
                    warn!("Confirmed head unavailable; retrying in {delay:?}...");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(e) => {
                    error!("Failed to resolve confirmed head: {e}");
                    warn!("Restarting listener in {delay:?}...");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(300));
                    continue;
                }
            };

            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(());
                info!("Listener is ready and signaled readiness");
            }

            let cursor =
                match repo::get_blockchain_event_cursor(&persist_ctx, config.chain_id).await {
                    Ok(cursor) => cursor,
                    Err(e) => {
                        error!("Failed to get blockchain event cursor: {e}");
                        warn!("Restarting listener in {delay:?}...");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(300));
                        continue;
                    }
                };

            let mut start_block = match cursor.as_ref() {
                Some(cursor) => (cursor.last_confirmed_block_number as u64).saturating_add(1),
                None => confirmed_head.saturating_sub(initial_backfill_blocks),
            };

            if let Some(cursor_model) = cursor.as_ref() {
                match Self::maybe_handle_reorg(
                    &provider,
                    &persist_ctx,
                    config.chain_id,
                    cursor_model,
                )
                .await
                {
                    Ok(Some(new_start)) => start_block = new_start,
                    Ok(None) => {}
                    Err(e) => {
                        error!("Failed to handle reorg: {e}");
                        warn!("Restarting listener in {delay:?}...");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(300));
                        continue;
                    }
                }
            }

            if start_block > confirmed_head {
                tokio::time::sleep(delay).await;
                continue;
            }

            let filter = base_filter
                .clone()
                .from_block(start_block)
                .to_block(BlockNumberOrTag::Number(confirmed_head));

            info!(
                "Fetching confirmed logs from block {start_block} to {confirmed_head} for address {address:?}"
            );

            let logs = match provider.get_logs(&filter).await {
                Ok(logs) => {
                    if !logs.is_empty() {
                        info!("Fetched {} confirmed log(s)", logs.len());
                    }
                    logs
                }
                Err(e) => {
                    error!("Failed to fetch confirmed logs: {e}");
                    warn!("Restarting listener in {delay:?}...");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(300));
                    continue;
                }
            };

            let mut logs = logs;
            logs.sort_by(|a, b| {
                let block_cmp = a.block_number.cmp(&b.block_number);
                if block_cmp == std::cmp::Ordering::Equal {
                    a.log_index.cmp(&b.log_index)
                } else {
                    block_cmp
                }
            });

            let confirmed_head_hash = match Self::store_block_hashes(
                &provider,
                &persist_ctx,
                config.chain_id,
                start_block,
                confirmed_head,
            )
            .await
            {
                Ok(hash) => hash,
                Err(e) => {
                    error!("Failed to store block hashes: {e}");
                    warn!("Retrying listener in {delay:?}...");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(300));
                    continue;
                }
            };

            let mut log_stream = stream::iter(logs);
            if let Err(e) =
                Self::process_events(&handler, &persist_ctx, config.chain_id, &mut log_stream).await
            {
                error!("Event processing error: {e}");
                warn!("Retrying listener in {delay:?}...");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(300));
                continue;
            }

            if let Err(e) = repo::upsert_blockchain_event_cursor(
                &persist_ctx,
                config.chain_id,
                confirmed_head,
                confirmed_head_hash,
            )
            .await
            {
                error!("Failed to update blockchain event cursor: {e}");
                warn!("Retrying listener in {delay:?}...");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(300));
                continue;
            }

            delay = Duration::from_secs(5);
            tokio::time::sleep(delay).await;
        }
    }

    async fn confirmed_head(
        provider: &impl alloy::providers::Provider,
        config: &EthereumConfig,
    ) -> Result<Option<u64>, BlockchainListenerError> {
        match config.confirmation_mode()? {
            crate::config::ConfirmationMode::Depth => {
                let latest = provider
                    .get_block_number()
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                Ok(Some(
                    latest.saturating_sub(config.number_of_blocks_to_confirm),
                ))
            }
            crate::config::ConfirmationMode::Safe => {
                let block = provider
                    .get_block_by_number(BlockNumberOrTag::Safe)
                    .full()
                    .await
                    .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                Ok(block.map(|b| b.header.number))
            }
            crate::config::ConfirmationMode::Finalized => {
                if config.finalized_head_depth > 0 {
                    let latest = provider
                        .get_block_number()
                        .await
                        .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                    Ok(Some(latest.saturating_sub(config.finalized_head_depth)))
                } else {
                    let block = provider
                        .get_block_by_number(BlockNumberOrTag::Finalized)
                        .full()
                        .await
                        .map_err(|e| BlockchainListenerError::Other(anyhow::anyhow!(e)))?;
                    Ok(block.map(|b| b.header.number))
                }
            }
        }
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

            let event_data = Self::encode_event_data(&log)?;
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
                    _ => {
                        info!("Unknown log: {:?}", log);
                        Ok(())
                    }
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

        warn!("Event stream ended unexpectedly");
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
    ) -> Result<Option<u64>, BlockchainListenerError> {
        let Some(stored_hash) = cursor.last_confirmed_block_hash.as_deref() else {
            return Ok(None);
        };
        let chain_hash =
            Self::block_hash_at(provider, cursor.last_confirmed_block_number as u64).await?;
        if chain_hash.as_deref() == Some(stored_hash) {
            return Ok(None);
        }

        error!(
            "Finalized block hash mismatch at {} (stored {}, chain {:?}); refusing to mutate DB without rollback",
            cursor.last_confirmed_block_number, stored_hash, chain_hash
        );
        let _ = persist_ctx;
        let _ = chain_id;
        Err(BlockchainListenerError::EventHandlerError(
            "finalized reorg detected; rollback disabled".to_string(),
        ))
    }

    fn encode_event_data(log: &Log) -> Result<StoredEventData, BlockchainListenerError> {
        match log.topic0() {
            Some(&CollateralDeposited::SIGNATURE_HASH) => {
                let CollateralDeposited {
                    user,
                    asset,
                    amount,
                    ..
                } = *log.log_decode()?.data();
                Ok(StoredEventData::CollateralDeposited {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                let RecipientRemunerated {
                    tab_id,
                    asset,
                    amount,
                    ..
                } = *log.log_decode()?.data();
                Ok(StoredEventData::RecipientRemunerated {
                    tab_id: format!("{:#x}", tab_id),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                let CollateralWithdrawn {
                    user,
                    asset,
                    amount,
                    ..
                } = *log.log_decode()?.data();
                Ok(StoredEventData::CollateralWithdrawn {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                let WithdrawalRequested {
                    user,
                    asset,
                    when,
                    amount,
                    ..
                } = *log.log_decode()?.data();
                Ok(StoredEventData::WithdrawalRequested {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    when: when.to(),
                    amount: amount.to_string(),
                })
            }
            Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                let WithdrawalCanceled { user, asset, .. } = *log.log_decode()?.data();
                Ok(StoredEventData::WithdrawalCanceled {
                    user: user.to_string(),
                    asset: asset.to_string(),
                })
            }
            Some(&TabPaid::SIGNATURE_HASH) => {
                let TabPaid {
                    tab_id,
                    asset,
                    user,
                    recipient,
                    amount,
                    ..
                } = *log.log_decode()?.data();
                let tx_hash = log
                    .transaction_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_default();
                Ok(StoredEventData::TabPaid {
                    tab_id: format!("{:#x}", tab_id),
                    user: user.to_string(),
                    recipient: recipient.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                    tx_hash,
                })
            }
            Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "WithdrawalGracePeriodUpdated".to_string(),
            }),
            Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "RemunerationGracePeriodUpdated".to_string(),
            }),
            Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "TabExpirationTimeUpdated".to_string(),
            }),
            Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "SynchronizationDelayUpdated".to_string(),
            }),
            _ => Ok(StoredEventData::Unknown {
                name: "unknown".to_string(),
            }),
        }
    }
}

fn is_retryable_handler_error(err: &BlockchainListenerError) -> bool {
    matches!(
        err,
        BlockchainListenerError::Db(PersistDbError::OptimisticLockConflict { .. })
            | BlockchainListenerError::Db(PersistDbError::DatabaseFailure(_))
            | BlockchainListenerError::DatabaseFailure(_)
    )
}
