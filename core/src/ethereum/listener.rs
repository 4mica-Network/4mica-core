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
use std::{sync::Arc, time::Duration};
use tokio::{self, sync::oneshot, task::JoinHandle};

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    provider: DynProvider,
    handler: Arc<dyn EthereumEventHandler>,
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
        let initial_backfill_blocks = self
            .config
            .number_of_blocks_to_confirm
            .saturating_add(self.config.number_of_pending_blocks);
        let handle = tokio::spawn(Self::listen_loop(
            self.provider.clone(),
            base_filter,
            address,
            persist_ctx,
            self.handler.clone(),
            ready_tx,
            initial_backfill_blocks,
        ));
        Ok(handle)
    }

    async fn listen_loop(
        provider: impl alloy::providers::Provider + 'static,
        base_filter: Filter,
        address: Address,
        persist_ctx: PersistCtx,
        handler: Arc<dyn EthereumEventHandler>,
        mut ready_tx: Option<oneshot::Sender<()>>,
        initial_backfill_blocks: u64,
    ) {
        let mut delay = Duration::from_secs(5);

        loop {
            let last_event = match repo::get_last_processed_blockchain_event(&persist_ctx).await {
                Ok(event) => event,
                Err(e) => {
                    error!("Failed to get the last processed blockchain event: {}", e);
                    warn!("Restarting listener in {delay:?}...");
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };

            let sub_filter = base_filter.clone().from_block(BlockNumberOrTag::Latest);
            match provider.subscribe_logs(&sub_filter).await {
                Ok(sub) => {
                    info!(
                        "Subscribed to new events from address {address:?} starting at latest block"
                    );

                    // Fetch historical logs from last processed event (or a small backfill window) to latest
                    let last_processed_block = last_event.map(|e| e.block_number as u64);
                    let mut backfill_start = last_processed_block;
                    if backfill_start.is_none() && initial_backfill_blocks > 0 {
                        match provider.get_block_number().await {
                            Ok(latest) => {
                                let start = latest.saturating_sub(initial_backfill_blocks);
                                backfill_start = Some(start);
                                info!(
                                    "No last processed event found; backfilling from block {start} to latest"
                                );
                            }
                            Err(e) => {
                                error!("Failed to fetch latest block for backfill: {e}");
                            }
                        }
                    }

                    let historical_logs = if let Some(start_block) = backfill_start {
                        let historical_filter = base_filter
                            .clone()
                            .from_block(start_block)
                            .to_block(BlockNumberOrTag::Latest);

                        info!("Fetching historical logs from block {start_block:?} to latest");

                        match provider.get_logs(&historical_filter).await {
                            Ok(logs) => {
                                info!("Fetched {} historical log(s)", logs.len());
                                logs
                            }
                            Err(e) => {
                                error!("Failed to fetch historical logs: {e}");
                                warn!("Restarting listener in {delay:?}...");
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(300));
                                continue;
                            }
                        }
                    } else {
                        vec![]
                    };

                    // Chain historical logs with live subscription stream
                    let historical_stream = stream::iter(historical_logs);
                    let live_stream = sub.into_stream();
                    let mut combined_stream = historical_stream.chain(live_stream);

                    // Reset the delay to 5 seconds on successful subscription
                    delay = Duration::from_secs(5);

                    // Signal that the listener is ready
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                        info!("Listener is ready and signaled readiness");
                    }

                    if let Err(e) =
                        Self::process_events(&handler, &persist_ctx, &mut combined_stream).await
                    {
                        error!("Listener crashed: {e:?}");
                    }
                }
                Err(err) => {
                    error!("Failed to subscribe to logs: {err}");
                }
            }

            warn!("Restarting listener in {delay:?}...");
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(300));
        }
    }

    async fn process_events(
        handler: &Arc<dyn EthereumEventHandler>,
        persist_ctx: &PersistCtx,
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

            info!(
                "Storing blockchain event: {signature} at block {block_number} with log index {log_index}"
            );

            let inserted = match repo::store_blockchain_event(
                persist_ctx,
                &signature,
                block_number,
                log_index,
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
                            && is_retryable_handler_error(&e)
                            && let Err(err) =
                                repo::delete_blockchain_event(persist_ctx, block_number, log_index)
                                    .await
                        {
                            error!("Failed to delete blockchain event: {err}");
                        }
                        break;
                    }
                }
            }
        }

        warn!("Event stream ended unexpectedly");
        Ok(())
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
