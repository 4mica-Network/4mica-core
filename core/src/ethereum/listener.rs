use crate::{
    config::EthereumConfig,
    error::BlockchainListenerError,
    ethereum::{contract::*, event_handler::EthereumEventHandler},
    persist::PersistCtx,
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::DynProvider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::StreamExt;
use log::{error, info, warn};
use std::{sync::Arc, time::Duration};
use tokio::{self, task::JoinHandle};

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    provider: DynProvider,
    erc20_tokens: Vec<Address>,
    handler: Arc<dyn EthereumEventHandler>,
}

impl EthereumListener {
    pub fn new(
        config: EthereumConfig,
        persist_ctx: PersistCtx,
        provider: DynProvider,
        erc20_tokens: Vec<Address>,
        handler: Arc<dyn EthereumEventHandler>,
    ) -> Self {
        Self {
            config,
            persist_ctx,
            provider,
            erc20_tokens,
            handler,
        }
    }

    /// Entry point — runs forever, reconnecting with exponential backoff.
    pub async fn run(&self) -> Result<JoinHandle<()>, BlockchainListenerError> {
        let address: Address = self
            .config
            .contract_address
            .parse()
            .map_err(anyhow::Error::from)?;

        let addresses: Vec<Address> = std::iter::once(address)
            .chain(self.erc20_tokens.iter().copied())
            .collect();
        let filter = Filter::new()
            .address(addresses)
            .events(all_event_signatures())
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();
        let handle = tokio::spawn(Self::listen_loop(
            self.provider.clone(),
            filter,
            address,
            persist_ctx,
            self.handler.clone(),
        ));
        Ok(handle)
    }

    async fn listen_loop(
        provider: impl alloy::providers::Provider + 'static,
        filter: Filter,
        address: Address,
        persist_ctx: PersistCtx,
        handler: Arc<dyn EthereumEventHandler>,
    ) {
        let mut delay = Duration::from_secs(5);

        loop {
            match provider.subscribe_logs(&filter).await {
                Ok(sub) => {
                    info!("Listening for events from {address:?}");
                    let mut stream = sub.into_stream();

                    if let Err(e) = Self::process_events(&persist_ctx, &handler, &mut stream).await
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
        _persist_ctx: &PersistCtx,
        handler: &Arc<dyn EthereumEventHandler>,
        stream: &mut (impl futures_util::Stream<Item = Log> + Unpin),
    ) -> Result<(), BlockchainListenerError> {
        while let Some(log) = stream.next().await {
            let result = match log.topic0() {
                Some(&CollateralDeposited::SIGNATURE_HASH) => {
                    handler.handle_collateral_deposited(log).await
                }
                Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                    handler.handle_recipient_remunerated(log).await
                }
                Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                    handler.handle_collateral_withdrawn(log).await
                }
                Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                    handler.handle_withdrawal_requested(log).await
                }
                Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                    handler.handle_withdrawal_canceled(log).await
                }
                Some(&PaymentRecorded::SIGNATURE_HASH) => {
                    handler.handle_payment_recorded(log).await
                }
                Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                    handler
                        .handle_admin_event(log, "WithdrawalGracePeriodUpdated")
                        .await
                }
                Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                    handler
                        .handle_admin_event(log, "RemunerationGracePeriodUpdated")
                        .await
                }
                Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => {
                    handler
                        .handle_admin_event(log, "TabExpirationTimeUpdated")
                        .await
                }
                Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => {
                    handler
                        .handle_admin_event(log, "SynchronizationDelayUpdated")
                        .await
                }
                Some(&erc20::Transfer::SIGNATURE_HASH) => handler
                    .handle_erc20_transfer(log)
                    .await
                    .map_err(|e| BlockchainListenerError::from(e)),
                _ => {
                    info!("Unknown log: {:?}", log);
                    Ok(())
                }
            };

            if let Err(e) = result {
                error!("Event handler error: {e}");
            }
        }

        warn!("Event stream ended unexpectedly");
        Ok(())
    }
}
