mod contract;

use crate::config::EthereumConfig;
use crate::error::BlockchainListenerError;
use crate::ethereum::contract::*;
use crate::persist::{PersistCtx, repo};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use futures_util::StreamExt;
use log::{error, info, warn};
use std::time::Duration;
use tokio;
use tokio::task::JoinHandle;

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
}

impl EthereumListener {
    pub fn new(config: EthereumConfig, persist_ctx: PersistCtx) -> Self {
        Self {
            config,
            persist_ctx,
        }
    }

    /// Public entry point. Keeps the listener alive with automatic reconnect.
    pub async fn run(&self) -> anyhow::Result<()> {
        let ws = WsConnect::new(&self.config.ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

        // Use the names exported by contract.rs (human-readable ABI signatures)
        let events_signatures = all_event_signatures();

        let contract_address: Address = self.config.contract_address.parse()?;
        let filter = Filter::new()
            .address(contract_address)
            .events(events_signatures)
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();

        // 🔑 keep reconnecting with exponential backoff
        let _: JoinHandle<()> = tokio::spawn(async move {
            let mut delay = Duration::from_secs(5);

            loop {
                match Self::run_once(
                    provider.clone(),
                    filter.clone(),
                    contract_address,
                    persist_ctx.clone(),
                )
                .await
                {
                    Ok(_) => warn!("Ethereum listener exited normally. Restarting in {delay:?}…"),
                    Err(err) => {
                        error!("Ethereum listener crashed: {err}. Restarting in {delay:?}…")
                    }
                }

                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay * 2, Duration::from_secs(300));
            }
        });

        Ok(())
    }

    /// Runs a single subscription session until the stream ends.
    async fn run_once<P>(
        provider: P,
        filter: Filter,
        contract_address: Address,
        persist_ctx: PersistCtx,
    ) -> anyhow::Result<()>
    where
        P: Provider + Clone + Send + Sync + 'static,
    {
        let sub = provider.subscribe_logs(&filter).await.map_err(|err| {
            error!("Failed to subscribe to logs: {err}");
            err
        })?;
        let mut stream = sub.into_stream();

        info!("[EthereumListener] Subscribed to contract \"{contract_address}\" events");

        while let Some(log) = stream.next().await {
            let result = match log.topic0() {
                Some(&CollateralDeposited::SIGNATURE_HASH) => {
                    Self::handle_collateral_deposited(&persist_ctx, log).await
                }
                Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                    Self::handle_recipient_remunerated(&persist_ctx, log).await
                }
                Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                    Self::handle_collateral_withdrawn(&persist_ctx, log).await
                }
                Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                    Self::handle_withdrawal_requested(&persist_ctx, log).await
                }
                Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                    Self::handle_withdrawal_canceled(&persist_ctx, log).await
                }
                Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                    Self::handle_withdrawal_grace_period_updated(log).await
                }
                Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                    Self::handle_remuneration_grace_period_updated(log).await
                }
                Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => {
                    Self::handle_tab_expiration_time_updated(log).await
                }
                Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => {
                    Self::handle_synchronization_delay_updated(log).await
                }
                _ => {
                    info!("[EthereumListener] Received unknown log: {log:?}");
                    Ok(())
                }
            };

            if let Err(err) = result {
                error!("[EthereumListener] Handler error: {err}");
            }
        }

        warn!("Exited from the Ethereum listener loop!");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    async fn handle_collateral_deposited(
        persist_ctx: &PersistCtx,
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited { user, amount } = *log.log_decode()?.data();
        info!("[EthereumListener] CollateralDeposited: user={user:?}, amount={amount}");
        repo::deposit(persist_ctx, user.to_string(), amount).await?;
        Ok(())
    }

    async fn handle_recipient_remunerated(
        persist_ctx: &PersistCtx,
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let RecipientRemunerated { tab_id, amount } = *log.log_decode()?.data();
        info!("[EthereumListener] RecipientRemunerated: tab={tab_id}, amount={amount}");

        let tab_id_str = tab_id.to_string();
        repo::remunerate_recipient(persist_ctx, tab_id_str, amount).await?;
        Ok(())
    }

    async fn handle_collateral_withdrawn(
        persist_ctx: &PersistCtx,
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn { user, amount } = *log.log_decode()?.data();
        info!("[EthereumListener] CollateralWithdrawn: user={user:?}, amount={amount}");
        repo::finalize_withdrawal(persist_ctx, user.to_string(), amount).await?;
        Ok(())
    }

    async fn handle_withdrawal_requested(
        persist_ctx: &PersistCtx,
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested { user, when, amount } = *log.log_decode()?.data();
        info!(
            "[EthereumListener] WithdrawalRequested: user={user:?}, when={when}, amount={amount}"
        );
        repo::request_withdrawal(persist_ctx, user.to_string(), when.to(), amount).await?;
        Ok(())
    }

    async fn handle_withdrawal_canceled(
        persist_ctx: &PersistCtx,
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user } = *log.log_decode()?.data();
        info!("[EthereumListener] WithdrawalCanceled: user={user:?}");
        repo::cancel_withdrawal(persist_ctx, user.to_string()).await?;
        Ok(())
    }

    async fn handle_withdrawal_grace_period_updated(
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let WithdrawalGracePeriodUpdated { newGracePeriod } = *log.log_decode()?.data();
        info!("[EthereumListener] WithdrawalGracePeriodUpdated: {newGracePeriod}");
        Ok(())
    }

    async fn handle_remuneration_grace_period_updated(
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let RemunerationGracePeriodUpdated { newGracePeriod } = *log.log_decode()?.data();
        info!("[EthereumListener] RemunerationGracePeriodUpdated: {newGracePeriod}");
        Ok(())
    }

    async fn handle_tab_expiration_time_updated(
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let TabExpirationTimeUpdated { newExpirationTime } = *log.log_decode()?.data();
        info!("[EthereumListener] TabExpirationTimeUpdated: {newExpirationTime}");
        Ok(())
    }

    async fn handle_synchronization_delay_updated(
        log: alloy::rpc::types::Log,
    ) -> Result<(), BlockchainListenerError> {
        let SynchronizationDelayUpdated {
            newSynchronizationDelay,
        } = *log.log_decode()?.data();
        info!("[EthereumListener] SynchronizationDelayUpdated: {newSynchronizationDelay}");
        Ok(())
    }
}
