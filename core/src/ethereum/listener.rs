use crate::{
    config::EthereumConfig,
    error::BlockchainListenerError,
    ethereum::contract::*,
    persist::{PersistCtx, repo},
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
use std::time::Duration;
use tokio;

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
    provider: DynProvider,
}

impl EthereumListener {
    pub fn new(config: EthereumConfig, persist_ctx: PersistCtx, provider: DynProvider) -> Self {
        Self {
            config,
            persist_ctx,
            provider,
        }
    }

    /// Entry point — runs forever, reconnecting with exponential backoff.
    pub async fn run(&self) -> Result<(), BlockchainListenerError> {
        let address: Address = self
            .config
            .contract_address
            .parse()
            .map_err(anyhow::Error::from)?;

        let filter = Filter::new()
            .address(address)
            .events(all_event_signatures())
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();
        tokio::spawn(Self::listen_loop(
            self.provider.clone(),
            filter,
            address,
            persist_ctx,
        ));

        Ok(())
    }

    async fn listen_loop(
        provider: impl alloy::providers::Provider + 'static,
        filter: Filter,
        address: Address,
        persist_ctx: PersistCtx,
    ) {
        let mut delay = Duration::from_secs(5);

        loop {
            match provider.subscribe_logs(&filter).await {
                Ok(sub) => {
                    info!("Listening for events from {address:?}");
                    let mut stream = sub.into_stream();

                    if let Err(e) = Self::process_events(&persist_ctx, &mut stream).await {
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
        persist_ctx: &PersistCtx,
        stream: &mut (impl futures_util::Stream<Item = Log> + Unpin),
    ) -> Result<(), BlockchainListenerError> {
        while let Some(log) = stream.next().await {
            let result = match log.topic0() {
                Some(&CollateralDeposited::SIGNATURE_HASH) => {
                    Self::handle_collateral_deposited(persist_ctx, log).await
                }
                Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                    Self::handle_recipient_remunerated(persist_ctx, log).await
                }
                Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                    Self::handle_collateral_withdrawn(persist_ctx, log).await
                }
                Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                    Self::handle_withdrawal_requested(persist_ctx, log).await
                }
                Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                    Self::handle_withdrawal_canceled(persist_ctx, log).await
                }
                Some(&PaymentRecorded::SIGNATURE_HASH) => {
                    Self::handle_payment_recorded(persist_ctx, log).await
                }
                Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                    Self::log_simple_event::<WithdrawalGracePeriodUpdated>(log).await
                }
                Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                    Self::log_simple_event::<RemunerationGracePeriodUpdated>(log).await
                }
                Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => {
                    Self::log_simple_event::<TabExpirationTimeUpdated>(log).await
                }
                Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => {
                    Self::log_simple_event::<SynchronizationDelayUpdated>(log).await
                }
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

    // Helper for simple logs
    async fn log_simple_event<E: SolEvent + std::fmt::Debug>(
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let ev = log.log_decode::<E>()?;
        info!("{:?}", ev);
        Ok(())
    }

    // ----- Event Handlers -----
    async fn handle_collateral_deposited(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited {
            user,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        repo::deposit(ctx, user.to_string(), asset.to_string(), amount).await?;
        info!("Deposit by {user:?} of {amount}");
        Ok(())
    }

    async fn handle_recipient_remunerated(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let RecipientRemunerated {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        repo::remunerate_recipient(ctx, tab_id, asset.to_string(), amount).await?;
        info!("Recipient remunerated: tab={tab_id}, amount={amount}");
        Ok(())
    }

    // Handler
    async fn handle_payment_recorded(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let PaymentRecorded {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();

        // Lookup tab → user + server
        let tab = repo::get_tab_by_id(ctx, tab_id).await?.ok_or_else(|| {
            anyhow::anyhow!(
                "Tab not found for PaymentRecorded: {}",
                crate::util::u256_to_string(tab_id)
            )
        })?;

        // Create a stable tx_id; using the tx hash is a good idempotent key.
        let tx_id = log
            .transaction_hash
            .map(|h| format!("{:#x}", h))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Persist a user transaction; recipient = server for recorded payment
        repo::submit_payment_transaction(
            ctx,
            tab.user_address.clone(),
            tab.server_address.clone(),
            asset.to_string(),
            tx_id,
            amount,
        )
        .await?;

        log::info!(
            "PaymentRecorded: tab={}, amount={}",
            crate::util::u256_to_string(tab_id),
            amount
        );
        Ok(())
    }

    async fn handle_collateral_withdrawn(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn { user, amount, .. } = *log.log_decode()?.data();
        repo::finalize_withdrawal(ctx, user.to_string(), amount).await?;
        info!("Collateral withdrawn by {user:?}: {amount}");
        Ok(())
    }

    async fn handle_withdrawal_requested(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            when,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        repo::request_withdrawal(ctx, user.to_string(), asset.to_string(), when.to(), amount)
            .await?;
        info!("Withdrawal requested: {user:?}, when={when}, amount={amount}");
        Ok(())
    }

    async fn handle_withdrawal_canceled(
        ctx: &PersistCtx,
        log: Log,
    ) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user, .. } = *log.log_decode()?.data();
        repo::cancel_withdrawal(ctx, user.to_string()).await?;
        info!("Withdrawal canceled by {user:?}");
        Ok(())
    }
}
