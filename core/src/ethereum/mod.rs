mod contract;
use crate::config::EthereumConfig;
use crate::ethereum::contract::*;
use crate::persist::{PersistCtx, repo};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use entities::*;
use futures_util::StreamExt;
use log::{error, info, warn};
use sea_orm::EntityTrait;
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

    pub async fn run(&self) -> anyhow::Result<()> {
        let ws = WsConnect::new(&self.config.ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let events_signatures = vec![
            CollateralDeposited::SIGNATURE,
            RecipientRemunerated::SIGNATURE,
            CollateralWithdrawn::SIGNATURE,
            WithdrawalRequested::SIGNATURE,
            WithdrawalCanceled::SIGNATURE,
            WithdrawalGracePeriodUpdated::SIGNATURE,
            RemunerationGracePeriodUpdated::SIGNATURE,
            TabExpirationTimeUpdated::SIGNATURE,
            SynchronizationDelayUpdated::SIGNATURE,
            RecordedPayment::SIGNATURE,
        ];
        let contract_address: Address = self.config.contract_address.parse()?;
        let filter = Filter::new()
            .address(contract_address)
            .events(events_signatures)
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();
        let _: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let sub = provider.subscribe_logs(&filter).await.map_err(|err| {
                error!("Failed to subscribe to logs: {err}");
                err
            })?;
            let mut stream = sub.into_stream();

            info!("[EthereumListener] Subscribed to contract \"{contract_address}\" events");

            while let Some(log) = stream.next().await {
                match log.topic0() {
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
                    Some(&RecordedPayment::SIGNATURE_HASH) => {
                        Self::handle_recorded_payment(log).await
                    }
                    _ => info!("[EthereumListener] Received unknown log: {log:?}"),
                }
            }

            warn!("Exited from the Ethereum listener loop!");
            Ok(())
        });

        Ok(())
    }

    async fn handle_collateral_deposited(persist_ctx: &PersistCtx, log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<CollateralDeposited>().map_err(|err| {
            error!("[EthereumListener] Error decoding CollateralDeposited: {err}");
        }) else {
            return;
        };

        let CollateralDeposited { user, amount } = log.data();
        info!("[EthereumListener] CollateralDeposited: {user:?}, amount={amount}");

        if let Err(err) = repo::deposit(persist_ctx, user.to_string(), *amount).await {
            error!("Failed to add collateral (CollateralDeposited): {err}");
        }
    }

    async fn handle_recipient_remunerated(persist_ctx: &PersistCtx, log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<RecipientRemunerated>().map_err(|err| {
            error!("[EthereumListener] Error decoding RecipientRemunerated: {err}");
        }) else {
            return;
        };
        let RecipientRemunerated { tab_id, amount } = log.data();
        info!("[EthereumListener] RecipientRemunerated: tab={tab_id}, amount={amount}");

        let tab_id_str = tab_id.to_string();
        let Some(_user_addr) = Self::find_user_address(persist_ctx, &tab_id_str).await else {
            return;
        };
        if let Err(err) = repo::remunerate_recipient(persist_ctx, tab_id.to_string(), *amount).await
        {
            error!("Failed to persist RecipientRemunerated: {err}");
        }
    }

    async fn handle_collateral_withdrawn(persist_ctx: &PersistCtx, log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<CollateralWithdrawn>().map_err(|err| {
            error!("[EthereumListener] Error decoding CollateralWithdrawn: {err}");
        }) else {
            return;
        };

        let CollateralWithdrawn { user, amount } = log.data();
        info!("[EthereumListener] CollateralWithdrawn: {user:?}, amount={amount}");

        if let Err(err) = repo::finalize_withdrawal(persist_ctx, user.to_string(), *amount).await {
            error!("Failed to finalize withdrawal: {err}");
        }
    }

    async fn handle_withdrawal_requested(persist_ctx: &PersistCtx, log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<WithdrawalRequested>().map_err(|err| {
            error!("[EthereumListener] Error decoding WithdrawalRequested: {err}");
        }) else {
            return;
        };

        let WithdrawalRequested { user, when, amount } = log.data();
        info!("[EthereumListener] WithdrawalRequested: {user:?}, when={when}, amount={amount}");

        if let Err(err) =
            repo::request_withdrawal(persist_ctx, user.to_string(), when.to(), *amount).await
        {
            error!("Failed to request withdrawal: {err}");
        }
    }

    async fn handle_withdrawal_canceled(persist_ctx: &PersistCtx, log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<WithdrawalCanceled>().map_err(|err| {
            error!("[EthereumListener] Error decoding WithdrawalCanceled: {err}");
        }) else {
            return;
        };

        let WithdrawalCanceled { user } = log.data();
        info!("[EthereumListener] WithdrawalCanceled: {user:?}");

        if let Err(err) = repo::cancel_withdrawal(persist_ctx, user.to_string()).await {
            error!("Failed to cancel withdrawal: {err}");
        }
    }

    async fn handle_withdrawal_grace_period_updated(log: alloy::rpc::types::Log) {
        let Ok(log) = log
            .log_decode::<WithdrawalGracePeriodUpdated>()
            .map_err(|err| {
                error!("[EthereumListener] Error decoding WithdrawalGracePeriodUpdated: {err}");
            })
        else {
            return;
        };

        let WithdrawalGracePeriodUpdated { newGracePeriod } = log.data();
        info!("[EthereumListener] WithdrawalGracePeriodUpdated: {newGracePeriod}");
    }

    async fn handle_remuneration_grace_period_updated(log: alloy::rpc::types::Log) {
        let Ok(log) = log
            .log_decode::<RemunerationGracePeriodUpdated>()
            .map_err(|err| {
                error!("[EthereumListener] Error decoding RemunerationGracePeriodUpdated: {err}");
            })
        else {
            return;
        };

        let RemunerationGracePeriodUpdated { newGracePeriod } = log.data();
        info!("[EthereumListener] RemunerationGracePeriodUpdated: {newGracePeriod}");
    }

    async fn handle_tab_expiration_time_updated(log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<TabExpirationTimeUpdated>().map_err(|err| {
            error!("[EthereumListener] Error decoding TabExpirationTimeUpdated: {err}");
        }) else {
            return;
        };

        let TabExpirationTimeUpdated { newExpirationTime } = log.data();
        info!("[EthereumListener] TabExpirationTimeUpdated: {newExpirationTime}");
    }

    async fn handle_synchronization_delay_updated(log: alloy::rpc::types::Log) {
        let Ok(log) = log
            .log_decode::<SynchronizationDelayUpdated>()
            .map_err(|err| {
                error!("[EthereumListener] Error decoding SynchronizationDelayUpdated: {err}");
            })
        else {
            return;
        };

        let SynchronizationDelayUpdated {
            newSynchronizationDelay,
        } = log.data();
        info!("[EthereumListener] SynchronizationDelayUpdated: {newSynchronizationDelay}");
    }

    async fn handle_recorded_payment(log: alloy::rpc::types::Log) {
        let Ok(log) = log.log_decode::<RecordedPayment>().map_err(|err| {
            error!("[EthereumListener] Error decoding RecordedPayment: {err}");
        }) else {
            return;
        };

        let RecordedPayment { tab_id, amount } = log.data();
        info!("[EthereumListener] RecordedPayment: tab={tab_id}, amount={amount}");
        // TODO: persist if desired
    }

    async fn find_user_address(persist_ctx: &PersistCtx, tab_id: &str) -> Option<String> {
        match tabs::Entity::find_by_id(tab_id.to_owned())
            .one(&*persist_ctx.db)
            .await
        {
            Ok(Some(tab)) => Some(tab.user_address),
            Ok(None) => {
                warn!("[EthereumListener] Missing Tab {tab_id} for RecipientRemunerated; skipping");
                None
            }
            Err(err) => {
                error!("[EthereumListener] DB error loading Tab {tab_id}: {err}");
                None
            }
        }
    }
}
