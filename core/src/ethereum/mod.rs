mod contract;
use crate::config::EthereumConfig;
use crate::ethereum::contract::*;
use crate::persist::{PersistCtx, repo};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use futures_util::StreamExt;
use log::{error, info, warn};
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

        let contract_address: Address = self.config.contract_address.parse()?;
        let filter = Filter::new()
            .address(contract_address)
            .events(vec![
                UserRegistered::SIGNATURE,
                CollateralDeposited::SIGNATURE,
                RecipientRemunerated::SIGNATURE,
                CollateralWithdrawn::SIGNATURE,
                WithdrawalRequested::SIGNATURE,
                WithdrawalCanceled::SIGNATURE,
                WithdrawalGracePeriodUpdated::SIGNATURE,
                RemunerationGracePeriodUpdated::SIGNATURE,
                TabExpirationTimeUpdated::SIGNATURE,
                RecordedPayment::SIGNATURE,
            ])
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
                    Some(&UserRegistered::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<UserRegistered>().map_err(|err| {
                            error!("[EthereumListener] Error decoding UserRegistered: {err}");
                        }) else {
                            continue;
                        };
                        let UserRegistered {
                            user,
                            initialCollateral,
                        } = log.data();
                        info!("[EthereumListener] UserRegistered: {user:?}, {initialCollateral}");

                        repo::deposit(&persist_ctx, user.to_string(), initialCollateral.into())
                            .await
                            .map_err(|err| {
                                error!("Failed to deposit (UserRegistered): {err}");
                                err
                            })
                            .ok();
                    }
                    Some(&CollateralDeposited::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<CollateralDeposited>().map_err(|err| {
                            error!("[EthereumListener] Error decoding CollateralDeposited: {err}");
                        }) else {
                            continue;
                        };
                        let CollateralDeposited { user, amount } = log.data();
                        info!("[EthereumListener] CollateralDeposited: {user:?}, {amount}");

                        repo::deposit(&persist_ctx, user.to_string(), amount.into())
                            .await
                            .map_err(|err| {
                                error!("Failed to add collateral (CollateralDeposited): {err}");
                                err
                            })
                            .ok();
                    }
                    Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<RecipientRemunerated>().map_err(|err| {
                            error!("[EthereumListener] Error decoding RecipientRemunerated: {err}");
                        }) else {
                            continue;
                        };
                        let RecipientRemunerated {
                            tab_id,
                            req_id,
                            amount,
                        } = log.data();
                        info!(
                            "[EthereumListener] RecipientRemunerated: tab {tab_id}, req {req_id}, amount {amount}"
                        );
                        // TODO: Add DB logic for remuneration events.
                    }
                    Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<CollateralWithdrawn>().map_err(|err| {
                            error!("[EthereumListener] Error decoding CollateralWithdrawn: {err}");
                        }) else {
                            continue;
                        };
                        let CollateralWithdrawn { user, amount } = log.data();
                        info!("[EthereumListener] CollateralWithdrawn: {user:?}, {amount}");
                        // TODO: Handle DB state changes for withdrawals.
                    }
                    Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<WithdrawalRequested>().map_err(|err| {
                            error!("[EthereumListener] Error decoding WithdrawalRequested: {err}");
                        }) else {
                            continue;
                        };
                        let WithdrawalRequested { user, when } = log.data();
                        info!("[EthereumListener] WithdrawalRequested: {user:?}, at {when}");
                        // TODO: Persist withdrawal request.
                    }
                    Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<WithdrawalCanceled>().map_err(|err| {
                            error!("[EthereumListener] Error decoding WithdrawalCanceled: {err}");
                        }) else {
                            continue;
                        };
                        let WithdrawalCanceled { user } = log.data();
                        info!("[EthereumListener] WithdrawalCanceled: {user:?}");
                        // TODO: Update withdrawal record.
                    }
                    Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                        let Ok(log) =
                            log.log_decode::<WithdrawalGracePeriodUpdated>().map_err(|err| {
                                error!(
                                    "[EthereumListener] Error decoding WithdrawalGracePeriodUpdated: {err}"
                                );
                            }) else {
                                continue;
                            };
                        let WithdrawalGracePeriodUpdated { newGracePeriod } = log.data();
                        info!("[EthereumListener] WithdrawalGracePeriodUpdated: {newGracePeriod}");
                    }
                    Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                        let Ok(log) =
                            log.log_decode::<RemunerationGracePeriodUpdated>().map_err(|err| {
                                error!(
                                    "[EthereumListener] Error decoding RemunerationGracePeriodUpdated: {err}"
                                );
                            }) else {
                                continue;
                            };
                        let RemunerationGracePeriodUpdated { newGracePeriod } = log.data();
                        info!(
                            "[EthereumListener] RemunerationGracePeriodUpdated: {newGracePeriod}"
                        );
                    }
                    Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<TabExpirationTimeUpdated>().map_err(|err| {
                            error!(
                                "[EthereumListener] Error decoding TabExpirationTimeUpdated: {err}"
                            );
                        }) else {
                            continue;
                        };
                        let TabExpirationTimeUpdated { newExpirationTime } = log.data();
                        info!("[EthereumListener] TabExpirationTimeUpdated: {newExpirationTime}");
                    }
                    Some(&RecordedPayment::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<RecordedPayment>().map_err(|err| {
                            error!("[EthereumListener] Error decoding RecordedPayment: {err}");
                        }) else {
                            continue;
                        };
                        let RecordedPayment { tab_id, amount } = log.data();
                        info!("[EthereumListener] RecordedPayment: tab {tab_id}, amount {amount}");
                        // TODO: Update tab payments in DB.
                    }
                    log => {
                        info!("[EthereumListener] Received unknown log: {log:?}");
                    }
                }
            }

            warn!("Exited from the Ethereum listener loop!");
            Ok(())
        });

        Ok(())
    }
}
