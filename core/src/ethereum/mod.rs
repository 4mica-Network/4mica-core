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
use sea_orm::EntityTrait;
use tokio;
use tokio::task::JoinHandle;

// NEW: import tabs to resolve user_address from tab_id
use entities::*;

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
                SynchronizationDelayUpdated::SIGNATURE,
                RecordedPayment::SIGNATURE,
            ])
            // start from latest block to avoid replaying full history on fresh boot
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();
        let _: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            // ⚠️ You can wrap this in a reconnect loop if desired.
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
                        info!(
                            "[EthereumListener] UserRegistered: {user:?}, initial={initialCollateral}"
                        );

                        // NOTE: if initialCollateral is U256, precision loss is acceptable for f64 here per your schema.
                        let _ =
                            repo::deposit(&persist_ctx, user.to_string(), initialCollateral.into())
                                .await
                                .map_err(|err| {
                                    error!("Failed to deposit (UserRegistered): {err}");
                                    err
                                });
                    }

                    Some(&CollateralDeposited::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<CollateralDeposited>().map_err(|err| {
                            error!("[EthereumListener] Error decoding CollateralDeposited: {err}");
                        }) else {
                            continue;
                        };
                        let CollateralDeposited { user, amount } = log.data();
                        info!("[EthereumListener] CollateralDeposited: {user:?}, amount={amount}");

                        let _ = repo::deposit(&persist_ctx, user.to_string(), amount.into())
                            .await
                            .map_err(|err| {
                                error!("Failed to add collateral (CollateralDeposited): {err}");
                                err
                            });
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
                            "[EthereumListener] RecipientRemunerated: tab={tab_id}, req={req_id}, amount={amount}"
                        );

                        // Resolve user_address via Tabs
                        let tab_id_str = tab_id.to_string();
                        let user_addr = match tabs::Entity::find_by_id(tab_id_str.clone())
                            .one(&*persist_ctx.db)
                            .await
                        {
                            Ok(Some(tab)) => tab.user_address,
                            Ok(None) => {
                                warn!(
                                    "[EthereumListener] Missing Tab {tab_id_str} for RecipientRemunerated; skipping"
                                );
                                continue;
                            }
                            Err(err) => {
                                error!(
                                    "[EthereumListener] DB error loading Tab {tab_id_str}: {err}"
                                );
                                continue;
                            }
                        };

                        let _ = repo::remunerate_recipient(
                            &persist_ctx,
                            user_addr,
                            tab_id.to(),
                            amount.into(),
                        )
                        .await
                        .map_err(|err| {
                            error!("Failed to persist RecipientRemunerated: {err}");
                            err
                        });
                    }

                    Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<CollateralWithdrawn>().map_err(|err| {
                            error!("[EthereumListener] Error decoding CollateralWithdrawn: {err}");
                        }) else {
                            continue;
                        };
                        let CollateralWithdrawn { user, amount } = log.data();
                        info!("[EthereumListener] CollateralWithdrawn: {user:?}, amount={amount}");

                        let _ = repo::finalize_withdrawal(
                            &persist_ctx,
                            user.to_string(),
                            amount.into(),
                        )
                        .await
                        .map_err(|err| {
                            error!("Failed to finalize withdrawal: {err}");
                            err
                        });
                    }

                    Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<WithdrawalRequested>().map_err(|err| {
                            error!("[EthereumListener] Error decoding WithdrawalRequested: {err}");
                        }) else {
                            continue;
                        };
                        let WithdrawalRequested { user, when, amount } = log.data();
                        info!(
                            "[EthereumListener] WithdrawalRequested: {user:?}, when={when}, amount={amount}"
                        );

                        let _ = repo::request_withdrawal(
                            &persist_ctx,
                            user.to_string(),
                            when.to(),
                            amount.into(),
                        )
                        .await
                        .map_err(|err| {
                            error!("Failed to request withdrawal: {err}");
                            err
                        });
                    }

                    Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<WithdrawalCanceled>().map_err(|err| {
                            error!("[EthereumListener] Error decoding WithdrawalCanceled: {err}");
                        }) else {
                            continue;
                        };
                        let WithdrawalCanceled { user } = log.data();
                        info!("[EthereumListener] WithdrawalCanceled: {user:?}");

                        let _ = repo::cancel_withdrawal(&persist_ctx, user.to_string())
                            .await
                            .map_err(|err| {
                                error!("Failed to cancel withdrawal: {err}");
                                err
                            });
                    }

                    Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => {
                        let Ok(log) = log
                            .log_decode::<WithdrawalGracePeriodUpdated>()
                            .map_err(|err| {
                                error!(
                                    "[EthereumListener] Error decoding WithdrawalGracePeriodUpdated: {err}"
                                );
                            })
                        else {
                            continue;
                        };
                        let WithdrawalGracePeriodUpdated { newGracePeriod } = log.data();
                        info!("[EthereumListener] WithdrawalGracePeriodUpdated: {newGracePeriod}");
                        // No DB persistence (config only)
                    }

                    Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => {
                        let Ok(log) = log
                            .log_decode::<RemunerationGracePeriodUpdated>()
                            .map_err(|err| {
                                error!(
                                    "[EthereumListener] Error decoding RemunerationGracePeriodUpdated: {err}"
                                );
                            })
                        else {
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

                    Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => {
                        let Ok(log) =
                            log.log_decode::<SynchronizationDelayUpdated>().map_err(|err| {
                                error!(
                                    "[EthereumListener] Error decoding SynchronizationDelayUpdated: {err}"
                                );
                            })
                        else {
                            continue;
                        };
                        let SynchronizationDelayUpdated {
                            newSynchronizationDelay,
                        } = log.data();
                        info!(
                            "[EthereumListener] SynchronizationDelayUpdated: {newSynchronizationDelay}"
                        );
                    }

                    Some(&RecordedPayment::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<RecordedPayment>().map_err(|err| {
                            error!("[EthereumListener] Error decoding RecordedPayment: {err}");
                        }) else {
                            continue;
                        };
                        let RecordedPayment { tab_id, amount } = log.data();
                        info!("[EthereumListener] RecordedPayment: tab={tab_id}, amount={amount}");
                        // TODO: persist if desired
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
