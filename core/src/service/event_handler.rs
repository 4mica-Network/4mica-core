use alloy::rpc::types::Log;
use alloy_primitives::{Address, U256};
use async_trait::async_trait;
use blockchain::txtools::PaymentTx;
use log::{info, warn};
use metrics_4mica::measure;

use crate::metrics::misc::record_event_handler_time;
use crate::{
    error::BlockchainListenerError,
    ethereum::{contract::*, event_data::EventMeta, event_handler::EthereumEventHandler},
    persist::repo,
    service::CoreService,
};

#[async_trait]
impl EthereumEventHandler for CoreService {
    #[measure(record_event_handler_time, name = "collateral_deposited")]
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited {
            user,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Deposit by {user:?} of {amount}, asset={asset}");

        let meta = event_meta_from_log(self, &log)?;
        repo::deposit_with_event(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            amount,
            Some(&meta),
        )
        .await?;
        self.sync_stablecoin_balance_from_chain(user, asset).await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "recipient_remunerated")]
    async fn handle_recipient_remunerated(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let RecipientRemunerated {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Recipient remunerated: tab={tab_id}, amount={amount}");

        let meta = event_meta_from_log(self, &log)?;
        repo::remunerate_recipient_with_event(
            &self.inner.persist_ctx,
            tab_id,
            asset.to_string(),
            amount,
            Some(&meta),
        )
        .await?;
        if let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id).await? {
            let user = match tab.user_address.parse::<Address>() {
                Ok(user) => user,
                Err(err) => {
                    warn!(
                        "Invalid user address {} for remunerated tab {} (err: {}). Skipping stablecoin sync.",
                        tab.user_address,
                        crate::util::u256_to_string(tab_id),
                        err
                    );
                    return Ok(());
                }
            };
            self.sync_stablecoin_balance_from_chain(user, asset).await?;
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "collateral_withdrawn")]
    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn {
            user,
            asset,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Collateral withdrawn by {user:?}: {amount}");

        let meta = event_meta_from_log(self, &log)?;
        if self.stablecoin_a_token(asset).await?.is_some() {
            repo::mark_withdrawal_executed_with_event(
                &self.inner.persist_ctx,
                user.to_string(),
                asset.to_string(),
                amount,
                Some(&meta),
            )
            .await?;
            self.sync_stablecoin_balance_from_chain(user, asset).await?;
        } else {
            repo::finalize_withdrawal_with_event(
                &self.inner.persist_ctx,
                user.to_string(),
                asset.to_string(),
                amount,
                Some(&meta),
            )
            .await?;
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_requested")]
    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            asset,
            when,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Withdrawal requested: {user:?}, asset={asset}, when={when}, amount={amount}");

        let meta = event_meta_from_log(self, &log)?;
        repo::request_withdrawal_with_event(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            when.to(),
            amount,
            Some(&meta),
        )
        .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_canceled")]
    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user, asset, .. } = *log.log_decode()?.data();
        info!("Withdrawal canceled by {user:?}, asset={asset}");

        let meta = event_meta_from_log(self, &log)?;
        repo::cancel_withdrawal_with_event(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            Some(&meta),
        )
        .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "payment_recorded")]
    async fn handle_payment_recorded(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let PaymentRecorded {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!(
            "PaymentRecorded: tab={}, amount={}, asset={}",
            crate::util::u256_to_string(tab_id),
            amount,
            asset
        );

        // Unlocking collateral is handled after record-payment finalization.
        Ok(())
    }

    #[measure(record_event_handler_time, name = "tab_paid")]
    async fn handle_tab_paid(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let TabPaid {
            tab_id,
            asset,
            user,
            recipient,
            amount,
            ..
        } = *log.log_decode()?.data();

        let tab_id_str = crate::util::u256_to_string(tab_id);
        info!(
            "Tab paid: tab={tab_id_str}, user={user}, recipient={recipient}, amount={amount}, asset={asset}"
        );

        let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id).await? else {
            warn!("Tab not found for TabPaid: {}. Skipping.", tab_id_str);
            return Ok(());
        };

        let tab_user_address: Address = match tab.user_address.parse() {
            Ok(address) => address,
            Err(err) => {
                warn!(
                    "Invalid tab user address {} for tab {} (err: {}). Skipping.",
                    &tab.user_address, tab_id_str, err
                );
                return Ok(());
            }
        };

        if tab_user_address != user {
            warn!(
                "User address does not match tab user address for tab {}. Skipping.",
                tab_id_str
            );
            return Ok(());
        }

        let tab_asset_address: Address = match tab.asset_address.parse() {
            Ok(address) => address,
            Err(err) => {
                warn!(
                    "Invalid tab asset address {} for tab {} (err: {}). Skipping.",
                    &tab.asset_address, tab_id_str, err
                );
                return Ok(());
            }
        };

        if tab_asset_address != asset {
            warn!(
                "Asset does not match tab asset for tab {}. Skipping.",
                tab_id_str
            );
            return Ok(());
        }

        let recipient_address: Address = tab.server_address.parse().map_err(|e| {
            BlockchainListenerError::EventHandlerError(format!(
                "Failed to parse recipient address: {e}"
            ))
        })?;

        if recipient_address != recipient {
            warn!(
                "Recipient does not match tab recipient for tab {}. Skipping.",
                tab_id_str
            );
            return Ok(());
        }

        let payment = PaymentTx {
            block_number: log.block_number.unwrap_or_default(),
            block_hash: log.block_hash,
            block_timestamp: log.block_timestamp,
            tx_hash: log.transaction_hash.unwrap_or_default(),
            from: user,
            to: recipient,
            amount,
            tab_id,
            req_id: U256::from(1),
            erc20_token: Some(asset),
        };
        self.handle_discovered_payments(vec![payment])
            .await
            .map_err(|e| {
                BlockchainListenerError::EventHandlerError(format!(
                    "Failed to handle discovered payments: {e}"
                ))
            })?;

        Ok(())
    }

    #[measure(record_event_handler_time, name = "admin_event")]
    async fn handle_admin_event(
        &self,
        log: Log,
        event_name: &str,
    ) -> Result<(), BlockchainListenerError> {
        match event_name {
            "WithdrawalGracePeriodUpdated" => {
                let ev = log.log_decode::<WithdrawalGracePeriodUpdated>()?;
                info!("{:?}", ev);
            }
            "RemunerationGracePeriodUpdated" => {
                let ev = log.log_decode::<RemunerationGracePeriodUpdated>()?;
                info!("{:?}", ev);
            }
            "TabExpirationTimeUpdated" => {
                let TabExpirationTimeUpdated {
                    newExpirationTime: new_expiration_time,
                    ..
                } = *log.log_decode()?.data();
                let new_expiration = new_expiration_time.to();
                info!("TabExpirationTimeUpdated: {}", new_expiration);
                self.set_tab_expiration_time(new_expiration);
            }
            "SynchronizationDelayUpdated" => {
                let ev = log.log_decode::<SynchronizationDelayUpdated>()?;
                info!("{:?}", ev);
            }
            "VerificationKeyUpdated" => {
                let ev = log.log_decode::<VerificationKeyUpdated>()?;
                info!("{:?}", ev);
            }
            "GuaranteeVersionUpdated" => {
                let ev = log.log_decode::<GuaranteeVersionUpdated>()?;
                info!("{:?}", ev);
            }
            _ => {
                info!("Unknown simple event: {}", event_name);
            }
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "unknown")]
    async fn handle_unknown_event(&self, log: Log) -> Result<(), BlockchainListenerError> {
        info!("Unknown event: {:?}", log);
        Ok(())
    }
}

impl CoreService {
    async fn sync_stablecoin_balance_from_chain(
        &self,
        user: Address,
        asset: Address,
    ) -> Result<(), BlockchainListenerError> {
        if asset == Address::ZERO {
            return Ok(());
        }

        if self.stablecoin_a_token(asset).await?.is_none() {
            return Ok(());
        }

        let contract = self.read_contract()?;
        let guarantee_capacity = contract
            .guaranteeCapacity(user, asset)
            .call()
            .await
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to load guarantee capacity for user {user} asset {asset}: {err}"
                ))
            })?;

        repo::sync_user_asset_total(
            &self.inner.persist_ctx,
            &user.to_string(),
            &asset.to_string(),
            guarantee_capacity,
        )
        .await?;

        Ok(())
    }

    fn read_contract(
        &self,
    ) -> Result<
        crate::ethereum::contract::contract_abi::Core4Mica::Core4MicaInstance<
            alloy::providers::DynProvider,
        >,
        BlockchainListenerError,
    > {
        use crate::ethereum::contract::contract_abi::Core4Mica;

        let contract_address = self
            .inner
            .config
            .ethereum_config
            .contract_address
            .parse::<Address>()
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to parse contract address {}: {err}",
                    self.inner.config.ethereum_config.contract_address
                ))
            })?;

        Ok(Core4Mica::new(
            contract_address,
            self.inner.read_provider.clone(),
        ))
    }

    async fn stablecoin_a_token(
        &self,
        asset: Address,
    ) -> Result<Option<Address>, BlockchainListenerError> {
        if asset == Address::ZERO {
            return Ok(None);
        }

        let contract = self.read_contract()?;
        let a_token = contract
            .stablecoinAToken(asset)
            .call()
            .await
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to load stablecoin aToken for asset {asset}: {err}"
                ))
            })?;

        if a_token == Address::ZERO {
            Ok(None)
        } else {
            Ok(Some(a_token))
        }
    }
}

fn event_meta_from_log(
    service: &CoreService,
    log: &Log,
) -> Result<EventMeta, BlockchainListenerError> {
    let chain_id = service.inner.config.ethereum_config.chain_id;
    let Some(block_hash) = log.block_hash else {
        return Err(BlockchainListenerError::EventHandlerError(
            "log missing block_hash".to_string(),
        ));
    };
    let Some(tx_hash) = log.transaction_hash else {
        return Err(BlockchainListenerError::EventHandlerError(
            "log missing tx_hash".to_string(),
        ));
    };
    let Some(log_index) = log.log_index else {
        return Err(BlockchainListenerError::EventHandlerError(
            "log missing log_index".to_string(),
        ));
    };

    Ok(EventMeta {
        chain_id,
        block_hash: format!("{:#x}", block_hash),
        tx_hash: format!("{:#x}", tx_hash),
        log_index,
    })
}
