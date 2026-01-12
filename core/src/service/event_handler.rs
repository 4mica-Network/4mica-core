use alloy::rpc::types::Log;
use alloy_primitives::{Address, U256};
use async_trait::async_trait;
use blockchain::txtools::PaymentTx;
use log::{info, warn};

use crate::{
    error::BlockchainListenerError,
    ethereum::{contract::*, event_handler::EthereumEventHandler},
    persist::repo,
    service::CoreService,
};

#[async_trait]
impl EthereumEventHandler for CoreService {
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited {
            user,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Deposit by {user:?} of {amount}, asset={asset}");

        repo::deposit(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            amount,
        )
        .await?;
        Ok(())
    }

    async fn handle_recipient_remunerated(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let RecipientRemunerated {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Recipient remunerated: tab={tab_id}, amount={amount}");

        repo::remunerate_recipient(&self.inner.persist_ctx, tab_id, asset.to_string(), amount)
            .await?;
        Ok(())
    }

    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn {
            user,
            asset,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Collateral withdrawn by {user:?}: {amount}");

        repo::finalize_withdrawal(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            amount,
        )
        .await?;
        Ok(())
    }

    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            asset,
            when,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Withdrawal requested: {user:?}, asset={asset}, when={when}, amount={amount}");

        repo::request_withdrawal(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            when.to(),
            amount,
        )
        .await?;
        Ok(())
    }

    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user, asset, .. } = *log.log_decode()?.data();
        info!("Withdrawal canceled by {user:?}, asset={asset}");

        repo::cancel_withdrawal(&self.inner.persist_ctx, user.to_string(), asset.to_string())
            .await?;
        Ok(())
    }

    async fn handle_payment_recorded(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let PaymentRecorded {
            tab_id,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!(
            "PaymentRecorded: tab={}, amount={}",
            crate::util::u256_to_string(tab_id),
            amount
        );

        repo::unlock_user_collateral(&self.inner.persist_ctx, tab_id, asset.to_string(), amount)
            .await?;

        Ok(())
    }

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

        if tab.user_address != user.to_string() {
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
            _ => {
                info!("Unknown simple event: {}", event_name);
            }
        }
        Ok(())
    }
}
