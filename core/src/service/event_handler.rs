use alloy::rpc::types::Log;
use async_trait::async_trait;
use blockchain::txtools;
use log::{info, warn};

use crate::{
    error::BlockchainListenerError,
    ethereum::{
        contract::{erc20::Transfer, *},
        event_handler::EthereumEventHandler,
    },
    persist::repo,
    service::CoreService,
};

#[async_trait]
impl EthereumEventHandler for CoreService {
    async fn handle_erc20_transfer(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let Transfer { from, to, amount } = *log.log_decode()?.data();
        info!("ERC20 transfer: from={from}, to={to}, amount={amount}");

        let Some(tx_hash) = log.transaction_hash else {
            warn!("No transaction hash found for ERC20 transfer");
            return Ok(());
        };

        let erc20_token = log.address();
        let Some(payment_tx) = txtools::parse_erc20_transfer(
            &self.inner.read_provider,
            tx_hash,
            from,
            to,
            amount,
            erc20_token,
        )
        .await
        .map_err(|err| BlockchainListenerError::EventHandlerError(err.to_string()))?
        else {
            warn!(
                "Failed to parse ERC20 transfer: {}",
                log.transaction_hash.unwrap_or_default()
            );
            return Ok(());
        };

        self.handle_discovered_payments(vec![payment_tx])
            .await
            .map_err(|err| BlockchainListenerError::EventHandlerError(err.to_string()))?;

        Ok(())
    }

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
        let CollateralWithdrawn { user, amount, .. } = *log.log_decode()?.data();
        info!("Collateral withdrawn by {user:?}: {amount}");

        repo::finalize_withdrawal(&self.inner.persist_ctx, user.to_string(), amount).await?;
        Ok(())
    }

    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            when,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Withdrawal requested: {user:?}, when={when}, amount={amount}");

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
        let WithdrawalCanceled { user, .. } = *log.log_decode()?.data();
        info!("Withdrawal canceled by {user:?}");

        repo::cancel_withdrawal(&self.inner.persist_ctx, user.to_string()).await?;
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

        // Lookup tab → user + server
        let tab = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id)
            .await?
            .ok_or_else(|| {
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
            &self.inner.persist_ctx,
            tab.user_address.clone(),
            tab.server_address.clone(),
            asset.to_string(),
            tx_id,
            amount,
        )
        .await?;
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
                let ev = log.log_decode::<TabExpirationTimeUpdated>()?;
                info!("{:?}", ev);
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
