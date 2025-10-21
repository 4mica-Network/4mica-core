use crate::config::{DEFAULT_ASSET_ADDRESS, EthereumConfig};
use crate::scheduler::Task;
use crate::service::CoreService;
use crate::{
    error::{ServiceError, ServiceResult},
    persist::repo,
    util::u256_to_string,
};
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use log::{error, info};

impl CoreService {
    /// Persist and unlock user collateral for each discovered on-chain payment.
    pub async fn handle_discovered_payments(&self, events: Vec<PaymentTx>) -> ServiceResult<()> {
        for ev in events {
            let tab_id_str = u256_to_string(ev.tab_id);
            let tx_hash = format!("{:#x}", ev.tx_hash);
            let amount = ev.amount;

            info!(
                "Processing discovered payment: block={} tab_id={} req_id={} amount={} tx={}",
                ev.block_number,
                tab_id_str,
                u256_to_string(ev.req_id),
                amount,
                tx_hash
            );

            if repo::payment_transaction_exists(&self.inner.persist_ctx, &tx_hash).await? {
                info!(
                    "Skipping already processed payment tx {} for tab {}",
                    tx_hash, tab_id_str
                );
                continue;
            }

            let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, ev.tab_id).await? else {
                error!(
                    "Tab {} not found while processing payment tx {}. Skipping.",
                    tab_id_str, tx_hash
                );
                continue;
            };

            let asset_address = ev
                .erc20_token
                .map(|token| token.to_string())
                .unwrap_or(DEFAULT_ASSET_ADDRESS.to_string());

            repo::submit_payment_transaction(
                &self.inner.persist_ctx,
                tab.user_address.clone(),
                tab.server_address.clone(),
                asset_address.clone(),
                tx_hash.clone(),
                amount,
            )
            .await?;

            if let Err(err) = self
                .inner
                .contract_api
                .record_payment(ev.tab_id, amount)
                .await
            {
                error!(
                    "Failed to record payment on-chain for tab {} (tx {}): {err}",
                    tab_id_str, tx_hash
                );
                return Err(ServiceError::Other(anyhow!(
                    "failed to record payment on-chain for tab {tab_id_str}: {err}"
                )));
            }

            repo::unlock_user_collateral(&self.inner.persist_ctx, ev.tab_id, asset_address, amount)
                .await?;
        }
        Ok(())
    }

    /// Periodically scan Ethereum for tab payments.
    async fn scan_blockchain(&self, lookback: u64) -> anyhow::Result<()> {
        let events = txtools::scan_tab_payments(&self.inner.read_provider, lookback)
            .await
            .inspect_err(|e| {
                error!("scan_tab_payments failed: {e}");
            })?;

        self.handle_discovered_payments(events)
            .await
            .inspect_err(|e| {
                error!("failed to persist discovered payments: {e}");
            })?;

        Ok(())
    }
}

pub struct ScanPaymentsTask(CoreService);

impl ScanPaymentsTask {
    pub fn new(service: CoreService) -> Self {
        Self(service)
    }

    fn ethereum_config(&self) -> &EthereumConfig {
        &self.0.inner.config.ethereum_config
    }
}

#[async_trait]
impl Task for ScanPaymentsTask {
    fn cron_pattern(&self) -> String {
        self.ethereum_config().cron_job_settings.clone()
    }

    async fn run(&self) -> anyhow::Result<()> {
        let lookback = self.ethereum_config().number_of_blocks_to_confirm;
        self.0.scan_blockchain(lookback).await
    }
}
