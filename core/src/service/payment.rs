use crate::config::{DEFAULT_ASSET_ADDRESS, EthereumConfig};
use crate::scheduler::Task;
use crate::service::CoreService;
use crate::{
    error::{ServiceError, ServiceResult},
    persist::repo,
    util::u256_to_string,
};
use alloy::primitives::Address;
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use log::{error, info, warn};

impl CoreService {
    /// Submit user transactions and record payments on-chain for each discovered on-chain payment.
    pub async fn handle_discovered_payments(&self, events: Vec<PaymentTx>) -> ServiceResult<()> {
        for payment in events {
            let tab_id_str = u256_to_string(payment.tab_id);
            let tx_hash = format!("{:#x}", payment.tx_hash);
            let amount = payment.amount;

            info!(
                "Processing discovered payment: block={} tab_id={} req_id={} amount={} tx={} from={} to={}",
                payment.block_number,
                tab_id_str,
                u256_to_string(payment.req_id),
                amount,
                tx_hash,
                payment.from,
                payment.to
            );

            let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, payment.tab_id).await?
            else {
                warn!(
                    "Tab {} not found while processing payment tx {}. Skipping.",
                    tab_id_str, tx_hash
                );
                continue;
            };
            if tab.server_address != payment.to.to_string() {
                warn!(
                    "Recipient address does not match payment recipient for tab {}. Skipping.",
                    tab_id_str
                );
                continue;
            }

            let tab_user_address = match tab.user_address.parse::<Address>() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(
                        "Invalid user address {} for tab {} (err: {}). Skipping.",
                        tab.user_address, tab_id_str, err
                    );
                    continue;
                }
            };

            if tab_user_address != payment.from {
                warn!(
                    "Payment sender {} does not match tab user {} for tab {}. Skipping.",
                    payment.from, tab.user_address, tab_id_str
                );
                continue;
            }

            let asset_address = payment
                .erc20_token
                .unwrap_or(DEFAULT_ASSET_ADDRESS.parse().map_err(anyhow::Error::from)?);

            // Submit a user transaction if it doesn't already exist
            let rows_affected = repo::submit_payment_transaction(
                &self.inner.persist_ctx,
                tab.user_address.clone(),
                tab.server_address.clone(),
                asset_address.to_string(),
                tx_hash.clone(),
                amount,
            )
            .await?;

            if rows_affected == 0 {
                info!(
                    "Payment transaction already exists for tab {}. Skipping.",
                    tab_id_str
                );
                continue;
            }

            if let Err(err) = self
                .inner
                .contract_api
                .record_payment(payment.tab_id, asset_address, amount)
                .await
            {
                return Err(ServiceError::Other(anyhow!(
                    "Failed to record payment on-chain for tab {} (tx {}): {err}",
                    tab_id_str,
                    tx_hash
                )));
            }
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
                error!("failed to handle discovered payments: {e}");
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
