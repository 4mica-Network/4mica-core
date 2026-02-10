use crate::config::{DEFAULT_ASSET_ADDRESS, EthereumConfig};
use crate::scheduler::Task;
use crate::service::CoreService;
use crate::{
    error::{ServiceError, ServiceResult},
    persist::{PersistCtx, repo},
    util::u256_to_string,
};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockNumberOrTag;
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use log::{error, info, warn};
use std::str::FromStr;

pub async fn process_discovered_payment(ctx: &PersistCtx, payment: PaymentTx) -> ServiceResult<()> {
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

    let Some(tab) = repo::get_tab_by_id(ctx, payment.tab_id).await? else {
        warn!(
            "Tab {} not found while processing payment tx {}. Skipping.",
            tab_id_str, tx_hash
        );
        return Ok(());
    };
    if tab.server_address != payment.to.to_string() {
        warn!(
            "Recipient address does not match payment recipient for tab {}. Skipping.",
            tab_id_str
        );
        return Ok(());
    }

    let tab_user_address = match tab.user_address.parse::<Address>() {
        Ok(addr) => addr,
        Err(err) => {
            warn!(
                "Invalid user address {} for tab {} (err: {}). Skipping.",
                tab.user_address, tab_id_str, err
            );
            return Ok(());
        }
    };

    if tab_user_address != payment.from {
        warn!(
            "Payment sender {} does not match tab user {} for tab {}. Skipping.",
            payment.from, tab.user_address, tab_id_str
        );
        return Ok(());
    }

    let asset_address = payment
        .erc20_token
        .unwrap_or(DEFAULT_ASSET_ADDRESS.parse().map_err(anyhow::Error::from)?);

    let tab_asset_address = match tab.asset_address.parse::<Address>() {
        Ok(address) => address,
        Err(err) => {
            warn!(
                "Invalid tab asset address {} for tab {} (err: {}). Skipping.",
                &tab.asset_address, tab_id_str, err
            );
            return Ok(());
        }
    };

    if tab_asset_address != asset_address {
        warn!(
            "Payment asset does not match tab asset for tab {}. Skipping.",
            tab_id_str
        );
        return Ok(());
    }

    let block_hash = payment.block_hash.map(|hash| format!("{:#x}", hash));
    let tab_id = u256_to_string(payment.tab_id);

    // Record a pending user transaction if it doesn't already exist
    let rows_affected = repo::submit_pending_payment_transaction(
        ctx,
        repo::PendingPaymentInput {
            user_address: tab.user_address.clone(),
            recipient_address: tab.server_address.clone(),
            asset_address: asset_address.to_string(),
            transaction_id: tx_hash.clone(),
            amount,
            tab_id,
            block_number: payment.block_number,
            block_hash,
        },
    )
    .await?;

    if rows_affected == 0 {
        info!(
            "Payment transaction already exists for tab {}. Skipping.",
            tab_id_str
        );
        return Ok(());
    }

    Ok(())
}

impl CoreService {
    /// Submit user transactions and record payments on-chain for each discovered on-chain payment.
    pub async fn handle_discovered_payments(&self, events: Vec<PaymentTx>) -> ServiceResult<()> {
        for payment in events {
            process_discovered_payment(&self.inner.persist_ctx, payment).await?;
        }
        Ok(())
    }

    /// Confirm pending payments once they are past the safe head.
    pub async fn confirm_pending_payments(&self) -> ServiceResult<()> {
        let Some(safe_head) = self.safe_head().await? else {
            warn!("Safe head unavailable; skipping pending payment confirmation");
            return Ok(());
        };

        let pending =
            repo::get_pending_transactions_upto(&self.inner.persist_ctx, safe_head).await?;

        for tx in pending {
            let tx_hash = match B256::from_str(&tx.tx_id) {
                Ok(hash) => hash,
                Err(err) => {
                    warn!(
                        "Invalid tx hash {} (err: {err}); marking reverted",
                        tx.tx_id
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let block_number = match tx.block_number {
                Some(num) => num as u64,
                None => {
                    warn!(
                        "Pending tx {} missing block_number; marking reverted",
                        tx.tx_id
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let block = self
                .inner
                .read_provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .full()
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;

            let Some(block) = block else {
                warn!(
                    "Block {} not found for tx {}; marking reverted",
                    block_number, tx.tx_id
                );
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            };

            if let Some(expected_hash) = tx.block_hash.as_deref() {
                let actual_hash = format!("{:#x}", block.hash());
                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    warn!(
                        "Block hash mismatch for tx {} (expected {}, got {}); marking reverted",
                        tx.tx_id, expected_hash, actual_hash
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            }

            let receipt = self
                .inner
                .read_provider
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;

            let Some(receipt) = receipt else {
                warn!("Receipt missing for tx {}; marking reverted", tx.tx_id);
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            };

            if receipt.block_number != Some(block_number) {
                warn!(
                    "Receipt block mismatch for tx {} (expected {}, got {:?}); marking reverted",
                    tx.tx_id, block_number, receipt.block_number
                );
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            }

            if let Some(expected_hash) = tx.block_hash.as_deref()
                && let Some(receipt_hash) = receipt.block_hash
            {
                let actual_hash = format!("{:#x}", receipt_hash);
                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    warn!(
                        "Receipt hash mismatch for tx {} (expected {}, got {}); marking reverted",
                        tx.tx_id, expected_hash, actual_hash
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            }

            let Some(tab_id) = tx.tab_id.as_deref() else {
                warn!("Pending tx {} missing tab_id; marking reverted", tx.tx_id);
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            };
            let tab_id = U256::from_str(tab_id).map_err(|e| {
                ServiceError::InvalidParams(format!("invalid tab_id {tab_id}: {e}"))
            })?;
            let asset_address = Address::from_str(&tx.asset_address).map_err(|e| {
                ServiceError::InvalidParams(format!(
                    "invalid asset address {}: {e}",
                    tx.asset_address
                ))
            })?;
            let amount = U256::from_str(&tx.amount).map_err(|e| {
                ServiceError::InvalidParams(format!("invalid amount {}: {e}", tx.amount))
            })?;

            let record_tx = match self
                .inner
                .contract_api
                .record_payment(tab_id, asset_address, amount)
                .await
            {
                Ok(tx) => tx,
                Err(err) => {
                    error!(
                        "record_payment failed for tx {} (tab {}): {err}",
                        tx.tx_id, tab_id
                    );
                    continue;
                }
            };

            let record_hash = format!("{:#x}", record_tx.tx_hash);
            let record_block_hash = record_tx.block_hash.map(|hash| format!("{:#x}", hash));

            repo::mark_payment_transaction_recorded(
                &self.inner.persist_ctx,
                &tx.tx_id,
                record_hash,
                record_tx.block_number,
                record_block_hash,
            )
            .await?;
        }

        Ok(())
    }

    pub async fn finalize_recorded_payments(&self) -> ServiceResult<()> {
        let Some(safe_head) = self.safe_head().await? else {
            warn!("Safe head unavailable; skipping recorded payment finalization");
            return Ok(());
        };

        let recorded =
            repo::get_recorded_transactions_upto(&self.inner.persist_ctx, safe_head).await?;

        for tx in recorded {
            let record_tx_hash = match tx.record_tx_hash.as_deref() {
                Some(hash) => hash,
                None => {
                    warn!(
                        "Recorded tx {} missing record_tx_hash; marking reverted",
                        tx.tx_id
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let tx_hash = match B256::from_str(record_tx_hash) {
                Ok(hash) => hash,
                Err(err) => {
                    warn!(
                        "Invalid record_tx_hash {} (err: {err}); marking reverted",
                        record_tx_hash
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let record_block_number = match tx.record_tx_block_number {
                Some(num) => num as u64,
                None => {
                    warn!(
                        "Recorded tx {} missing record_tx_block_number; marking reverted",
                        tx.tx_id
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let receipt = self
                .inner
                .read_provider
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|e| ServiceError::Other(anyhow!(e)))?;

            let Some(receipt) = receipt else {
                warn!(
                    "Receipt missing for record tx {}; marking reverted",
                    record_tx_hash
                );
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            };

            if receipt.block_number != Some(record_block_number) {
                warn!(
                    "Record receipt block mismatch for tx {} (expected {}, got {:?}); marking reverted",
                    record_tx_hash, record_block_number, receipt.block_number
                );
                repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id).await?;
                continue;
            }

            if let Some(expected_hash) = tx.record_tx_block_hash.as_deref()
                && let Some(receipt_hash) = receipt.block_hash
            {
                let actual_hash = format!("{:#x}", receipt_hash);
                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    warn!(
                        "Record receipt hash mismatch for tx {} (expected {}, got {}); marking reverted",
                        record_tx_hash, expected_hash, actual_hash
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            }

            let tab_id = match tx.tab_id.as_deref() {
                Some(id) => match U256::from_str(id) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        warn!(
                            "Invalid tab_id {} for tx {} (err: {err}); marking reverted",
                            id, tx.tx_id
                        );
                        repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                            .await?;
                        continue;
                    }
                },
                None => {
                    warn!("Recorded tx {} missing tab_id; marking reverted", tx.tx_id);
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            let amount = match U256::from_str(&tx.amount) {
                Ok(value) => value,
                Err(err) => {
                    warn!(
                        "Invalid amount {} for tx {} (err: {err}); marking reverted",
                        tx.amount, tx.tx_id
                    );
                    repo::mark_payment_transaction_reverted(&self.inner.persist_ctx, &tx.tx_id)
                        .await?;
                    continue;
                }
            };

            if let Err(err) = repo::unlock_user_collateral(
                &self.inner.persist_ctx,
                tab_id,
                tx.asset_address.clone(),
                amount,
            )
            .await
            {
                error!(
                    "Failed to unlock collateral for tx {} (tab {}): {err}",
                    tx.tx_id, tab_id
                );
                continue;
            }

            repo::mark_payment_transaction_finalized(&self.inner.persist_ctx, &tx.tx_id).await?;
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

    async fn safe_head(&self) -> ServiceResult<Option<u64>> {
        let cfg = &self.inner.config.ethereum_config;
        match cfg.confirmation_mode()? {
            crate::config::ConfirmationMode::Depth => {
                let latest = self
                    .inner
                    .read_provider
                    .get_block_number()
                    .await
                    .map_err(|e| ServiceError::Other(anyhow!(e)))?;
                Ok(Some(latest.saturating_sub(cfg.number_of_blocks_to_confirm)))
            }
            crate::config::ConfirmationMode::Safe => {
                let block = self
                    .inner
                    .read_provider
                    .get_block_by_number(BlockNumberOrTag::Safe)
                    .full()
                    .await
                    .map_err(|e| ServiceError::Other(anyhow!(e)))?;
                Ok(block.map(|b| b.header.number))
            }
            crate::config::ConfirmationMode::Finalized => {
                let block = self
                    .inner
                    .read_provider
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .full()
                    .await
                    .map_err(|e| ServiceError::Other(anyhow!(e)))?;
                Ok(block.map(|b| b.header.number))
            }
        }
    }
}

pub struct ScanPaymentsTask(CoreService);
pub struct ConfirmPaymentsTask(CoreService);
pub struct FinalizePaymentsTask(CoreService);

impl ScanPaymentsTask {
    pub fn new(service: CoreService) -> Self {
        Self(service)
    }

    fn ethereum_config(&self) -> &EthereumConfig {
        &self.0.inner.config.ethereum_config
    }
}

impl ConfirmPaymentsTask {
    pub fn new(service: CoreService) -> Self {
        Self(service)
    }

    fn ethereum_config(&self) -> &EthereumConfig {
        &self.0.inner.config.ethereum_config
    }
}

impl FinalizePaymentsTask {
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
        let lookback = self.ethereum_config().number_of_pending_blocks;
        self.0.scan_blockchain(lookback).await
    }
}

#[async_trait]
impl Task for ConfirmPaymentsTask {
    fn cron_pattern(&self) -> String {
        self.ethereum_config().cron_job_settings.clone()
    }

    async fn run(&self) -> anyhow::Result<()> {
        self.0
            .confirm_pending_payments()
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl Task for FinalizePaymentsTask {
    fn cron_pattern(&self) -> String {
        self.ethereum_config().cron_job_settings.clone()
    }

    async fn run(&self) -> anyhow::Result<()> {
        self.0
            .finalize_recorded_payments()
            .await
            .map_err(anyhow::Error::from)
    }
}
