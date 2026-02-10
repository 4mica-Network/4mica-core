use crate::config::{DEFAULT_ASSET_ADDRESS, EthereumConfig};
use crate::scheduler::Task;
use crate::service::CoreService;
use crate::{
    error::ServiceResult,
    persist::{PersistCtx, repo},
    util::u256_to_string,
};
use alloy::primitives::Address;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use log::{error, info, warn};

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

    // Record a pending user transaction if it doesn't already exist
    let rows_affected = repo::submit_pending_payment_transaction(
        ctx,
        repo::PendingPaymentInput {
            user_address: tab.user_address.clone(),
            recipient_address: tab.server_address.clone(),
            asset_address: asset_address.to_string(),
            transaction_id: tx_hash.clone(),
            amount,
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
