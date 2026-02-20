use alloy::rpc::types::Log;
use async_trait::async_trait;

use crate::error::BlockchainListenerError;

#[async_trait]
pub trait EthereumEventHandler: Send + Sync {
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_recipient_remunerated(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_payment_recorded(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_tab_paid(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_admin_event(
        &self,
        log: Log,
        event_name: &str,
    ) -> Result<(), BlockchainListenerError>;

    async fn handle_unknown_event(&self, log: Log) -> Result<(), BlockchainListenerError>;
}
