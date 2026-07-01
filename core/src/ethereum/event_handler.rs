use alloy::rpc::types::Log;
use async_trait::async_trait;

use crate::error::BlockchainListenerError;

#[async_trait]
pub trait EthereumEventHandler: Send + Sync {
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_cycle_committed(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_debtor_paid(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_creditor_claimed(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_debtor_defaulted(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_cycle_finalized(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_settlement_skipped(&self, log: Log) -> Result<(), BlockchainListenerError>;

    async fn handle_admin_event(
        &self,
        log: Log,
        event_name: &str,
    ) -> Result<(), BlockchainListenerError>;

    async fn handle_unknown_event(&self, log: Log) -> Result<(), BlockchainListenerError>;

    /// Notify the handler that the scanner advanced its confirmed head (one successful tick), so it
    /// can track scan liveness. Used to detect a stale on-chain `withdrawalGracePeriod` cache before
    /// minting guarantees. Default no-op; the production handler records the timestamp.
    fn note_scan_progress(&self) {}
}
