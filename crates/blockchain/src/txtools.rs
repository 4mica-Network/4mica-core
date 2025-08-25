use alloy::consensus::TxEnvelope;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Transaction;
use log::error;
use rpc::common::UserTransactionInfo;
use rpc::RpcResult;

// --- function to fetch a transaction ---
pub async fn fetch_transaction<P: Provider>(provider: &P, tx_hash: B256) -> RpcResult<Transaction> {
    provider
        .get_transaction_by_hash(tx_hash)
        .await
        .map_err(|err| {
            error!("Failed to get transaction from provider: {err}");
            rpc::internal_error()
        })?
        .ok_or_else(|| {
            error!("Transaction not found");
            rpc::invalid_params_error("Transaction not found")
        })
}

// --- Helper to parse Ethereum address ---
pub fn parse_eth_address(addr: &str, field: &str) -> RpcResult<Address> {
    addr.parse().map_err(|err| {
        error!("Invalid Ethereum address for {field}: {err}");
        rpc::invalid_params_error(&format!("Invalid {field} address"))
    })
}

// --- Helper to convert amount to U256 ---
pub fn convert_amount_to_u256(amount: f64) -> RpcResult<U256> {
    let wei = amount as u128;
    Ok(U256::from(wei))
}
