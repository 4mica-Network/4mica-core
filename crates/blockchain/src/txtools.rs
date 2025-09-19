use alloy::consensus::TxEnvelope;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Transaction;
use log::error;
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

// --- validate transaction fields ---
pub fn validate_transaction(
    tx: &Transaction,
    user_address: Address,
    recipient_address: Address,
    expected_amount: U256,
) -> RpcResult<()> {
    if tx.inner.signer() != user_address {
        return Err(rpc::invalid_params_error(
            "User address does not match transaction sender",
        ));
    }

    // TODO: which transaction types do we support?
    let (to, value) = match tx.inner.inner() {
        TxEnvelope::Eip7702(tx) => (tx.tx().to, tx.tx().value),
        _ => return Err(rpc::invalid_params_error("Invalid transaction type")),
    };

    if to != recipient_address {
        return Err(rpc::invalid_params_error(
            "Recipient address does not match transaction recipient",
        ));
    }

    if value != expected_amount {
        return Err(rpc::invalid_params_error(
            "Transaction amount does not match",
        ));
    }

    Ok(())
}

// --- Helper to parse Ethereum address ---
pub fn parse_eth_address(addr: &str, field: &str) -> RpcResult<Address> {
    addr.parse().map_err(|err| {
        error!("Invalid Ethereum address for {field}: {err}");
        rpc::invalid_params_error(&format!("Invalid {field} address"))
    })
}
