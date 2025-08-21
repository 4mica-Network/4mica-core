use alloy::consensus::TxEnvelope;
use alloy::primitives::private::serde::ser::Error;
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
    if tx.from != user_address {
        return Err(rpc::invalid_params_error(
            "User address does not match transaction sender",
        ));
    }

    // TODO: which transaction types do we support?
    let (to, value) = match &tx.inner {
        TxEnvelope::Legacy(tx) => {
            return Err(Error::custom("unsupported transaction type: Legacy"));
        }
        TxEnvelope::Eip2930(tx) => {
            return Err(Error::custom("unsupported transaction type: EIP2930"));
        }
        TxEnvelope::Eip1559(tx) => {
            return Err(Error::custom("unsupported transaction type: EIP1559"));
        }
        TxEnvelope::Eip4844(tx) => {
            return Err(Error::custom("unsupported transaction type: EIP4844"));
        }
        TxEnvelope::Eip7702(tx) => (tx.tx().to, tx.tx().value),
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

// --- Helper to convert amount to U256 ---
pub fn convert_amount_to_u256(amount: f64) -> RpcResult<U256> {
    let wei = amount as u128;
    Ok(U256::from(wei))
}
