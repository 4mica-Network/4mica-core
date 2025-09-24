use crate::{
    error,
    persist::{PersistCtx, repo},
};
use alloy::{
    consensus::TxEnvelope,
    primitives::{Address, B256, U256},
    providers::Provider,
    rpc::types::{Block, BlockNumber, Transaction},
};
use log::{error, info};
use rpc::RpcResult;

///  function to fetch a transaction
pub async fn fetch_transaction<P: Provider>(provider: &P, tx_hash: B256) -> Result<Transaction> {
    provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or(TxProcessingError::NotFound)
}

/// Validate basic transaction fields
pub fn validate_transaction(
    tx: &Transaction,
    user_address: Address,
    recipient_address: Address,
    expected_amount: U256,
) -> Result<()> {
    if tx.inner.signer() != user_address {
        return Err(rpc::invalid_params_error("sender mismatch").into());
    }

    let (to, value) = match tx.inner.inner() {
        TxEnvelope::Eip7702(inner) => (inner.tx().to, inner.tx().value),
        _ => return Err(TxProcessingError::InvalidTxType),
    };

    if to != recipient_address {
        return Err(rpc::invalid_params_error("recipient mismatch").into());
    }

    if value != expected_amount {
        return Err(rpc::invalid_params_error("amount mismatch").into());
    }

    Ok(())
}

/// Helper to parse Ethereum address
pub fn parse_eth_address(addr: &str, field: &str) -> Result<Address> {
    addr.parse()
        .map_err(|_| rpc::invalid_params_error(&format!("Invalid {field} address")).into())
}

/// Placeholder – to be implemented with real smart-contract call
async fn register_payment_on_chain(tab_id: &str, req_id: &str) -> rpc::RpcResult<()> {
    info!(
        "(placeholder) register_payment called on-chain for tab_id={} req_id={}",
        tab_id, req_id
    );
    Ok(())
}

/// Scan the last `lookback` blocks and process all matching payment transactions.
pub async fn process_tab_payments<P: Provider>(
    provider: &P,
    ctx: &PersistCtx,
    lookback: u64,
) -> Result<()> {
    let latest = provider.get_block_number().await?;
    let start = latest.saturating_sub(lookback);

    for num in start..=latest {
        process_block(provider, ctx, num).await?;
    }
    Ok(())
}

async fn process_block<P: Provider>(provider: &P, ctx: &PersistCtx, num: u64) -> Result<()> {
    let block: Option<Block<Transaction>> = provider
        .get_block_by_number(BlockNumber::Number(num.into()))
        .await?;

    if let Some(block) = block {
        for tx in block.transactions {
            if let Some((tab_id, req_id)) = extract_tab_req(&tx)? {
                process_payment_tx(ctx, &tx, &tab_id, &req_id).await?;
            }
        }
    }
    Ok(())
}

fn extract_tab_req(tx: &Transaction) -> Result<Option<(String, String)>> {
    let s = std::str::from_utf8(tx.inner.input())?;
    let tab = s.split(';').find_map(|p| p.strip_prefix("tab_id:"));
    let req = s.split(';').find_map(|p| p.strip_prefix("req_id:"));
    Ok(match (tab, req) {
        (Some(t), Some(r)) => Some((t.to_string(), r.to_string())),
        _ => None,
    })
}

/// Record the payment, settle the tab and call the on-chain placeholder.
async fn process_payment_tx(
    ctx: &PersistCtx,
    tx: &Transaction,
    tab_id: &str,
    req_id: &str,
) -> Result<()> {
    let from = format!("{:?}", tx.inner.signer());
    let to = match tx.inner.inner() {
        TxEnvelope::Eip7702(inner) => inner.tx().to,
        _ => return Err(TxProcessingError::InvalidTxType),
    };
    let to = format!("{:?}", to);
    let amount = match tx.inner.inner() {
        TxEnvelope::Eip7702(inner) => inner.tx().value,
        _ => U256::ZERO,
    };

    info!(
        "Processing payment tx: from={} to={} tab_id={} req_id={} amount={}",
        from, to, tab_id, req_id, amount
    );

    repo::submit_payment_transaction(
        ctx,
        from.clone(),
        to.clone(),
        format!("{:?}", tx.hash),
        amount,
    )
    .await?;

    repo::remunerate_recipient(ctx, tab_id.to_string(), amount).await?;

    register_payment_on_chain(tab_id, req_id).await
}

async fn register_payment_on_chain(tab_id: &str, req_id: &str) -> Result<()> {
    info!(
        "(placeholder) register_payment on-chain: tab_id={} req_id={}",
        tab_id, req_id
    );
    Ok(())
}

/// Placeholder for the actual smart-contract call.
async fn register_payment_on_chain(tab_id: &str, req_id: &str) -> RpcResult<()> {
    info!(
        "(placeholder) register_payment called on-chain for tab_id={} req_id={}",
        tab_id, req_id
    );
    Ok(())
}
