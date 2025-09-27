use std::str::FromStr;

use log::{debug, info};

use alloy::{
    consensus::{Transaction as AlloyTransaction, TxEnvelope},
    primitives::{Address, B256, TxKind, U256},
    providers::Provider,
    rpc::types::eth::{Block, BlockNumberOrTag, Transaction},
};

use crate::error::{Result, TxProcessingError};

/// Simple, structured representation of a tab payment discovered on-chain.
/// No persistence or side-effects here.
#[derive(Debug, Clone)]
pub struct PaymentTx {
    pub block_number: u64,
    pub tx_hash: B256,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
    pub tab_id: U256,
    pub req_id: U256,
}

/// Fetch a transaction by hash.
pub async fn fetch_transaction<P: Provider>(
    provider: &P,
    tx_hash: impl Into<B256>,
) -> Result<Transaction> {
    let hash: B256 = tx_hash.into();
    provider
        .get_transaction_by_hash(hash)
        .await
        .map_err(|e| TxProcessingError::Rpc(e.into()))?
        .ok_or(TxProcessingError::NotFound)
}

/// Validate basic transaction fields.
pub fn validate_transaction(
    tx: &Transaction,
    user_address: Address,
    recipient_address: Address,
    expected_amount: U256,
) -> Result<()> {
    if tx.inner.signer() != user_address {
        return Err(TxProcessingError::InvalidParams("sender mismatch".into()));
    }

    let (to, value) = extract_to_value(tx.inner.inner()).ok_or(TxProcessingError::InvalidTxType)?;

    if to != recipient_address {
        return Err(TxProcessingError::InvalidParams(
            "recipient mismatch".into(),
        ));
    }

    if value != expected_amount {
        return Err(TxProcessingError::InvalidParams("amount mismatch".into()));
    }

    Ok(())
}

/// Helper to parse Ethereum address.
pub fn parse_eth_address(addr: &str, field: &str) -> Result<Address> {
    addr.parse()
        .map_err(|_| TxProcessingError::InvalidParams(format!("Invalid {field} address")))
}

/// Scan the last `lookback` blocks and return all matching payment transactions,
/// parsed into `PaymentTx`. No DB writes, no on-chain calls.
pub async fn scan_tab_payments<P: Provider>(provider: &P, lookback: u64) -> Result<Vec<PaymentTx>> {
    let latest = provider
        .get_block_number()
        .await
        .map_err(|e| TxProcessingError::Rpc(e.into()))?;
    let start = latest.saturating_sub(lookback);

    let mut found = Vec::new();

    for num in start..=latest {
        // fetch the block
        let Some(block) = get_block(provider, num).await? else {
            continue;
        };

        // iterate over tx hashes
        for tx_hash_bytes in block.transactions.hashes() {
            // &[u8; 32] -> B256
            let tx_hash: B256 = B256::from(*tx_hash_bytes);

            let tx = match fetch_transaction(provider, tx_hash).await {
                Ok(t) => t,
                Err(err) => {
                    debug!(
                        "block {}: skip tx {:?}, fetch failed: {err}",
                        num, tx_hash_bytes
                    );
                    continue;
                }
            };

            // look for tab_id / req_id
            let Some((tab_id, req_id)) = extract_tab_req(&tx)? else {
                continue;
            };

            // convert to our PaymentTx type
            let Some(rec) = to_payment_tx(&tx, num, tab_id, req_id)? else {
                continue; // not an EIP-7702 tx
            };

            info!(
                "Discovered payment tx block={} hash={:?} from={:?} to={:?} \
                 amount={} tab_id={} req_id={}",
                num, rec.tx_hash, rec.from, rec.to, rec.amount, rec.tab_id, rec.req_id
            );

            found.push(rec);
        }
    }

    Ok(found)
}

async fn get_block<P: Provider>(provider: &P, num: u64) -> Result<Option<Block<Transaction>>> {
    provider
        .get_block_by_number(BlockNumberOrTag::Number(num.into()))
        .await
        .map_err(|e| TxProcessingError::Rpc(e.into()))
}

fn extract_to_value(env: &TxEnvelope) -> Option<(Address, U256)> {
    match env {
        TxEnvelope::Legacy(inner) => match inner.tx().to {
            TxKind::Call(to) => Some((to, inner.tx().value)),
            TxKind::Create => None,
        },
        TxEnvelope::Eip2930(inner) => match inner.tx().to {
            TxKind::Call(to) => Some((to, inner.tx().value)),
            TxKind::Create => None,
        },
        TxEnvelope::Eip1559(inner) => match inner.tx().to {
            TxKind::Call(to) => Some((to, inner.tx().value)),
            TxKind::Create => None,
        },
        TxEnvelope::Eip4844(inner) => inner.tx().tx().to().map(|to| (to, inner.tx().tx().value())),
        TxEnvelope::Eip7702(inner) => inner.tx().to().map(|to| (to, inner.tx().value())),
    }
}

fn extract_tab_req(tx: &Transaction) -> Result<Option<(U256, U256)>> {
    // Skip if input is not valid UTF-8 instead of failing the whole scan.
    let s = match std::str::from_utf8(tx.inner.input()) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let tab = s.split(';').find_map(|p| p.strip_prefix("tab_id:"));
    let req = s.split(';').find_map(|p| p.strip_prefix("req_id:"));

    Ok(match (tab, req) {
        (Some(t), Some(r)) => {
            // parse both as 256-bit integers
            let t_u256 = U256::from_str(t).map_err(|_| anyhow::anyhow!("invalid tab_id: {t}"))?;
            let r_u256 = U256::from_str(r).map_err(|_| anyhow::anyhow!("invalid req_id: {r}"))?;
            Some((t_u256, r_u256))
        }
        _ => None,
    })
}

fn to_payment_tx(
    tx: &Transaction,
    block_number: u64,
    tab_id: U256,
    req_id: U256,
) -> Result<Option<PaymentTx>> {
    let from = tx.inner.signer();

    let (to, amount) = match extract_to_value(tx.inner.inner()) {
        Some(tv) => tv,
        None => return Ok(None), // skip unknown types
    };

    Ok(Some(PaymentTx {
        block_number,
        tx_hash: *tx.inner.hash(),
        from,
        to,
        amount,
        tab_id,
        req_id,
    }))
}
