use std::str::FromStr;

use log::info;

use alloy::{
    consensus::{Transaction as AlloyTransaction, TxEnvelope},
    primitives::{Address, B256, TxKind, U256},
    providers::Provider,
    rpc::types::eth::{Block, BlockNumberOrTag, Transaction},
};

use crate::error::{Result, TxProcessingError};

/// Simple representation of a tab payment discovered on-chain.
#[derive(Debug, Clone)]
pub struct PaymentTx {
    pub block_number: u64,
    pub block_hash: Option<B256>,
    pub block_timestamp: Option<u64>,
    pub tx_hash: B256,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
    pub tab_id: U256,
    pub req_id: U256,
    pub erc20_token: Option<Address>,
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

/// Scan the last `lookback` blocks up to the provided head and return all matching
/// payment transactions, parsed into `PaymentTx`. No DB writes, no on-chain calls.
pub async fn scan_tab_payments<P: Provider>(
    provider: &P,
    lookback: u64,
    head: BlockNumberOrTag,
) -> Result<Vec<PaymentTx>> {
    let latest = match head {
        BlockNumberOrTag::Number(n) => n,
        tag => {
            let block = provider
                .get_block_by_number(tag)
                .full()
                .await
                .map_err(|e| TxProcessingError::Rpc(e.into()))?;
            let Some(block) = block else {
                return Ok(Vec::new());
            };
            block.header.number
        }
    };
    let start = latest.saturating_sub(lookback);

    let mut found = Vec::new();

    for num in start..=latest {
        // fetch the block
        let Some(block) = get_block(provider, num).await? else {
            continue;
        };
        let block_hash = Some(block.hash());
        let block_timestamp = Some(block.header.timestamp);

        // iterate over tx hashes
        for tx in block.transactions.into_transactions() {
            // look for tab_id / req_id
            let Some((tab_id, req_id)) = extract_tab_req(&tx) else {
                continue;
            };

            // convert to our PaymentTx type
            let Some(rec) =
                parse_eth_transfer(&tx, num, block_hash, block_timestamp, tab_id, req_id)?
            else {
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

async fn get_block<P: Provider>(provider: &P, num: u64) -> Result<Option<Block>> {
    provider
        .get_block_by_number(BlockNumberOrTag::Number(num))
        .full()
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

fn extract_tab_req(tx: &Transaction) -> Option<(U256, U256)> {
    extract_tab_req_from_input(tx.inner.input())
}

fn extract_tab_req_from_input(input: &[u8]) -> Option<(U256, U256)> {
    let s = std::str::from_utf8(input).ok()?;

    let (mut tab, mut req) = (None, None);
    for part in s.split(';') {
        if let Some(v) = part.strip_prefix("tab_id:") {
            tab = Some(v);
        } else if let Some(v) = part.strip_prefix("req_id:") {
            req = Some(v);
        }
    }

    let t = tab.filter(|s| !s.is_empty())?;
    let r = req.filter(|s| !s.is_empty())?;
    Some((U256::from_str(t).ok()?, U256::from_str(r).ok()?))
}

fn parse_eth_transfer(
    tx: &Transaction,
    block_number: u64,
    block_hash: Option<B256>,
    block_timestamp: Option<u64>,
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
        block_hash,
        block_timestamp,
        tx_hash: *tx.inner.hash(),
        from,
        to,
        amount,
        tab_id,
        req_id,
        erc20_token: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tab_req_parses_valid_markers() {
        let parsed = extract_tab_req_from_input(b"tab_id:42;req_id:7");

        assert_eq!(parsed, Some((U256::from(42), U256::from(7))));
    }

    #[test]
    fn extract_tab_req_skips_malformed_numeric_markers() {
        assert_eq!(extract_tab_req_from_input(b"tab_id:a;req_id:0"), None);
        assert_eq!(extract_tab_req_from_input(b"tab_id:0;req_id:a"), None);
        assert_eq!(extract_tab_req_from_input(b"tab_id:;req_id:"), None);
    }

    #[test]
    fn extract_tab_req_skips_non_utf8_input() {
        assert_eq!(extract_tab_req_from_input(&[0xff, 0xfe]), None);
    }
}
