use std::str::FromStr;

use alloy::primitives::{Address, keccak256};
use alloy::sol;
use alloy::sol_types::{SolStruct, SolValue};
use alloy::{primitives::B256, sol_types::eip712_domain};
use anyhow::anyhow;
use rpc::{CorePublicParameters, PaymentGuaranteeRequestClaimsV1};

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256  tabId;
        uint256  reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
    }
}

pub fn eip712_digest(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaimsV1,
) -> anyhow::Result<B256> {
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let message = SolGuaranteeRequestClaimsV1 {
        user: Address::from_str(&claims.user_address)
            .map_err(|_| anyhow!("invalid claims.user_address"))?,
        recipient: Address::from_str(&claims.recipient_address)
            .map_err(|_| anyhow!("invalid claims.recipient_address"))?,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)
            .map_err(|_| anyhow!("invalid claims.asset_address"))?,
        timestamp: claims.timestamp,
    };

    Ok(message.eip712_signing_hash(&domain))
}

pub fn eip191_digest(
    claims: &PaymentGuaranteeRequestClaimsV1,
    user: Address,
    recipient: Address,
) -> anyhow::Result<B256> {
    let data = SolGuaranteeRequestClaimsV1 {
        user,
        recipient,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)
            .map_err(|_| anyhow!("invalid claims.asset_address"))?,
        timestamp: claims.timestamp,
    }
    .abi_encode();

    // "\x19Ethereum Signed Message:\n" + len + data; then keccak256
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);

    Ok(keccak256(prefixed))
}
