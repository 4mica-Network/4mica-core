use std::str::FromStr;

use alloy::primitives::{Address, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{SolStruct, SolValue};
use alloy::{primitives::B256, sol_types::eip712_domain};
use anyhow::anyhow;
use rpc::{CorePublicParameters, PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestClaimsV2};

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256  tabId;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
    }

    struct SolGuaranteeRequestClaimsV2 {
        address user;
        address recipient;
        uint256 tabId;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64 timestamp;
        address validationRegistryAddress;
        bytes32 validationRequestHash;
        uint256 validationChainId;
        address validatorAddress;
        uint256 validatorAgentId;
        uint8 minValidationScore;
        bytes32 validationSubjectHash;
        string requiredValidationTag;
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

pub fn eip712_digest_v2(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaimsV2,
) -> anyhow::Result<B256> {
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let message = SolGuaranteeRequestClaimsV2 {
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
        validationRegistryAddress: claims.validation_policy.validation_registry_address,
        validationRequestHash: claims.validation_policy.validation_request_hash,
        validationChainId: U256::from(claims.validation_policy.validation_chain_id),
        validatorAddress: claims.validation_policy.validator_address,
        validatorAgentId: claims.validation_policy.validator_agent_id,
        minValidationScore: claims.validation_policy.min_validation_score,
        validationSubjectHash: claims.validation_policy.validation_subject_hash,
        requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
    };

    Ok(message.eip712_signing_hash(&domain))
}

pub fn eip191_digest_v2(
    claims: &PaymentGuaranteeRequestClaimsV2,
    user: Address,
    recipient: Address,
) -> anyhow::Result<B256> {
    let data = SolGuaranteeRequestClaimsV2 {
        user,
        recipient,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)
            .map_err(|_| anyhow!("invalid claims.asset_address"))?,
        timestamp: claims.timestamp,
        validationRegistryAddress: claims.validation_policy.validation_registry_address,
        validationRequestHash: claims.validation_policy.validation_request_hash,
        validationChainId: U256::from(claims.validation_policy.validation_chain_id),
        validatorAddress: claims.validation_policy.validator_address,
        validatorAgentId: claims.validation_policy.validator_agent_id,
        minValidationScore: claims.validation_policy.min_validation_score,
        validationSubjectHash: claims.validation_policy.validation_subject_hash,
        requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
    }
    .abi_encode();

    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);

    Ok(keccak256(prefixed))
}
