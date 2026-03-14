use std::str::FromStr;

use alloy::primitives::{Address, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{SolStruct, SolValue};
use alloy::{primitives::B256, sol_types::eip712_domain};
use anyhow::anyhow;
use rpc::{CorePublicParameters, PaymentGuaranteeRequestClaims};

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

// ── unified dispatch helpers ────────────────────────────────────────────────

/// EIP-712 signing hash for any supported guarantee request version.
/// Add a new `PaymentGuaranteeRequestClaims` variant here when introducing V3.
pub fn eip712_digest_for_claims(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaims,
) -> anyhow::Result<B256> {
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let parse = |field: &'static str, value: &str| {
        Address::from_str(value).map_err(|_| anyhow!("invalid {field}"))
    };

    match claims {
        PaymentGuaranteeRequestClaims::V1(c) => {
            let message = SolGuaranteeRequestClaimsV1 {
                user: parse("claims.user_address", &c.user_address)?,
                recipient: parse("claims.recipient_address", &c.recipient_address)?,
                tabId: c.tab_id,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse("claims.asset_address", &c.asset_address)?,
                timestamp: c.timestamp,
            };
            Ok(message.eip712_signing_hash(&domain))
        }
        PaymentGuaranteeRequestClaims::V2(c) => {
            let message = SolGuaranteeRequestClaimsV2 {
                user: parse("claims.user_address", &c.user_address)?,
                recipient: parse("claims.recipient_address", &c.recipient_address)?,
                tabId: c.tab_id,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse("claims.asset_address", &c.asset_address)?,
                timestamp: c.timestamp,
                validationRegistryAddress: c.validation_policy.validation_registry_address,
                validationRequestHash: c.validation_policy.validation_request_hash,
                validationChainId: U256::from(c.validation_policy.validation_chain_id),
                validatorAddress: c.validation_policy.validator_address,
                validatorAgentId: c.validation_policy.validator_agent_id,
                minValidationScore: c.validation_policy.min_validation_score,
                validationSubjectHash: c.validation_policy.validation_subject_hash,
                requiredValidationTag: c.validation_policy.required_validation_tag.clone(),
            };
            Ok(message.eip712_signing_hash(&domain))
        }
    }
}

/// EIP-191 signing hash for any supported guarantee request version.
/// Add a new `PaymentGuaranteeRequestClaims` variant here when introducing V3.
pub fn eip191_digest_for_claims(
    claims: &PaymentGuaranteeRequestClaims,
    user: Address,
    recipient: Address,
) -> anyhow::Result<B256> {
    let parse = |field: &'static str, value: &str| {
        Address::from_str(value).map_err(|_| anyhow!("invalid {field}"))
    };

    let data = match claims {
        PaymentGuaranteeRequestClaims::V1(c) => SolGuaranteeRequestClaimsV1 {
            user,
            recipient,
            tabId: c.tab_id,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse("claims.asset_address", &c.asset_address)?,
            timestamp: c.timestamp,
        }
        .abi_encode(),
        PaymentGuaranteeRequestClaims::V2(c) => SolGuaranteeRequestClaimsV2 {
            user,
            recipient,
            tabId: c.tab_id,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse("claims.asset_address", &c.asset_address)?,
            timestamp: c.timestamp,
            validationRegistryAddress: c.validation_policy.validation_registry_address,
            validationRequestHash: c.validation_policy.validation_request_hash,
            validationChainId: U256::from(c.validation_policy.validation_chain_id),
            validatorAddress: c.validation_policy.validator_address,
            validatorAgentId: c.validation_policy.validator_agent_id,
            minValidationScore: c.validation_policy.min_validation_score,
            validationSubjectHash: c.validation_policy.validation_subject_hash,
            requiredValidationTag: c.validation_policy.required_validation_tag.clone(),
        }
        .abi_encode(),
    };

    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    Ok(keccak256(prefixed))
}
