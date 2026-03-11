use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::{SolValue, sol};
use anyhow::bail;
use std::str::FromStr;
use std::sync::LazyLock;

use super::PaymentGuaranteeValidationPolicyV2;

const VALIDATION_SUBJECT_BINDING_DOMAIN: &str = "4MICA_VALIDATION_SUBJECT_V1";
const VALIDATION_REQUEST_BINDING_DOMAIN: &str = "4MICA_VALIDATION_REQUEST_V1";
static VALIDATION_SUBJECT_BINDING_DOMAIN_HASH: LazyLock<B256> =
    LazyLock::new(|| keccak256(VALIDATION_SUBJECT_BINDING_DOMAIN.as_bytes()));
static VALIDATION_REQUEST_BINDING_DOMAIN_HASH: LazyLock<B256> =
    LazyLock::new(|| keccak256(VALIDATION_REQUEST_BINDING_DOMAIN.as_bytes()));

sol! {
    struct ValidationSubjectPayloadV1 {
        bytes32 bindingDomain;
        uint256 tabId;
        uint256 reqId;
        address user;
        address recipient;
        uint256 amount;
        address asset;
        uint64 timestamp;
    }

    struct ValidationRequestPayloadV1 {
        bytes32 bindingDomain;
        uint256 chainId;
        address validationRegistryAddress;
        address validatorAddress;
        uint256 validatorAgentId;
        bytes32 validationSubjectHash;
        uint8 minValidationScore;
        bytes32 requiredValidationTagHash;
    }
}

pub fn compute_validation_subject_hash(
    user_address: &str,
    recipient_address: &str,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    asset_address: &str,
    timestamp: u64,
) -> anyhow::Result<[u8; 32]> {
    let payload = ValidationSubjectPayloadV1 {
        bindingDomain: *VALIDATION_SUBJECT_BINDING_DOMAIN_HASH,
        tabId: tab_id,
        reqId: req_id,
        user: parse_address("user_address", user_address)?,
        recipient: parse_address("recipient_address", recipient_address)?,
        amount,
        asset: parse_address("asset_address", asset_address)?,
        timestamp,
    }
    .abi_encode();

    Ok(keccak256(payload).into())
}

pub fn compute_validation_request_hash(
    policy: &PaymentGuaranteeValidationPolicyV2,
) -> anyhow::Result<[u8; 32]> {
    validate_min_validation_score(policy.min_validation_score)?;
    let payload = ValidationRequestPayloadV1 {
        bindingDomain: *VALIDATION_REQUEST_BINDING_DOMAIN_HASH,
        chainId: U256::from(policy.validation_chain_id),
        validationRegistryAddress: policy.validation_registry_address,
        validatorAddress: policy.validator_address,
        validatorAgentId: policy.validator_agent_id,
        validationSubjectHash: policy.validation_subject_hash,
        minValidationScore: policy.min_validation_score,
        requiredValidationTagHash: keccak256(policy.required_validation_tag.as_bytes()),
    }
    .abi_encode();

    Ok(keccak256(payload).into())
}

fn validate_min_validation_score(score: u8) -> anyhow::Result<()> {
    if !(1..=100).contains(&score) {
        bail!("min_validation_score must be between 1 and 100");
    }
    Ok(())
}

fn parse_address(field: &str, value: &str) -> anyhow::Result<Address> {
    Address::from_str(value).map_err(|_| anyhow::anyhow!("{field} is not a valid address: {value}"))
}
