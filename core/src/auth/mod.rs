use crate::error::{ServiceError, ServiceResult};
use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use alloy_sol_types::{SolStruct, SolValue, eip712_domain, sol};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, SigningScheme,
};
use std::str::FromStr;

pub mod access;
pub mod constants;
pub mod jwt;
pub mod siwe;
pub mod utils;

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

/// Verify that the request was signed by `claims.user_address`
pub fn verify_guarantee_request_signature(
    params: &CorePublicParameters,
    req: &PaymentGuaranteeRequest,
) -> ServiceResult<()> {
    let (user_addr, recipient_addr) = claims_participants(&req.claims)?;

    let user_addr = Address::from_str(user_addr)
        .map_err(|_| ServiceError::InvalidParams("invalid user address".into()))?;
    let recipient_addr = Address::from_str(recipient_addr)
        .map_err(|_| ServiceError::InvalidParams("invalid recipient address".into()))?;

    let sig_bytes = crate::util::normalize_and_decode_hex(&req.signature)
        .map_err(|_| ServiceError::InvalidParams("invalid hex signature".into()))?;
    let sig = Signature::try_from(&sig_bytes[..])
        .map_err(|_| ServiceError::InvalidParams("invalid signature length".into()))?;

    // TODO: do we need something like this?
    // if !is_low_s(&sig) {
    //     warn!("High-S signature rejected");
    //     return Err(ServiceError::InvalidParams("Invalid signature".into()));
    // }

    let digest: B256 =
        digest_for_guarantee_request(params, &req.scheme, &req.claims, user_addr, recipient_addr)?;

    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|_| ServiceError::InvalidParams("signature recovery failed".into()))?;

    if recovered != user_addr {
        return Err(ServiceError::InvalidParams("Invalid signature".into()));
    }
    Ok(())
}

fn claims_participants(claims: &PaymentGuaranteeRequestClaims) -> ServiceResult<(&str, &str)> {
    match claims {
        PaymentGuaranteeRequestClaims::V1(claims) => Ok((
            claims.user_address.as_str(),
            claims.recipient_address.as_str(),
        )),
        PaymentGuaranteeRequestClaims::V2(claims) => Ok((
            claims.user_address.as_str(),
            claims.recipient_address.as_str(),
        )),
    }
}

fn digest_for_guarantee_request(
    params: &CorePublicParameters,
    scheme: &SigningScheme,
    claims: &PaymentGuaranteeRequestClaims,
    user_addr: Address,
    recipient_addr: Address,
) -> ServiceResult<B256> {
    match scheme {
        SigningScheme::Eip712 => eip712_digest(params, claims),
        SigningScheme::Eip191 => eip191_digest(claims, user_addr, recipient_addr),
    }
}

/// Compute an EIP-712 signing hash for any supported guarantee request version.
fn eip712_digest(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaims,
) -> ServiceResult<B256> {
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let parse_addr = |field: &'static str, value: &str| {
        Address::from_str(value)
            .map_err(|_| ServiceError::InvalidParams(format!("invalid {field}")))
    };

    match claims {
        PaymentGuaranteeRequestClaims::V1(c) => {
            let message = SolGuaranteeRequestClaimsV1 {
                user: parse_addr("user address", &c.user_address)?,
                recipient: parse_addr("recipient address", &c.recipient_address)?,
                tabId: c.tab_id,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse_addr("asset address", &c.asset_address)?,
                timestamp: c.timestamp,
            };
            Ok(message.eip712_signing_hash(&domain))
        }
        PaymentGuaranteeRequestClaims::V2(c) => {
            let message = SolGuaranteeRequestClaimsV2 {
                user: parse_addr("user address", &c.user_address)?,
                recipient: parse_addr("recipient address", &c.recipient_address)?,
                tabId: c.tab_id,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse_addr("asset address", &c.asset_address)?,
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

/// Compute an EIP-191 signing hash for any supported guarantee request version.
fn eip191_digest(
    claims: &PaymentGuaranteeRequestClaims,
    user: Address,
    recipient: Address,
) -> ServiceResult<B256> {
    let parse_addr = |field: &'static str, value: &str| {
        Address::from_str(value)
            .map_err(|_| ServiceError::InvalidParams(format!("invalid {field}")))
    };

    let data = match claims {
        PaymentGuaranteeRequestClaims::V1(c) => SolGuaranteeRequestClaimsV1 {
            user,
            recipient,
            tabId: c.tab_id,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse_addr("asset address", &c.asset_address)?,
            timestamp: c.timestamp,
        }
        .abi_encode(),
        PaymentGuaranteeRequestClaims::V2(c) => SolGuaranteeRequestClaimsV2 {
            user,
            recipient,
            tabId: c.tab_id,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse_addr("asset address", &c.asset_address)?,
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
