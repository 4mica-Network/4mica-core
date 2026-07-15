//! EVM signing and identifiers for payment guarantee requests.
//!
//! This module verifies wallet signatures over guarantee requests (EIP-712 and
//! EIP-191), and derives the deterministic on-chain identifiers a guarantee is
//! bound to within a settlement cycle.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::{SolStruct, SolValue, eip712_domain};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestEssentials, SigningScheme, SolGuaranteeRequestClaimsV1,
    SolGuaranteeRequestClaimsV2,
};

use crate::error::{ServiceError, ServiceResult};
use crate::evm::{bytes32_hex, length_prefixed_keccak, parse_address};

/// The deterministic guarantee identifier (`0x`-prefixed hex) for a request
/// within a cycle.
pub fn guarantee_id_for_cycle(cycle_id: &str, claims: &PaymentGuaranteeRequestClaims) -> String {
    bytes32_hex(guarantee_digest(cycle_id, claims))
}

/// keccak256 digest uniquely identifying a guarantee request within a cycle.
fn guarantee_digest(cycle_id: &str, claims: &PaymentGuaranteeRequestClaims) -> B256 {
    length_prefixed_keccak(&[
        b"4MICA_CYCLE_GUARANTEE_V1".as_slice(),
        cycle_id.as_bytes(),
        claims.user_address().as_bytes(),
        claims.recipient_address().as_bytes(),
        claims.asset_address().as_bytes(),
        claims.req_id().to_string().as_bytes(),
        claims.version().to_string().as_bytes(),
    ])
}

/// Verify that the request was signed by `claims.user_address`.
pub fn verify_guarantee_request_signature(
    params: &CorePublicParameters,
    req: &PaymentGuaranteeRequest,
) -> ServiceResult<()> {
    let (user_addr, recipient_addr) = claims_participants(&req.claims)?;

    let user_addr = parse_address("user", user_addr)?;
    let recipient_addr = parse_address("recipient", recipient_addr)?;

    let sig_bytes = crate::util::normalize_and_decode_hex(&req.signature)
        .map_err(|_| ServiceError::InvalidParams("invalid hex signature".into()))?;
    let sig = alloy_primitives::Signature::try_from(&sig_bytes[..])
        .map_err(|_| ServiceError::InvalidParams("invalid signature length".into()))?;

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
    let verifying_contract = parse_address("core contract", &params.contract_address)?;
    let domain = eip712_domain!(
        name:               params.eip712_name.clone(),
        version:            params.eip712_version.clone(),
        chain_id:           params.chain_id,
        verifying_contract: verifying_contract,
    );

    match claims {
        PaymentGuaranteeRequestClaims::V1(c) => {
            let message = SolGuaranteeRequestClaimsV1 {
                user: parse_address("user", &c.user_address)?,
                recipient: parse_address("recipient", &c.recipient_address)?,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse_address("asset", &c.asset_address)?,
                timestamp: c.timestamp,
            };
            Ok(message.eip712_signing_hash(&domain))
        }
        PaymentGuaranteeRequestClaims::V2(c) => {
            let message = SolGuaranteeRequestClaimsV2 {
                user: parse_address("user", &c.user_address)?,
                recipient: parse_address("recipient", &c.recipient_address)?,
                reqId: c.req_id,
                amount: c.amount,
                asset: parse_address("asset", &c.asset_address)?,
                timestamp: c.timestamp,
                validationRegistryAddress: c.validation_policy.validation_registry_address,
                validationRequestHash: c.validation_policy.validation_request_hash,
                validationChainId: U256::from(c.validation_policy.validation_chain_id),
                validatorAddress: c.validation_policy.validator_address,
                validatorAgentId: c.validation_policy.validator_agent_id,
                minValidationScore: c.validation_policy.min_validation_score,
                validationSubjectHash: c.validation_policy.validation_subject_hash,
                jobHash: c.validation_policy.job_hash,
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
    let data = match claims {
        PaymentGuaranteeRequestClaims::V1(c) => SolGuaranteeRequestClaimsV1 {
            user,
            recipient,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse_address("asset", &c.asset_address)?,
            timestamp: c.timestamp,
        }
        .abi_encode(),
        PaymentGuaranteeRequestClaims::V2(c) => SolGuaranteeRequestClaimsV2 {
            user,
            recipient,
            reqId: c.req_id,
            amount: c.amount,
            asset: parse_address("asset", &c.asset_address)?,
            timestamp: c.timestamp,
            validationRegistryAddress: c.validation_policy.validation_registry_address,
            validationRequestHash: c.validation_policy.validation_request_hash,
            validationChainId: U256::from(c.validation_policy.validation_chain_id),
            validatorAddress: c.validation_policy.validator_address,
            validatorAgentId: c.validation_policy.validator_agent_id,
            minValidationScore: c.validation_policy.min_validation_score,
            validationSubjectHash: c.validation_policy.validation_subject_hash,
            jobHash: c.validation_policy.job_hash,
            requiredValidationTag: c.validation_policy.required_validation_tag.clone(),
        }
        .abi_encode(),
    };

    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    Ok(keccak256(prefixed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpc::PaymentGuaranteeRequestClaimsV1;

    fn v1_claims(req_id: u64) -> PaymentGuaranteeRequestClaims {
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: Address::repeat_byte(0x11).to_string(),
            recipient_address: Address::repeat_byte(0x22).to_string(),
            req_id: U256::from(req_id),
            amount: U256::from(7u64),
            asset_address: Address::ZERO.to_string(),
            timestamp: 1_700_000_000,
        })
    }

    #[test]
    fn guarantee_id_is_stable_and_microtransaction_scoped() {
        let cycle_id = "0x0000000000000000000000000000000000000000:1777248000";
        let first = guarantee_id_for_cycle(cycle_id, &v1_claims(1));
        let second = guarantee_id_for_cycle(cycle_id, &v1_claims(1));
        let other = guarantee_id_for_cycle(cycle_id, &v1_claims(2));

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(first.starts_with("0x"));
    }
}
