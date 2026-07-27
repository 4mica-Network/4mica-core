//! EVM signing and identifiers for payment guarantee requests.
//!
//! This module verifies wallet signatures over guarantee requests (EIP-712 and
//! EIP-191), and derives the deterministic on-chain identifiers a guarantee is
//! bound to within a settlement cycle.

use alloy_primitives::{Address, B256, keccak256};
use alloy_sol_types::{SolStruct, SolValue, eip712_domain};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, SigningScheme,
    SolGuaranteeRequestClaimsV1, SolValidatedGuaranteeRequestClaimsV1, SolValidation,
    ValidationRequirement,
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
    let user_addr = parse_address("user", req.claims.user_address())?;
    let recipient_addr = parse_address("recipient", req.claims.recipient_address())?;

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

fn sol_validation(validation: &ValidationRequirement) -> SolValidation {
    SolValidation {
        validator: validation.validator.clone(),
        subject: validation.subject,
        deadline: validation.deadline.unwrap_or(0),
        params: validation.params.clone(),
    }
}

/// EIP-712 has no optional members, so the presence of a validation requirement picks the struct.
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

    let user = parse_address("user", claims.user_address())?;
    let recipient = parse_address("recipient", claims.recipient_address())?;
    let asset = parse_address("asset", claims.asset_address())?;

    match claims.validation() {
        None => Ok(SolGuaranteeRequestClaimsV1 {
            user,
            recipient,
            reqId: claims.req_id(),
            amount: claims.amount(),
            asset,
            timestamp: claims.timestamp(),
        }
        .eip712_signing_hash(&domain)),
        Some(validation) => Ok(SolValidatedGuaranteeRequestClaimsV1 {
            user,
            recipient,
            reqId: claims.req_id(),
            amount: claims.amount(),
            asset,
            timestamp: claims.timestamp(),
            validation: sol_validation(validation),
        }
        .eip712_signing_hash(&domain)),
    }
}

fn eip191_digest(
    claims: &PaymentGuaranteeRequestClaims,
    user: Address,
    recipient: Address,
) -> ServiceResult<B256> {
    let asset = parse_address("asset", claims.asset_address())?;

    let data = match claims.validation() {
        None => SolGuaranteeRequestClaimsV1 {
            user,
            recipient,
            reqId: claims.req_id(),
            amount: claims.amount(),
            asset,
            timestamp: claims.timestamp(),
        }
        .abi_encode(),
        Some(validation) => SolValidatedGuaranteeRequestClaimsV1 {
            user,
            recipient,
            reqId: claims.req_id(),
            amount: claims.amount(),
            asset,
            timestamp: claims.timestamp(),
            validation: sol_validation(validation),
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
    use alloy_primitives::U256;

    fn claims(req_id: u64) -> PaymentGuaranteeRequestClaims {
        PaymentGuaranteeRequestClaims::new(
            Address::repeat_byte(0x11).to_string(),
            Address::repeat_byte(0x22).to_string(),
            U256::from(req_id),
            U256::from(7u64),
            1_700_000_000,
            Some(Address::ZERO.to_string()),
        )
    }

    #[test]
    fn guarantee_id_is_stable_and_microtransaction_scoped() {
        let cycle_id = "0x0000000000000000000000000000000000000000:1777248000";
        let first = guarantee_id_for_cycle(cycle_id, &claims(1));
        let second = guarantee_id_for_cycle(cycle_id, &claims(1));
        let other = guarantee_id_for_cycle(cycle_id, &claims(2));

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(first.starts_with("0x"));
    }
}
