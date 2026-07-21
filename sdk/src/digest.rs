use std::str::FromStr;

use alloy::primitives::{Address, keccak256};
use alloy::sol_types::{SolStruct, SolValue};
use alloy::{primitives::B256, sol_types::eip712_domain};
use anyhow::anyhow;
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequestClaims, SolGuaranteeRequestClaimsV1,
    SolValidatedGuaranteeRequestClaimsV1, SolValidation, ValidationRequirement,
};

fn parse_addr(field: &'static str, value: &str) -> anyhow::Result<Address> {
    Address::from_str(value).map_err(|_| anyhow!("invalid {field}"))
}

fn sol_validation(validation: &ValidationRequirement) -> SolValidation {
    SolValidation {
        validator: validation.validator.clone(),
        subject: validation.subject,
        deadline: validation.deadline.unwrap_or(0),
        params: validation.params.clone(),
    }
}

/// EIP-712 signing hash for a guarantee request. Must stay byte-identical to the operator's
/// request domain (core/src/evm/guarantee.rs): the deployment's Core4Mica address is bound in so a
/// request signature cannot be replayed against another 4Mica deployment on the same chain
/// (4MCA-L06).
pub fn eip712_digest_for_claims(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaims,
) -> anyhow::Result<B256> {
    let verifying_contract = parse_addr("core contract", &params.contract_address)?;
    let domain = eip712_domain!(
        name:               params.eip712_name.clone(),
        version:            params.eip712_version.clone(),
        chain_id:           params.chain_id,
        verifying_contract: verifying_contract,
    );

    let user = parse_addr("claims.user_address", claims.user_address())?;
    let recipient = parse_addr("claims.recipient_address", claims.recipient_address())?;
    let asset = parse_addr("claims.asset_address", claims.asset_address())?;

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

/// EIP-191 signing hash for a guarantee request.
pub fn eip191_digest_for_claims(
    claims: &PaymentGuaranteeRequestClaims,
    user: Address,
    recipient: Address,
) -> anyhow::Result<B256> {
    let asset = parse_addr("claims.asset_address", claims.asset_address())?;

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
