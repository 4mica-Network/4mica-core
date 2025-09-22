use alloy_primitives::{Address, B256, Signature, keccak256};
use alloy_sol_types::{SolStruct, SolValue, eip712_domain, sol};
use hex;
use jsonrpsee::tracing::info;
use std::str::FromStr;

use crate::error::{ServiceError, ServiceResult};
use rpc::common::{PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme};
use rpc::core::CorePublicParameters;

/// Verify that the request was signed by `claims.user_address`
pub fn verify_promise_signature(
    params: &CorePublicParameters,
    req: &PaymentGuaranteeRequest,
) -> ServiceResult<()> {
    let claims = &req.claims;
    info!(
        "Verifying promise signature\n  claims: {:?}\n  signature: {}… (len: {} bytes)",
        claims,
        &req.signature[..std::cmp::min(req.signature.len(), 34)], // "0x" + first 16 bytes of hex
        req.signature.len()
    );
    let user_addr = Address::from_str(&claims.user_address.to_lowercase())
        .map_err(|_| ServiceError::InvalidParams("invalid user address".into()))?;
    let recipient_addr = Address::from_str(&claims.recipient_address.to_lowercase())
        .map_err(|_| ServiceError::InvalidParams("invalid recipient address".into()))?;

    let sig_bytes = hex::decode(req.signature.trim_start_matches("0x"))
        .map_err(|_| ServiceError::InvalidParams("invalid hex signature".into()))?;
    let sig = Signature::try_from(&sig_bytes[..])
        .map_err(|_| ServiceError::InvalidParams("invalid signature length".into()))?;
    info!("Parsed signature: {:?}", sig);
    let digest: B256 = match req.scheme {
        SigningScheme::Eip712 => eip712_digest(params, claims)?,
        SigningScheme::Eip191 => eip191_digest(claims, user_addr, recipient_addr)?,
    };
    info!("Computed digest: 0x{}", hex::encode(digest));
    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|_| ServiceError::InvalidParams("signature recovery failed".into()))?;

    if recovered != user_addr {
        info!("Recovered address: {recovered:?}, expected: {user_addr:?}");
        return Err(ServiceError::InvalidParams("Invalid signature".into()));
    }
    Ok(())
}

/// EIP-712 digest using the new `alloy_sol_types` API
fn eip712_digest(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeClaims,
) -> ServiceResult<B256> {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            string  tabId;
            uint64  reqId;
            uint256 amount;
            uint64  timestamp;
        }
    }

    let req_id_u64 = claims
        .req_id
        .parse::<u64>()
        .map_err(|_| ServiceError::InvalidParams("Invalid req_id".into()))?;

    // Build the EIP-712 domain that matches what the service advertises
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    // Fill the Solidity struct from the client-supplied claims
    let message = PaymentGuarantee {
        user: Address::from_str(&claims.user_address)
            .map_err(|_| ServiceError::InvalidParams("invalid user address".into()))?,
        recipient: Address::from_str(&claims.recipient_address)
            .map_err(|_| ServiceError::InvalidParams("invalid recipient address".into()))?,
        tabId: claims.tab_id.clone(),
        reqId: req_id_u64,
        amount: claims.amount,
        timestamp: claims.timestamp,
    };

    // This replaces the old `TypedData::digest()`
    Ok(message.eip712_signing_hash(&domain))
}

fn eip191_digest(
    claims: &PaymentGuaranteeClaims,
    user: Address,
    recipient: Address,
) -> ServiceResult<B256> {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            string tabId;
            uint64 reqId;
            uint256 amount;
            uint64 timestamp;
        }
    }

    let req_id_u64 = claims
        .req_id
        .parse::<u64>()
        .map_err(|_| ServiceError::InvalidParams("Invalid req_id".into()))?;

    let data = PaymentGuarantee {
        user,
        recipient,
        tabId: claims.tab_id.clone(),
        reqId: req_id_u64,
        amount: claims.amount,
        timestamp: claims.timestamp,
    }
    .abi_encode();

    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    Ok(keccak256(prefixed))
}
