use crate::error::{ServiceError, ServiceResult};
use alloy_primitives::{Address, B256, Signature, keccak256};
use alloy_sol_types::{SolStruct, SolValue, eip712_domain, sol};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, SigningScheme,
};
use std::str::FromStr;

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

/// Verify that the request was signed by `claims.user_address`
pub fn verify_guarantee_request_signature(
    params: &CorePublicParameters,
    req: &PaymentGuaranteeRequest,
) -> ServiceResult<()> {
    let (user_addr, recipient_addr) = match &req.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => (
            claims.user_address.as_str(),
            claims.recipient_address.as_str(),
        ),
    };

    let user_addr = Address::from_str(user_addr)
        .map_err(|_| ServiceError::InvalidParams("invalid user address".into()))?;
    let recipient_addr = Address::from_str(recipient_addr)
        .map_err(|_| ServiceError::InvalidParams("invalid recipient address".into()))?;

    let sig_bytes = crypto::hex::decode_hex(&req.signature)
        .map_err(|_| ServiceError::InvalidParams("invalid hex signature".into()))?;
    let sig = Signature::try_from(&sig_bytes[..])
        .map_err(|_| ServiceError::InvalidParams("invalid signature length".into()))?;

    // TODO: do we need something like this?
    // if !is_low_s(&sig) {
    //     warn!("High-S signature rejected");
    //     return Err(ServiceError::InvalidParams("Invalid signature".into()));
    // }

    let digest: B256 = match (&req.scheme, &req.claims) {
        (SigningScheme::Eip712, PaymentGuaranteeRequestClaims::V1(claims)) => {
            eip712_digest_v1(params, claims)?
        }
        (SigningScheme::Eip191, PaymentGuaranteeRequestClaims::V1(claims)) => {
            eip191_digest_v1(claims, user_addr, recipient_addr)?
        }
    };

    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|_| ServiceError::InvalidParams("signature recovery failed".into()))?;

    if recovered != user_addr {
        return Err(ServiceError::InvalidParams("Invalid signature".into()));
    }
    Ok(())
}

// /// Reject high-S signatures (secp256k1 malleability)
// fn is_low_s(sig: &Signature) -> bool {
//     // secp256k1 curve order:
//     // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
//     // n/2:
//     const N_OVER_2_HEX: &str = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";
//     // Alloy Signature exposes s() as U256 (in newer versions). If not, adapt accordingly.
//     let s: U256 = sig.s();
//     let n_over_2 = U256::from_str(N_OVER_2_HEX).unwrap();
//     s <= n_over_2
// }

fn eip712_digest_v1(
    params: &CorePublicParameters,
    claims: &PaymentGuaranteeRequestClaimsV1,
) -> ServiceResult<B256> {
    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let message = SolGuaranteeRequestClaimsV1 {
        user: Address::from_str(&claims.user_address)
            .map_err(|_| ServiceError::InvalidParams("invalid user address".into()))?,
        recipient: Address::from_str(&claims.recipient_address)
            .map_err(|_| ServiceError::InvalidParams("invalid recipient address".into()))?,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)
            .map_err(|_| ServiceError::InvalidParams("invalid asset address".into()))?,
        timestamp: claims.timestamp,
    };

    Ok(message.eip712_signing_hash(&domain))
}

fn eip191_digest_v1(
    claims: &PaymentGuaranteeRequestClaimsV1,
    user: Address,
    recipient: Address,
) -> ServiceResult<B256> {
    let data = SolGuaranteeRequestClaimsV1 {
        user,
        recipient,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)
            .map_err(|_| ServiceError::InvalidParams("invalid asset address".into()))?,
        timestamp: claims.timestamp,
    }
    .abi_encode();

    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    Ok(keccak256(prefixed))
}
