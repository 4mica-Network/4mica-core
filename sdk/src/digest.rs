use std::str::FromStr;

use alloy::primitives::{Address, keccak256};
use alloy::sol_types::{SolStruct, SolValue};
use alloy::{primitives::B256, sol, sol_types::eip712_domain};
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

#[cfg(test)]
mod deposit_tests {
    use super::*;
    use alloy::primitives::{address, b256};
    use alloy::signers::{SignerSync, local::PrivateKeySigner};

    // Canonical EIP-712 `encodeType` strings the tokens hash. If field order/types drift from
    // these, the produced signature will not verify on-chain — so pin them exactly.
    const ERC3009_TYPE: &str = "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
    const PERMIT2_TYPE: &str = "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";

    #[test]
    fn receive_authorization_type_hash_matches_erc3009() {
        let msg = ReceiveWithAuthorization {
            from: Address::ZERO,
            to: Address::ZERO,
            value: U256::ZERO,
            validAfter: U256::ZERO,
            validBefore: U256::ZERO,
            nonce: B256::ZERO,
        };
        assert_eq!(msg.eip712_type_hash(), keccak256(ERC3009_TYPE));
    }

    #[test]
    fn permit_transfer_from_type_hash_matches_permit2() {
        let msg = PermitTransferFrom {
            permitted: TokenPermissions {
                token: Address::ZERO,
                amount: U256::ZERO,
            },
            spender: Address::ZERO,
            nonce: U256::ZERO,
            deadline: U256::ZERO,
        };
        assert_eq!(msg.eip712_type_hash(), keccak256(PERMIT2_TYPE));
    }

    #[test]
    fn receive_authorization_digest_signature_recovers_to_signer() {
        let signer = PrivateKeySigner::random();
        // Arbitrary but fixed domain separator, standing in for the token's DOMAIN_SEPARATOR().
        let domain = b256!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let digest = eip712_digest_for_receive_authorization(
            domain,
            signer.address(),
            address!("000000000000000000000000000000000000c0de"),
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(2_000_000_000u64),
            b256!("dead00000000000000000000000000000000000000000000000000000000beef"),
        );
        let sig = signer.sign_hash_sync(&digest).expect("sign");
<<<<<<< HEAD
        assert_eq!(
            sig.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
=======
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), signer.address());
>>>>>>> b80ed21 (feat(sdk): add gasless deposit signing for EIP-3009 and Permit2 authorizations)
    }

    #[test]
    fn permit2_digest_signature_recovers_to_signer() {
        let signer = PrivateKeySigner::random();
        let domain = b256!("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
        let digest = eip712_digest_for_permit2_transfer(
            domain,
            address!("000000000000000000000000000000000000da0c"),
            U256::from(1_000_000u64),
            address!("000000000000000000000000000000000000c0de"),
            U256::from(42u64),
            U256::from(2_000_000_000u64),
        );
        let sig = signer.sign_hash_sync(&digest).expect("sign");
<<<<<<< HEAD
        assert_eq!(
            sig.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
=======
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), signer.address());
>>>>>>> b80ed21 (feat(sdk): add gasless deposit signing for EIP-3009 and Permit2 authorizations)
    }
}
