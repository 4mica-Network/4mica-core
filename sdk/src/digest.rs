use std::str::FromStr;

use alloy::primitives::{Address, U256, keccak256};
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

sol! {
    /// EIP-3009 authorization struct, as signed by the token holder. The token binds `to` and
    /// `value` inside the signature, so a facilitator submitting the deposit cannot redirect funds.
    struct ReceiveWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }

    /// Permit2 `SignatureTransfer` token permission.
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// Permit2 `PermitTransferFrom` struct. `spender` is bound to the contract that will call
    /// `permitTransferFrom` (Core4Mica), so only that contract can consume the signature.
    struct PermitTransferFrom {
        TokenPermissions permitted;
        address spender;
        uint256 nonce;
        uint256 deadline;
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

/// EIP-712 signing hash from a raw domain separator and a struct hash:
/// `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))`.
///
/// We read the domain separator straight from the token (its `DOMAIN_SEPARATOR()`) rather than
/// reconstructing name/version/chainId, so the signature always matches what the token verifies —
/// no per-token EIP-712 metadata is needed from core.
fn eip712_digest(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    keccak256(buf)
}

/// EIP-712 domain separator built from its parts:
/// `keccak256(abi.encode(typeHash, keccak256(name), [keccak256(version),] chainId, verifyingContract))`.
///
/// This is the reconstruction path x402 servers rely on — they advertise `name`/`version` in the
/// payment requirements' `extra` and each client rebuilds the domain locally. It is offline, but
/// only as correct as the advertised metadata: a wrong `name` yields a well-formed separator that
/// no token will ever verify against. Prefer a separator read from the token itself when one is
/// available.
///
/// `version` is optional because not every EIP-712 domain has one — Permit2's is
/// `EIP712Domain(string name,uint256 chainId,address verifyingContract)`.
pub fn eip712_domain_separator(
    name: &str,
    version: Option<&str>,
    chain_id: u64,
    verifying_contract: Address,
) -> B256 {
    let type_hash = match version {
        Some(_) => keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .as_slice(),
        ),
        None => keccak256(
            b"EIP712Domain(string name,uint256 chainId,address verifyingContract)".as_slice(),
        ),
    };

    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(keccak256(name.as_bytes()).as_slice());
    if let Some(version) = version {
        encoded.extend_from_slice(keccak256(version.as_bytes()).as_slice());
    }
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    encoded.extend_from_slice(verifying_contract.into_word().as_slice());
    keccak256(encoded)
}

/// Permit2's domain separator for `chain_id`.
///
/// Unlike a token's, this needs neither a chain read nor server-advertised metadata: Permit2 is
/// deployed at one canonical address on every chain and its domain has a fixed name and no version,
/// so `chain_id` is the only variable.
pub fn permit2_domain_separator(chain_id: u64) -> B256 {
    eip712_domain_separator("Permit2", None, chain_id, crate::contract::PERMIT2_ADDRESS)
}

/// EIP-712 signing hash for an EIP-3009 `receiveWithAuthorization` gasless deposit.
/// `domain_separator` is the deposited token's own `DOMAIN_SEPARATOR()`.
#[allow(clippy::too_many_arguments)]
pub fn eip712_digest_for_receive_authorization(
    domain_separator: B256,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let message = ReceiveWithAuthorization {
        from,
        to,
        value,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    };
    eip712_digest(domain_separator, message.eip712_hash_struct())
}

/// EIP-712 signing hash for a Permit2 `PermitTransferFrom` gasless deposit.
/// `domain_separator` is the canonical Permit2 singleton's `DOMAIN_SEPARATOR()`; `spender` is the
/// Core4Mica contract that will call `permitTransferFrom`.
pub fn eip712_digest_for_permit2_transfer(
    domain_separator: B256,
    token: Address,
    amount: U256,
    spender: Address,
    nonce: U256,
    deadline: U256,
) -> B256 {
    let message = PermitTransferFrom {
        permitted: TokenPermissions { token, amount },
        spender,
        nonce,
        deadline,
    };
    eip712_digest(domain_separator, message.eip712_hash_struct())
}

/// EIP-712 signing hash for any supported guarantee request version.
/// Add a new `PaymentGuaranteeRequestClaims` variant here when introducing V3.
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
        assert_eq!(
            sig.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
    }

    /// Pinned against the value read from Base Sepolia USDC's own `DOMAIN_SEPARATOR()`
    /// (`0x036CbD53…`, name "USDC", version "2"). This is the x402-style reconstruction path, and
    /// the whole risk is that advertised metadata disagrees with the token — so the expectation
    /// here comes from the token, not from re-running the same formula.
    #[test]
    fn reconstructed_domain_separator_matches_real_usdc() {
        let separator = eip712_domain_separator(
            "USDC",
            Some("2"),
            84532,
            address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
        );
        assert_eq!(
            separator,
            b256!("71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818")
        );
    }

    /// A wrong `name` still produces a well-formed separator — it just never verifies. This is
    /// exactly how a stale constants table fails, silently, so keep it pinned.
    #[test]
    fn reconstructed_domain_separator_is_sensitive_to_the_name() {
        let real = eip712_domain_separator(
            "USDC",
            Some("2"),
            84532,
            address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
        );
        // Base *mainnet* USDC calls itself "USD Coin"; using the wrong one is a silent failure.
        let wrong = eip712_domain_separator(
            "USD Coin",
            Some("2"),
            84532,
            address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
        );
        assert_ne!(real, wrong);
    }

    /// Pinned against the canonical Permit2's own `DOMAIN_SEPARATOR()` on Base Sepolia.
    #[test]
    fn derived_permit2_domain_separator_matches_the_deployed_contract() {
        assert_eq!(
            permit2_domain_separator(84532),
            b256!("010f27a92fb9a32622f44f001dc4d15706a85b33499cfc2ce9033113ab26592c")
        );
    }

    #[test]
    fn permit2_domain_separator_is_chain_specific() {
        assert_ne!(permit2_domain_separator(84532), permit2_domain_separator(1));
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
        assert_eq!(
            sig.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
    }
}
