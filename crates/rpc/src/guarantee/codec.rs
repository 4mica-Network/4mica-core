use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolValue, sol};
use std::str::FromStr;
use thiserror::Error;

use super::{
    GUARANTEE_CLAIMS_VERSION, GUARANTEE_CLAIMS_VERSION_V2, PaymentGuaranteeClaims,
    PaymentGuaranteeValidationPolicyV2,
};

sol! {
    struct GuaranteeClaimsV1 {
        bytes32 domain;
        uint256 cycle_id;
        uint256 req_id;
        address client;
        address recipient;
        uint256 amount;
        address asset;
        uint64 timestamp;
        uint64 version;
    }

    struct GuaranteeClaimsV2 {
        bytes32 domain;
        uint256 cycle_id;
        uint256 req_id;
        address client;
        address recipient;
        uint256 amount;
        address asset;
        uint64 timestamp;
        uint64 version;
        address validation_registry_address;
        bytes32 validation_request_hash;
        uint64 validation_chain_id;
        address validator_address;
        uint256 validator_agent_id;
        uint8 min_validation_score;
        bytes32 validation_subject_hash;
        bytes32 job_hash;
        string required_validation_tag;
    }
}

pub fn encode_guarantee_claims(claims: PaymentGuaranteeClaims) -> anyhow::Result<Vec<u8>> {
    encode_guarantee_claims_inner(claims).map_err(Into::into)
}

pub fn decode_guarantee_claims(data: &[u8]) -> anyhow::Result<PaymentGuaranteeClaims> {
    decode_guarantee_claims_inner(data).map_err(Into::into)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuaranteeClaimsVersion {
    V1,
    V2,
}

impl GuaranteeClaimsVersion {
    fn as_u64(self) -> u64 {
        match self {
            Self::V1 => GUARANTEE_CLAIMS_VERSION,
            Self::V2 => GUARANTEE_CLAIMS_VERSION_V2,
        }
    }
}

impl TryFrom<u64> for GuaranteeClaimsVersion {
    type Error = CodecError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            GUARANTEE_CLAIMS_VERSION => Ok(Self::V1),
            GUARANTEE_CLAIMS_VERSION_V2 => Ok(Self::V2),
            _ => Err(CodecError::UnsupportedVersion(value)),
        }
    }
}

#[derive(Debug, Error)]
enum CodecError {
    #[error("Unsupported guarantee claims version: {0}")]
    UnsupportedVersion(u64),
    #[error("v1 guarantee claims must not carry validation_policy")]
    UnexpectedValidationPolicyForV1,
    #[error("v2 guarantee claims require validation_policy")]
    MissingValidationPolicyForV2,
    #[error("invalid {field} address: {value}")]
    InvalidAddress { field: &'static str, value: String },
    #[error("mismatched embedded version: envelope={envelope}, embedded={embedded}")]
    MismatchedEmbeddedVersion { envelope: u64, embedded: u64 },
    #[error("validation invariant failed: {0}")]
    ValidationInvariant(String),
    #[error(transparent)]
    Abi(#[from] alloy_sol_types::Error),
}

fn encode_guarantee_claims_inner(claims: PaymentGuaranteeClaims) -> Result<Vec<u8>, CodecError> {
    let version = GuaranteeClaimsVersion::try_from(claims.version)?;
    let encoded_claims = match version {
        GuaranteeClaimsVersion::V1 => encode_v1_claims(&claims)?,
        GuaranteeClaimsVersion::V2 => encode_v2_claims(&claims)?,
    };

    Ok((version.as_u64(), encoded_claims).abi_encode_sequence())
}

fn decode_guarantee_claims_inner(data: &[u8]) -> Result<PaymentGuaranteeClaims, CodecError> {
    let (version, encoded_claims) = <(u64, Bytes) as SolValue>::abi_decode_sequence(data)?;
    let parsed_version = GuaranteeClaimsVersion::try_from(version)?;

    match parsed_version {
        GuaranteeClaimsVersion::V1 => decode_v1_claims(version, &encoded_claims),
        GuaranteeClaimsVersion::V2 => decode_v2_claims(version, &encoded_claims),
    }
}

fn encode_v1_claims(claims: &PaymentGuaranteeClaims) -> Result<Vec<u8>, CodecError> {
    if claims.validation_policy.is_some() {
        return Err(CodecError::UnexpectedValidationPolicyForV1);
    }

    let claims_sol = GuaranteeClaimsV1 {
        domain: claims.domain.into(),
        cycle_id: claims.cycle_id,
        req_id: claims.req_id,
        client: parse_address("user_address", &claims.user_address)?,
        recipient: parse_address("recipient_address", &claims.recipient_address)?,
        amount: claims.amount,
        asset: parse_address("asset_address", &claims.asset_address)?,
        timestamp: claims.timestamp,
        version: claims.version,
    };
    Ok(claims_sol.abi_encode())
}

fn encode_v2_claims(claims: &PaymentGuaranteeClaims) -> Result<Vec<u8>, CodecError> {
    let policy = claims
        .validation_policy
        .as_ref()
        .ok_or(CodecError::MissingValidationPolicyForV2)?;

    claims
        .validate_v2_policy_binding()
        .map_err(|e| CodecError::ValidationInvariant(e.to_string()))?;

    let claims_sol = GuaranteeClaimsV2 {
        domain: claims.domain.into(),
        cycle_id: claims.cycle_id,
        req_id: claims.req_id,
        client: parse_address("user_address", &claims.user_address)?,
        recipient: parse_address("recipient_address", &claims.recipient_address)?,
        amount: claims.amount,
        asset: parse_address("asset_address", &claims.asset_address)?,
        timestamp: claims.timestamp,
        version: claims.version,
        validation_registry_address: policy.validation_registry_address,
        validation_request_hash: policy.validation_request_hash,
        validation_chain_id: policy.validation_chain_id,
        validator_address: policy.validator_address,
        validator_agent_id: policy.validator_agent_id,
        min_validation_score: policy.min_validation_score,
        validation_subject_hash: policy.validation_subject_hash,
        job_hash: policy.job_hash,
        required_validation_tag: policy.required_validation_tag.clone(),
    };
    Ok(claims_sol.abi_encode())
}

fn decode_v1_claims(
    version: u64,
    encoded_claims: &[u8],
) -> Result<PaymentGuaranteeClaims, CodecError> {
    let claims_sol = GuaranteeClaimsV1::abi_decode(encoded_claims)?;
    if claims_sol.version != version {
        return Err(CodecError::MismatchedEmbeddedVersion {
            envelope: version,
            embedded: claims_sol.version,
        });
    }

    Ok(PaymentGuaranteeClaims {
        domain: claims_sol.domain.into(),
        user_address: claims_sol.client.to_string(),
        recipient_address: claims_sol.recipient.to_string(),
        tab_id: U256::ZERO,
        cycle_id: claims_sol.cycle_id,
        req_id: claims_sol.req_id,
        amount: claims_sol.amount,
        total_amount: claims_sol.cycle_id,
        asset_address: claims_sol.asset.to_string(),
        timestamp: claims_sol.timestamp,
        version,
        validation_policy: None,
    })
}

fn decode_v2_claims(
    version: u64,
    encoded_claims: &[u8],
) -> Result<PaymentGuaranteeClaims, CodecError> {
    let claims_sol = GuaranteeClaimsV2::abi_decode(encoded_claims)?;
    if claims_sol.version != version {
        return Err(CodecError::MismatchedEmbeddedVersion {
            envelope: version,
            embedded: claims_sol.version,
        });
    }

    let validation_policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: claims_sol.validation_registry_address,
        validation_request_hash: claims_sol.validation_request_hash,
        validation_chain_id: claims_sol.validation_chain_id,
        validator_address: claims_sol.validator_address,
        validator_agent_id: claims_sol.validator_agent_id,
        min_validation_score: claims_sol.min_validation_score,
        validation_subject_hash: claims_sol.validation_subject_hash,
        job_hash: claims_sol.job_hash,
        required_validation_tag: claims_sol.required_validation_tag,
    };

    let claims = PaymentGuaranteeClaims {
        domain: claims_sol.domain.into(),
        user_address: claims_sol.client.to_string(),
        recipient_address: claims_sol.recipient.to_string(),
        tab_id: U256::ZERO,
        cycle_id: claims_sol.cycle_id,
        req_id: claims_sol.req_id,
        amount: claims_sol.amount,
        total_amount: claims_sol.cycle_id,
        asset_address: claims_sol.asset.to_string(),
        timestamp: claims_sol.timestamp,
        version,
        validation_policy: Some(validation_policy),
    };
    claims
        .validate_v2_policy_binding()
        .map_err(|e| CodecError::ValidationInvariant(e.to_string()))?;
    Ok(claims)
}

fn parse_address(field: &'static str, value: &str) -> Result<Address, CodecError> {
    Address::from_str(value).map_err(|_| CodecError::InvalidAddress {
        field,
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guarantee::{compute_validation_request_hash, compute_validation_subject_hash};
    use alloy_primitives::{Address, B256, U256};

    fn create_test_claims_v1() -> PaymentGuaranteeClaims {
        let user_addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let recipient_addr: Address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            .parse()
            .unwrap();
        let asset_addr: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        PaymentGuaranteeClaims {
            domain: [1u8; 32],
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id: U256::ZERO,
            cycle_id: U256::from(100),
            req_id: U256::from(200),
            amount: U256::from(1000),
            total_amount: U256::from(100),
            asset_address: asset_addr.to_string(),
            timestamp: 1234567890,
            version: GUARANTEE_CLAIMS_VERSION,
            validation_policy: None,
        }
    }

    fn create_test_claims_v2() -> PaymentGuaranteeClaims {
        let user_addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let recipient_addr: Address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            .parse()
            .unwrap();
        let asset_addr: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let validation_registry_address: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let validator_address: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();

        let validation_subject_hash = compute_validation_subject_hash(
            &user_addr.to_string(),
            &recipient_addr.to_string(),
            U256::from(201),
            U256::from(1001),
            &asset_addr.to_string(),
            1_700_000_000,
        )
        .expect("compute subject hash");

        let mut policy = PaymentGuaranteeValidationPolicyV2 {
            validation_registry_address,
            validation_request_hash: B256::ZERO,
            validation_chain_id: 84532,
            validator_address,
            validator_agent_id: U256::from(42),
            min_validation_score: 80,
            validation_subject_hash: B256::from(validation_subject_hash),
            job_hash: B256::repeat_byte(0x11),
            required_validation_tag: "hard-finality".to_string(),
        };
        policy.validation_request_hash =
            B256::from(compute_validation_request_hash(&policy).expect("compute request hash"));

        PaymentGuaranteeClaims {
            domain: [2u8; 32],
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id: U256::ZERO,
            cycle_id: U256::from(101),
            req_id: U256::from(201),
            amount: U256::from(1001),
            total_amount: U256::from(101),
            asset_address: asset_addr.to_string(),
            timestamp: 1_700_000_000,
            version: 2,
            validation_policy: Some(policy),
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_v1() {
        let original_claims = create_test_claims_v1();

        let encoded =
            encode_guarantee_claims(original_claims.clone()).expect("Encoding should succeed");

        let decoded = decode_guarantee_claims(&encoded).expect("Decoding should succeed");

        assert_eq!(original_claims, decoded);
    }

    #[test]
    fn test_encode_decode_roundtrip_v2() {
        let original_claims = create_test_claims_v2();

        let encoded =
            encode_guarantee_claims(original_claims.clone()).expect("Encoding should succeed");

        let decoded = decode_guarantee_claims(&encoded).expect("Decoding should succeed");

        assert_eq!(original_claims, decoded);
    }

    #[test]
    fn test_encode_v2_without_policy_fails() {
        let mut claims = create_test_claims_v2();
        claims.validation_policy = None;

        let result = encode_guarantee_claims(claims);
        assert!(result.is_err(), "v2 without validation policy must fail");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("validation_policy"));
    }

    #[test]
    fn test_decode_v2_fails_on_non_canonical_validation_binding() {
        let claims = create_test_claims_v2();
        let policy = claims
            .validation_policy
            .as_ref()
            .expect("policy must exist for v2 test claims");

        let forged_claims = GuaranteeClaimsV2 {
            domain: claims.domain.into(),
            cycle_id: claims.cycle_id,
            req_id: claims.req_id,
            client: claims
                .user_address
                .parse()
                .expect("client address must parse"),
            recipient: claims
                .recipient_address
                .parse()
                .expect("recipient address must parse"),
            amount: claims.amount,
            asset: claims
                .asset_address
                .parse()
                .expect("asset address must parse"),
            timestamp: claims.timestamp,
            version: 2,
            validation_registry_address: policy.validation_registry_address,
            validation_request_hash: policy.validation_request_hash,
            validation_chain_id: policy.validation_chain_id,
            validator_address: policy.validator_address,
            validator_agent_id: policy.validator_agent_id,
            min_validation_score: policy.min_validation_score,
            validation_subject_hash: B256::repeat_byte(0xAB),
            job_hash: policy.job_hash,
            required_validation_tag: policy.required_validation_tag.clone(),
        };

        let encoded = (2, forged_claims.abi_encode()).abi_encode_sequence();
        let err = decode_guarantee_claims(&encoded).expect_err("non-canonical v2 must fail");
        assert!(err.to_string().contains("validation invariant failed"));
    }

    #[test]
    fn test_tampered_encoding() {
        // Test 2: Encode, tamper with the encoding, should error or differ
        let original_claims = create_test_claims_v1();

        // Encode the claims
        let mut encoded =
            encode_guarantee_claims(original_claims.clone()).expect("Encoding should succeed");

        // Tamper with the encoded data by flipping some bytes in the middle
        if encoded.len() > 64 {
            encoded[64] = encoded[64].wrapping_add(1);
            encoded[65] = encoded[65].wrapping_add(1);
        }

        // Attempt to decode the tampered data
        let decoded_result = decode_guarantee_claims(&encoded);

        // Either decoding should fail, or the decoded data should be different
        match decoded_result {
            Ok(decoded) => {
                assert_ne!(
                    decoded, original_claims,
                    "Tampered data should result in different claims"
                );
            }
            Err(_) => {
                // Decoding failed, which is expected for tampered data
            }
        }
    }

    #[test]
    fn test_unsupported_version() {
        // Test 3: Wrong version should error
        let mut claims = create_test_claims_v1();
        claims.version = 99; // Unsupported version

        // Attempt to encode with unsupported version
        let result = encode_guarantee_claims(claims);

        // Should fail with an error
        assert!(
            result.is_err(),
            "Encoding with unsupported version should fail"
        );

        // Verify error message contains version information
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported guarantee claims version"));
        assert!(error_msg.contains("99"));
    }

    #[test]
    fn test_decode_invalid_version() {
        // Additional test: Create encoded data with invalid version manually
        let claims = create_test_claims_v1();

        // First encode normally
        let encoded = encode_guarantee_claims(claims).expect("Encoding should succeed");

        // Decode to extract the version and encoded claims
        let (_version, encoded_claims) = <(u64, Bytes) as SolValue>::abi_decode_sequence(&encoded)
            .expect("Should decode successfully");

        // Re-encode with an invalid version (42)
        let invalid_version: u64 = 42;
        let tampered_with_version = (invalid_version, encoded_claims).abi_encode_sequence();

        // Try to decode
        let result = decode_guarantee_claims(&tampered_with_version);

        // Should fail
        assert!(
            result.is_err(),
            "Decoding with unsupported version should fail"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported guarantee claims version"));
        assert!(error_msg.contains("42"));
    }
}
