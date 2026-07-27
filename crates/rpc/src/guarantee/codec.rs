//! BLS envelope codec for guarantee claims.
//!
//! Wire format is `abi.encode(uint64 version, bytes claims)`, matching what `Core4Mica`
//! decodes. The version selects the claims layout; only v1 exists today.

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolValue, sol};
use std::str::FromStr;
use thiserror::Error;

use super::{GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims, is_supported_guarantee_version};

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
}

pub fn encode_guarantee_claims(claims: PaymentGuaranteeClaims) -> anyhow::Result<Vec<u8>> {
    encode_inner(claims).map_err(Into::into)
}

pub fn decode_guarantee_claims(data: &[u8]) -> anyhow::Result<PaymentGuaranteeClaims> {
    decode_inner(data).map_err(Into::into)
}

#[derive(Debug, Error)]
enum CodecError {
    #[error("Unsupported guarantee claims version: {0}")]
    UnsupportedVersion(u64),
    #[error("invalid {field} address: {value}")]
    InvalidAddress { field: &'static str, value: String },
    #[error("mismatched embedded version: envelope={envelope}, embedded={embedded}")]
    MismatchedEmbeddedVersion { envelope: u64, embedded: u64 },
    #[error(transparent)]
    Abi(#[from] alloy_sol_types::Error),
}

fn encode_inner(claims: PaymentGuaranteeClaims) -> Result<Vec<u8>, CodecError> {
    if claims.version != GUARANTEE_CLAIMS_VERSION {
        return Err(CodecError::UnsupportedVersion(claims.version));
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

    Ok((claims.version, claims_sol.abi_encode()).abi_encode_sequence())
}

fn decode_inner(data: &[u8]) -> Result<PaymentGuaranteeClaims, CodecError> {
    let (version, encoded_claims) = <(u64, Bytes) as SolValue>::abi_decode_sequence(data)?;
    if !is_supported_guarantee_version(version) {
        return Err(CodecError::UnsupportedVersion(version));
    }

    let claims_sol = GuaranteeClaimsV1::abi_decode(&encoded_claims)?;
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
        cycle_id: claims_sol.cycle_id,
        req_id: claims_sol.req_id,
        amount: claims_sol.amount,
        asset_address: claims_sol.asset.to_string(),
        timestamp: claims_sol.timestamp,
        version,
    })
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
    use alloy_primitives::{Address, U256};

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
            cycle_id: U256::from(100),
            req_id: U256::from(200),
            amount: U256::from(1000),
            asset_address: asset_addr.to_string(),
            timestamp: 1234567890,
            version: GUARANTEE_CLAIMS_VERSION,
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
    fn test_tampered_encoding() {
        let original_claims = create_test_claims_v1();

        let mut encoded =
            encode_guarantee_claims(original_claims.clone()).expect("Encoding should succeed");

        if encoded.len() > 64 {
            encoded[64] = encoded[64].wrapping_add(1);
            encoded[65] = encoded[65].wrapping_add(1);
        }

        // Tampering must either fail to decode or produce different claims; both are acceptable.
        if let Ok(decoded) = decode_guarantee_claims(&encoded) {
            assert_ne!(
                decoded, original_claims,
                "Tampered data should result in different claims"
            );
        }
    }

    #[test]
    fn test_unsupported_version() {
        let mut claims = create_test_claims_v1();
        claims.version = 99;

        let result = encode_guarantee_claims(claims);

        assert!(
            result.is_err(),
            "Encoding with unsupported version should fail"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported guarantee claims version"));
        assert!(error_msg.contains("99"));
    }

    #[test]
    fn test_decode_invalid_version() {
        let claims = create_test_claims_v1();

        let encoded = encode_guarantee_claims(claims).expect("Encoding should succeed");

        let (_version, encoded_claims) = <(u64, Bytes) as SolValue>::abi_decode_sequence(&encoded)
            .expect("Should decode successfully");

        let invalid_version: u64 = 42;
        let tampered_with_version = (invalid_version, encoded_claims).abi_encode_sequence();

        let result = decode_guarantee_claims(&tampered_with_version);

        assert!(
            result.is_err(),
            "Decoding with unsupported version should fail"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported guarantee claims version"));
        assert!(error_msg.contains("42"));
    }
}
