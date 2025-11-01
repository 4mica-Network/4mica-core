use alloy_primitives::Bytes;
use alloy_sol_types::{SolValue, sol};

use super::PaymentGuaranteeClaims;

sol! {
    struct GuaranteeClaimsV1 {
        bytes32 domain;
        uint256 tab_id;
        uint256 req_id;
        address client;
        address recipient;
        uint256 amount;
        uint256 total_amount;
        address asset;
        uint64 timestamp;
        uint64 version;
    }
}

pub fn encode_guarantee_claims(claims: PaymentGuaranteeClaims) -> anyhow::Result<Vec<u8>> {
    let encoded_claims = match claims.version {
        1 => {
            let claims_sol = GuaranteeClaimsV1 {
                domain: claims.domain.into(),
                tab_id: claims.tab_id,
                req_id: claims.req_id,
                client: claims.user_address.parse()?,
                recipient: claims.recipient_address.parse()?,
                amount: claims.amount,
                total_amount: claims.total_amount,
                asset: claims.asset_address.parse()?,
                timestamp: claims.timestamp,
                version: claims.version,
            };
            claims_sol.abi_encode()
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported guarantee claims version: {}",
                claims.version
            ));
        }
    };

    let with_version = (claims.version, encoded_claims).abi_encode_sequence();
    Ok(with_version)
}

pub fn decode_guarantee_claims(data: &[u8]) -> anyhow::Result<PaymentGuaranteeClaims> {
    let (version, encoded_claims) = <(u64, Bytes) as SolValue>::abi_decode_sequence(data)?;
    match version {
        1 => {
            let claims_sol = GuaranteeClaimsV1::abi_decode(&encoded_claims)?;
            Ok(PaymentGuaranteeClaims {
                domain: claims_sol.domain.into(),
                user_address: claims_sol.client.to_string(),
                recipient_address: claims_sol.recipient.to_string(),
                tab_id: claims_sol.tab_id,
                req_id: claims_sol.req_id,
                amount: claims_sol.amount,
                total_amount: claims_sol.total_amount,
                asset_address: claims_sol.asset.to_string(),
                timestamp: claims_sol.timestamp,
                version,
            })
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported guarantee claims version: {}",
                version
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    fn create_test_claims() -> PaymentGuaranteeClaims {
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
            tab_id: U256::from(100),
            req_id: U256::from(200),
            amount: U256::from(1000),
            total_amount: U256::from(5000),
            asset_address: asset_addr.to_string(),
            timestamp: 1234567890,
            version: 1,
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original_claims = create_test_claims();

        let encoded =
            encode_guarantee_claims(original_claims.clone()).expect("Encoding should succeed");

        let decoded = decode_guarantee_claims(&encoded).expect("Decoding should succeed");

        assert_eq!(original_claims, decoded);
    }

    #[test]
    fn test_tampered_encoding() {
        // Test 2: Encode, tamper with the encoding, should error or differ
        let original_claims = create_test_claims();

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
        let mut claims = create_test_claims();
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
        let claims = create_test_claims();

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
