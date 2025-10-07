use std::str::FromStr;

use crate::error::SignPaymentError;
use alloy::primitives::{Address, B256};
use alloy::signers::Signer;

use async_trait::async_trait;
use rpc::common::{PaymentGuaranteeClaims, SigningScheme};
use rpc::core::CorePublicParameters;

#[derive(Debug)]
pub struct PaymentSignature {
    pub signature: String,
    pub scheme: SigningScheme,
}

#[async_trait]
pub trait PaymentSigner: Send + Sync {
    /// Signs the claims with the chosen scheme and returns a ready-to-send request.
    ///
    /// Implementations SHOULD ensure the signer address equals `claims.user_address`
    /// to avoid mismatched-key bugs.
    async fn sign_request(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError>;
}

#[async_trait]
impl<S> PaymentSigner for S
where
    S: Signer + Send + Sync,
{
    async fn sign_request(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        let signer_addr = self.address();
        let expected = Address::from_str(&claims.user_address)
            .map_err(|_| SignPaymentError::InvalidUserAddress)?;

        if signer_addr != expected {
            return Err(SignPaymentError::AddressMismatch {
                signer: signer_addr,
                claims: claims.user_address.clone(),
            }
            .into());
        }

        let digest: B256 = match scheme {
            SigningScheme::Eip712 => crate::digest::eip712_digest(params, &claims)
                .map_err(|e| SignPaymentError::Failed(e.to_string()))?,
            SigningScheme::Eip191 => {
                let user = Address::from_str(&claims.user_address)
                    .map_err(|_| SignPaymentError::InvalidUserAddress)?;
                let recipient = Address::from_str(&claims.recipient_address)
                    .map_err(|_| SignPaymentError::InvalidRecipientAddress)?;
                crate::digest::eip191_digest(&claims, user, recipient)
                    .map_err(|e| SignPaymentError::Failed(e.to_string()))?
            }
        };

        let sig = self
            .sign_hash(&digest)
            .await
            .map_err(|e| SignPaymentError::Failed(e.to_string()))?;

        let signature = sig.to_string();

        Ok(PaymentSignature { signature, scheme })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use alloy::signers::local::PrivateKeySigner;
    use chrono::Utc;
    use core_service::auth::verify_promise_signature;
    use rpc::common::PaymentGuaranteeRequest;

    fn create_test_params() -> CorePublicParameters {
        CorePublicParameters {
            public_key: vec![0u8; 48],
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            ethereum_http_rpc_url: "http://localhost:8545".to_string(),
            eip712_name: "4mica".to_string(),
            eip712_version: "1".to_string(),
            chain_id: 1,
        }
    }

    fn create_test_claims(user_addr: &str, recipient_addr: &str) -> PaymentGuaranteeClaims {
        PaymentGuaranteeClaims {
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id: U256::from(12345u64),
            req_id: U256::from(1u64),
            amount: U256::from(100u64),
            timestamp: Utc::now().timestamp() as u64,
        }
    }

    #[tokio::test]
    async fn test_eip712_sign_and_verify_success() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let user_addr = wallet.address().to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        let claims = create_test_claims(&user_addr, &recipient_addr);

        let result = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip712)
            .await;

        assert!(result.is_ok(), "Signing should succeed");
        let payment_sig = result.unwrap();
        assert!(matches!(payment_sig.scheme, SigningScheme::Eip712));

        let request = PaymentGuaranteeRequest {
            claims,
            signature: payment_sig.signature,
            scheme: payment_sig.scheme,
        };

        let verify_result = verify_promise_signature(&params, &request);
        assert!(
            verify_result.is_ok(),
            "EIP-712 signature verification should succeed"
        );
    }

    #[tokio::test]
    async fn test_eip191_sign_and_verify_success() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let user_addr = wallet.address().to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        let claims = create_test_claims(&user_addr, &recipient_addr);

        let result = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip191)
            .await;

        assert!(result.is_ok(), "Signing should succeed");
        let payment_sig = result.unwrap();
        assert!(matches!(payment_sig.scheme, SigningScheme::Eip191));

        let request = PaymentGuaranteeRequest {
            claims,
            signature: payment_sig.signature,
            scheme: payment_sig.scheme,
        };

        let verify_result = verify_promise_signature(&params, &request);
        assert!(
            verify_result.is_ok(),
            "EIP-191 signature verification should succeed"
        );
    }

    #[tokio::test]
    async fn test_eip712_signature_fails_with_tampered_claims() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let user_addr = wallet.address().to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        let claims = create_test_claims(&user_addr, &recipient_addr);

        // Sign the original claims
        let result = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip712)
            .await
            .unwrap();

        // Tamper with the amount after signing
        let mut tampered_claims = claims;
        tampered_claims.amount = U256::from(999u64);

        let request = PaymentGuaranteeRequest {
            claims: tampered_claims,
            signature: result.signature,
            scheme: result.scheme,
        };

        // Verification should fail
        let verify_result = verify_promise_signature(&params, &request);
        assert!(
            verify_result.is_err(),
            "EIP-712 signature verification should fail with tampered amount"
        );

        let err = verify_result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid signature"),
            "Expected 'Invalid signature' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_eip191_signature_fails_with_tampered_claims() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let user_addr = wallet.address().to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        let claims = create_test_claims(&user_addr, &recipient_addr);

        // Sign the original claims
        let result = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip191)
            .await
            .unwrap();

        // Tamper with the recipient address after signing
        let mut tampered_claims = claims;
        tampered_claims.recipient_address =
            "0x9999999999999999999999999999999999999999".to_string();

        let request = PaymentGuaranteeRequest {
            claims: tampered_claims,
            signature: result.signature,
            scheme: result.scheme,
        };

        // Verification should fail
        let verify_result = verify_promise_signature(&params, &request);
        assert!(
            verify_result.is_err(),
            "EIP-191 signature verification should fail with tampered recipient"
        );

        let err = verify_result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid signature"),
            "Expected 'Invalid signature' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_sign_request_fails_with_address_mismatch() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let different_addr = "0x9999999999999999999999999999999999999999".to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        // Create claims with different user address than the signer
        let claims = create_test_claims(&different_addr, &recipient_addr);

        // Sign should fail because signer address != claims.user_address
        let result = wallet
            .sign_request(&params, claims, SigningScheme::Eip712)
            .await;

        assert!(
            result.is_err(),
            "Signing should fail when signer address doesn't match claims.user_address"
        );

        let err = result.unwrap_err();
        match err {
            SignPaymentError::AddressMismatch { signer, claims } => {
                assert_eq!(signer, wallet.address());
                assert_eq!(claims, different_addr);
            }
            _ => panic!("Expected AddressMismatch error, got: {:?}", err),
        }
    }

    #[tokio::test]
    async fn test_eip712_and_eip191_produce_different_signatures() {
        let params = create_test_params();
        let wallet = PrivateKeySigner::random();
        let user_addr = wallet.address().to_string();
        let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

        let claims = create_test_claims(&user_addr, &recipient_addr);

        // Sign with EIP-712
        let sig_eip712 = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip712)
            .await
            .unwrap();

        // Sign with EIP-191
        let sig_eip191 = wallet
            .sign_request(&params, claims.clone(), SigningScheme::Eip191)
            .await
            .unwrap();

        // Signatures should be different
        assert_ne!(
            sig_eip712.signature, sig_eip191.signature,
            "EIP-712 and EIP-191 should produce different signatures"
        );

        // EIP-712 signature should not validate with EIP-191 scheme
        let request = PaymentGuaranteeRequest {
            claims: claims.clone(),
            signature: sig_eip712.signature.clone(),
            scheme: SigningScheme::Eip191,
        };

        let result = verify_promise_signature(&params, &request);
        assert!(
            result.is_err(),
            "EIP-712 signature should not validate with EIP-191 scheme"
        );

        // EIP-191 signature should not validate with EIP-712 scheme
        let request = PaymentGuaranteeRequest {
            claims,
            signature: sig_eip191.signature,
            scheme: SigningScheme::Eip712,
        };

        let result = verify_promise_signature(&params, &request);
        assert!(
            result.is_err(),
            "EIP-191 signature should not validate with EIP-712 scheme"
        );
    }
}
