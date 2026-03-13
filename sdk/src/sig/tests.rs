use alloy::hex;
use alloy::primitives::{Address, B256, Signature, U256};
use alloy::signers::local::PrivateKeySigner;
use chrono::Utc;
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestClaimsV2,
    PaymentGuaranteeValidationPolicyV2, SigningScheme, compute_validation_request_hash,
    compute_validation_subject_hash,
};
use std::str::FromStr;

use crate::error::SignPaymentError;
use crate::sig::{PaymentSigner, PaymentSignerV2};

fn create_test_params() -> CorePublicParameters {
    CorePublicParameters {
        public_key: vec![0u8; 48],
        contract_address: "0x0000000000000000000000000000000000000000".to_string(),
        ethereum_http_rpc_url: "http://localhost:8545".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        active_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: Vec::new(),
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
    }
}

fn create_test_claims(user_addr: &str, recipient_addr: &str) -> PaymentGuaranteeRequestClaimsV1 {
    PaymentGuaranteeRequestClaimsV1 {
        user_address: user_addr.to_string(),
        recipient_address: recipient_addr.to_string(),
        tab_id: U256::from(12345u64),
        req_id: U256::ZERO,
        amount: U256::from(100u64),
        timestamp: Utc::now().timestamp() as u64,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    }
}

fn create_test_claims_v2(
    user_addr: &str,
    recipient_addr: &str,
) -> anyhow::Result<PaymentGuaranteeRequestClaimsV2> {
    let tab_id = U256::from(12345u64);
    let req_id = U256::ZERO;
    let amount = U256::from(100u64);
    let timestamp = Utc::now().timestamp() as u64;
    let asset_address = "0x0000000000000000000000000000000000000000".to_string();

    let validation_subject_hash = compute_validation_subject_hash(
        user_addr,
        recipient_addr,
        tab_id,
        req_id,
        amount,
        &asset_address,
        timestamp,
    )?;

    let mut validation_policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: Address::from_str(
            "0x1111111111111111111111111111111111111111",
        )?,
        validation_request_hash: B256::ZERO,
        validation_chain_id: 1,
        validator_address: Address::from_str("0x2222222222222222222222222222222222222222")?,
        validator_agent_id: U256::from(42u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(validation_subject_hash),
        required_validation_tag: "hard-finality".to_string(),
    };

    validation_policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&validation_policy)?);

    Ok(PaymentGuaranteeRequestClaimsV2 {
        user_address: user_addr.to_string(),
        recipient_address: recipient_addr.to_string(),
        tab_id,
        req_id,
        amount,
        asset_address,
        timestamp,
        validation_policy,
    })
}

fn verify_promise_signature(
    params: &CorePublicParameters,
    req: &PaymentGuaranteeRequest,
) -> Result<(), String> {
    let sig_bytes = hex::decode(req.signature.trim_start_matches("0x"))
        .map_err(|_| "invalid hex signature".to_string())?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| "invalid signature length".to_string())?;

    let (user_addr, digest) = match &req.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => {
            let user_addr = Address::from_str(&claims.user_address)
                .map_err(|_| "invalid user address".to_string())?;
            let recipient_addr = Address::from_str(&claims.recipient_address)
                .map_err(|_| "invalid recipient address".to_string())?;
            let digest = match req.scheme {
                SigningScheme::Eip712 => crate::digest::eip712_digest(params, claims)
                    .map_err(|_| "failed to compute digest".to_string())?,
                SigningScheme::Eip191 => {
                    crate::digest::eip191_digest(claims, user_addr, recipient_addr)
                        .map_err(|_| "failed to compute digest".to_string())?
                }
            };
            (user_addr, digest)
        }
        PaymentGuaranteeRequestClaims::V2(claims) => {
            let user_addr = Address::from_str(&claims.user_address)
                .map_err(|_| "invalid user address".to_string())?;
            let recipient_addr = Address::from_str(&claims.recipient_address)
                .map_err(|_| "invalid recipient address".to_string())?;
            let digest = match req.scheme {
                SigningScheme::Eip712 => crate::digest::eip712_digest_v2(params, claims)
                    .map_err(|_| "failed to compute digest".to_string())?,
                SigningScheme::Eip191 => {
                    crate::digest::eip191_digest_v2(claims, user_addr, recipient_addr)
                        .map_err(|_| "failed to compute digest".to_string())?
                }
            };
            (user_addr, digest)
        }
    };

    let recovered = sig
        .recover_address_from_prehash(&digest)
        .map_err(|_| "signature recovery failed".to_string())?;
    if recovered != user_addr {
        return Err("Invalid signature".into());
    }
    Ok(())
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

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        payment_sig.signature,
        payment_sig.scheme,
    );

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

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        payment_sig.signature,
        payment_sig.scheme,
    );

    let verify_result = verify_promise_signature(&params, &request);
    assert!(
        verify_result.is_ok(),
        "EIP-191 signature verification should succeed"
    );
}

#[tokio::test]
async fn test_eip712_sign_and_verify_success_v2() {
    let params = create_test_params();
    let wallet = PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

    let claims = create_test_claims_v2(&user_addr, &recipient_addr).expect("build valid v2");

    let result = wallet
        .sign_request_v2(&params, claims.clone(), SigningScheme::Eip712)
        .await;

    assert!(result.is_ok(), "Signing v2 should succeed");
    let payment_sig = result.expect("v2 signature");
    assert!(matches!(payment_sig.scheme, SigningScheme::Eip712));

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(claims),
        payment_sig.signature,
        payment_sig.scheme,
    );

    let verify_result = verify_promise_signature(&params, &request);
    assert!(
        verify_result.is_ok(),
        "V2 EIP-712 signature verification should succeed"
    );
}

#[tokio::test]
async fn test_eip191_sign_and_verify_success_v2() {
    let params = create_test_params();
    let wallet = PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

    let claims = create_test_claims_v2(&user_addr, &recipient_addr).expect("build valid v2");

    let result = wallet
        .sign_request_v2(&params, claims.clone(), SigningScheme::Eip191)
        .await;

    assert!(result.is_ok(), "Signing v2 should succeed");
    let payment_sig = result.expect("v2 signature");
    assert!(matches!(payment_sig.scheme, SigningScheme::Eip191));

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(claims),
        payment_sig.signature,
        payment_sig.scheme,
    );

    let verify_result = verify_promise_signature(&params, &request);
    assert!(
        verify_result.is_ok(),
        "V2 EIP-191 signature verification should succeed"
    );
}

#[tokio::test]
async fn test_eip712_signature_fails_with_tampered_v2_validation_field() {
    let params = create_test_params();
    let wallet = PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = "0x1234567890123456789012345678901234567890".to_string();

    let claims = create_test_claims_v2(&user_addr, &recipient_addr).expect("build valid v2");
    let result = wallet
        .sign_request_v2(&params, claims.clone(), SigningScheme::Eip712)
        .await
        .expect("v2 signing should succeed");

    let mut tampered_claims = claims;
    tampered_claims.validation_policy.validation_request_hash = B256::repeat_byte(0x11);

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(tampered_claims),
        result.signature,
        result.scheme,
    );

    let verify_result = verify_promise_signature(&params, &request);
    assert!(
        verify_result.is_err(),
        "V2 EIP-712 signature verification should fail with tampered validation_request_hash"
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

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(tampered_claims),
        result.signature,
        result.scheme,
    );

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
    tampered_claims.recipient_address = "0x9999999999999999999999999999999999999999".to_string();

    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(tampered_claims),
        result.signature,
        result.scheme,
    );

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
    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims.clone()),
        sig_eip712.signature,
        SigningScheme::Eip191,
    );

    let result = verify_promise_signature(&params, &request);
    assert!(
        result.is_err(),
        "EIP-712 signature should not validate with EIP-191 scheme"
    );

    // EIP-191 signature should not validate with EIP-712 scheme
    let request = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        sig_eip191.signature,
        SigningScheme::Eip712,
    );
    let result = verify_promise_signature(&params, &request);
    assert!(
        result.is_err(),
        "EIP-191 signature should not validate with EIP-712 scheme"
    );
}
