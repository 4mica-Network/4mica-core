use super::*;

async fn build_eip712_signed_request_with_wallet(
    params: &CorePublicParameters,
    wallet: &alloy::signers::local::PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    build_eip712_signed_request(params, wallet).await
}

#[tokio::test]
#[serial]
async fn verify_eip712_signature_ok() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let req = build_eip712_signed_request_with_wallet(&params, &wallet).await;
    verify_promise_signature(&params, &req).expect("valid EIP-712 signature must verify");
}

#[tokio::test]
#[serial]
async fn verify_eip712_signature_fails_if_tampered() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let mut req = build_eip712_signed_request_with_wallet(&params, &wallet).await;
    req.claims.amount = U256::from(999u64);

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid signature"),
        "tampered claims must produce invalid signature error"
    );
}

#[tokio::test]
#[serial]
async fn verify_eip191_signature_ok() {
    use alloy::{primitives::keccak256, sol_types::sol};
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256 tabId;
            uint256 reqId;
            uint256 amount;
            uint64 timestamp;
        }
    }

    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user = wallet.address();
    let recipient = Address::from(rand::random::<[u8; 20]>());
    let timestamp = Utc::now().timestamp() as u64;
    let tab_id = U256::from(0x7461622d7473u128);

    let msg = PaymentGuarantee {
        user,
        recipient,
        tabId: tab_id,
        reqId: U256::from(0u64),
        amount: U256::from(1u64),
        timestamp,
    };
    let data = msg.abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = keccak256(prefixed);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    let req = PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: user.to_string(),
            recipient_address: recipient.to_string(),
            tab_id,
            req_id: U256::from(0u64),
            amount: U256::from(1u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip191,
    };

    verify_promise_signature(&params, &req).expect("valid EIP-191 signature must verify");
}

#[tokio::test]
#[serial]
async fn verify_signature_fails_with_invalid_hex() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_with_wallet(&params, &wallet).await;

    req.signature = "0xZZZZ".to_string();

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid hex signature"),
        "invalid hex must be rejected"
    );
}
