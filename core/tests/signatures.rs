//! Signature & SIWE verification (pure crypto, no service state):
//! EIP-712/EIP-191 guarantee-request verification incl. validation-requirement
//! tamper detection, and SIWE EOA / ERC-1271 message verification.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, Signature, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::evm::guarantee::verify_guarantee_request_signature;
use core_service::evm::siwe::verify_siwe_message;
use rand::random;
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, SigningScheme,
};
use std::str::FromStr;
use test_log::test;

#[path = "common/mod.rs"]
mod common;
use common::api::{
    build_eip191_signed_validated_request, build_eip712_signed_request,
    build_eip712_signed_validated_request,
};
use common::contract::MockERC1271Wallet;

/// Reach into signed claims to corrupt them. Only tamper tests do this — production never
/// mutates claims a wallet has already signed.
fn v1_mut(claims: &mut PaymentGuaranteeRequestClaims) -> &mut PaymentGuaranteeRequestClaimsV1 {
    match claims {
        PaymentGuaranteeRequestClaims::V1(claims) => claims,
    }
}

// ════════════════════════ guarantee-request signature verification ════════════════════════
#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_eip712_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let req = build_eip712_signed_request(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid EIP-712 signature must verify");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_eip712_signature_fails_if_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let mut req = build_eip712_signed_request(&params, &wallet).await;
    v1_mut(&mut req.claims).amount = U256::from(999u64);

    let err = verify_guarantee_request_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid signature"),
        "tampered claims must produce invalid signature error"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_eip191_signature_ok() -> anyhow::Result<()> {
    use alloy::{primitives::keccak256, sol_types::sol};
    sol! {
        struct SolGuaranteeRequestClaimsV1 {
            address user;
            address recipient;
            uint256 reqId;
            uint256 amount;
            address asset;
            uint64  timestamp;
        }
    }

    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user = wallet.address();
    let recipient = Address::from(rand::random::<[u8; 20]>());
    let timestamp = Utc::now().timestamp() as u64;
    let msg = SolGuaranteeRequestClaimsV1 {
        user,
        recipient,
        reqId: U256::ZERO,
        amount: U256::from(1u64),
        asset: Address::from_str(DEFAULT_ASSET_ADDRESS).unwrap(),
        timestamp,
    };
    let data = msg.abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = keccak256(prefixed);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    let req = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::new(
            user.to_string(),
            recipient.to_string(),
            U256::ZERO,
            U256::from(1u64),
            timestamp,
            None,
        ),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip191,
    );

    verify_guarantee_request_signature(&params, &req).expect("valid EIP-191 signature must verify");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_signature_fails_with_invalid_hex() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request(&params, &wallet).await;

    req.signature = "0xZZZZ".to_string();

    let err = verify_guarantee_request_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid hex signature"),
        "invalid hex must be rejected"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_eip712_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip712_signed_validated_request(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid validated EIP-712 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_eip191_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip191_signed_validated_request(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid validated EIP-191 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_signature_fails_if_subject_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_validated_request(&params, &wallet).await;
    v1_mut(&mut req.claims)
        .validation
        .as_mut()
        .expect("validation")
        .subject = B256::repeat_byte(0x11);
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_signature_fails_if_validator_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_validated_request(&params, &wallet).await;
    v1_mut(&mut req.claims)
        .validation
        .as_mut()
        .expect("validation")
        .validator = Address::from(random::<[u8; 20]>()).to_string();
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_signature_fails_if_deadline_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_validated_request(&params, &wallet).await;
    v1_mut(&mut req.claims)
        .validation
        .as_mut()
        .expect("validation")
        .deadline = Some(1_900_000_000);
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_validated_signature_fails_if_params_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        supported_guarantee_versions: vec![1],
        core_domain_separator: String::new(),
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        validators: vec![common::api::TEST_VALIDATOR_URI.to_string()],
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_validated_request(&params, &wallet).await;
    v1_mut(&mut req.claims)
        .validation
        .as_mut()
        .expect("validation")
        .params = vec![0xff].into();
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

// ════════════════════════ SIWE message verification ════════════════════════

// Anvil default account #0 — always funded on a fresh anvil instance.
const ANVIL_DEFAULT_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn build_provider(port: u16) -> anyhow::Result<DynProvider> {
    // In CI an anvil instance is already running; reuse it instead of spawning a new one.
    if let Ok(rpc_url) = std::env::var("ETHEREUM_HTTP_RPC_URL") {
        let signer: PrivateKeySigner = ANVIL_DEFAULT_KEY.parse()?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc_url.parse()?);
        return Ok(provider.erased());
    }

    let provider_res = std::panic::catch_unwind(|| {
        ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| anvil.port(port))
    });

    let provider = match provider_res {
        Ok(Ok(provider)) => provider,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("failed to start anvil provider (panic)")),
    };

    Ok(provider.erased())
}

fn build_siwe_message(domain: &str, address: &str, chain_id: u64, nonce: &str) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\nSign in to 4mica.\n\nURI: https://example.com/login\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: 2024-01-01T00:00:00Z"
    )
}

#[test(tokio::test)]
async fn verify_siwe_eoa_signature() -> anyhow::Result<()> {
    let provider = build_provider(40107)?;
    let chain_id = provider.get_chain_id().await?;

    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();

    let message = build_siwe_message("example.com", &address, chain_id, "nonce-1");
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let parsed = verify_siwe_message(&provider, &address, &message, &signature_hex).await?;
    assert_eq!(parsed.address.to_string(), address);

    Ok(())
}

#[test(tokio::test)]
async fn verify_siwe_erc1271_signature() -> anyhow::Result<()> {
    let provider = build_provider(40108)?;
    let chain_id = provider.get_chain_id().await?;

    let wallet = MockERC1271Wallet::deploy(provider.clone()).await?;
    let address = wallet.address().to_string();

    let message = build_siwe_message("example.com", &address, chain_id, "nonce-1271");
    let signer = PrivateKeySigner::random();
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let parsed = verify_siwe_message(&provider, &address, &message, &signature_hex).await?;
    assert_eq!(parsed.address.to_string(), address);

    Ok(())
}
