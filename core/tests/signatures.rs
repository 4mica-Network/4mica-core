//! Signature & SIWE verification (pure crypto, no service state):
//! EIP-712/EIP-191 guarantee-request verification incl. V2 validation-policy
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
    build_eip191_signed_request_v2, build_eip712_signed_request, build_eip712_signed_request_v2,
};
use common::contract::MockERC1271Wallet;

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
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
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
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let mut req = build_eip712_signed_request(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => {
            claims.amount = U256::from(999u64);
        }
        PaymentGuaranteeRequestClaims::V2(_) => {
            panic!("test fixture builds only v1 guarantee requests");
        }
    }

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
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
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
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: user.to_string(),
            recipient_address: recipient.to_string(),
            req_id: U256::ZERO,
            amount: U256::from(1u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        }),
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
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
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
async fn verify_v2_eip712_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip712_signed_request_v2(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid V2 EIP-712 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_eip191_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip191_signed_request_v2(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid V2 EIP-191 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validation_request_hash_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validation_request_hash = B256::repeat_byte(0x11);
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validator_address_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validator_address = Address::from(random::<[u8; 20]>());
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validation_subject_hash_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validation_subject_hash = B256::repeat_byte(0x22);
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_required_validation_tag_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "0x0000000000000000000000000000000000000001".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.required_validation_tag = "soft-finality".to_string();
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
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
