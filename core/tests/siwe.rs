use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::anyhow;
use core_service::auth::siwe::verify_siwe_message;
use test_log::test;

mod common;
use common::contract::MockERC1271Wallet;

fn build_provider(port: u16) -> anyhow::Result<DynProvider> {
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
