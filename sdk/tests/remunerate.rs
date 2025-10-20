use alloy::{hex, primitives::Address, providers::ProviderBuilder, sol};
use rpc::{
    core::{CoreApiClient, CorePublicParameters},
    proxy::RpcProxy,
};
use rust_sdk_4mica::{
    Client, Config, ConfigBuilder, PaymentGuaranteeClaims, SigningScheme, U256,
    error::RemunerateError,
};
use std::{str::FromStr, time::Duration};

mod common;

sol! {
    #[sol(rpc)]
    #[allow(non_camel_case_types)]
    contract DebugCore4Mica {
        function GUARANTEE_VERIFICATION_KEY() external view returns (bytes32,bytes32,bytes32,bytes32);
        function guaranteeDomainSeparator() external view returns (bytes32);
    }
}

async fn log_signature_environment(
    tag: &str,
    config: &Config,
) -> anyhow::Result<CorePublicParameters> {
    let rpc_url = config.rpc_url.as_str();
    println!("[{}] SDK rpc_url={}", tag, rpc_url);

    let rpc_proxy = RpcProxy::new(rpc_url)?;
    let public_params = rpc_proxy.get_public_params().await?;
    println!(
        "[{}] Core service chain_id={}, contract_address={}, ethereum_http_rpc_url={}",
        tag,
        public_params.chain_id,
        public_params.contract_address,
        public_params.ethereum_http_rpc_url
    );
    println!(
        "[{}] Core service public key=0x{}",
        tag,
        hex::encode(&public_params.public_key)
    );

    let stored_domain = crypto::guarantee::guarantee_domain_separator()?;
    println!(
        "[{}] SDK stored domain separator=0x{}",
        tag,
        hex::encode(stored_domain)
    );

    let contract_address = Address::from_str(&public_params.contract_address)?;
    let recomputed_domain = crypto::guarantee::compute_guarantee_domain_separator(
        public_params.chain_id,
        contract_address,
    )?;
    println!(
        "[{}] SDK recomputed domain separator=0x{}",
        tag,
        hex::encode(recomputed_domain)
    );

    let provider = ProviderBuilder::new()
        .connect(&public_params.ethereum_http_rpc_url)
        .await?;
    let contract = DebugCore4Mica::new(contract_address, provider);
    let on_chain_domain = contract.guaranteeDomainSeparator().call().await?;
    println!(
        "[{}] On-chain domain separator=0x{}",
        tag,
        hex::encode(on_chain_domain)
    );
    let key = contract.GUARANTEE_VERIFICATION_KEY().call().await?;
    println!(
        "[{}] On-chain verification key:\n  x_a=0x{}\n  x_b=0x{}\n  y_a=0x{}\n  y_b=0x{}",
        tag,
        hex::encode(key._0),
        hex::encode(key._1),
        hex::encode(key._2),
        hex::encode(key._3)
    );

    Ok(public_params)
}

#[tokio::test]
#[test_log::test]
async fn test_recipient_remuneration() -> anyhow::Result<()> {
    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;
    let user_config_clone = user_config.clone();

    let user_address = user_config_clone.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;
    log_signature_environment("user", &user_config_clone).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356".to_string(),
        )
        .build()?;
    let recipient_config_clone = recipient_config.clone();

    let recipient_address = recipient_config_clone
        .wallet_private_key
        .address()
        .to_string();
    let recipient_client = Client::new(recipient_config).await?;
    log_signature_environment("recipient", &recipient_config_clone).await?;

    let user_info = user_client.user.get_user().await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    let user_info_after = user_client.user.get_user().await?;
    assert_eq!(
        user_info_after.collateral,
        user_info.collateral + deposit_amount
    );

    tokio::time::sleep(Duration::from_secs(2)).await;

    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            None,
            Some(3600 * 24 * 21),
        )
        .await?;

    let guarantee_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let claims = PaymentGuaranteeClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::from(0),
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };
    println!("[recipient] claims struct: {:?}", claims);

    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims.clone(), payment_sig.signature, payment_sig.scheme)
        .await?;
    println!(
        "[recipient] issued cert: claims=0x{} signature=0x{}",
        bls_cert.claims, bls_cert.signature
    );

    let claims_bytes = crypto::hex::decode_hex(&bls_cert.claims)?;
    println!(
        "[recipient] encoded claims bytes=0x{}",
        hex::encode(&claims_bytes)
    );
    let expected_bytes = crypto::guarantee::encode_guarantee_bytes(
        claims.tab_id,
        claims.req_id,
        &claims.user_address,
        &claims.recipient_address,
        claims.amount,
        &claims.asset_address,
        claims.timestamp,
    )?;
    println!(
        "[recipient] expected claims bytes=0x{}",
        hex::encode(&expected_bytes)
    );
    assert_eq!(claims_bytes, expected_bytes);

    recipient_client
        .recipient
        .remunerate(bls_cert)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remunerate the tab: {}", e))?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let user_info_after = user_client.user.get_user().await?;
    assert_eq!(
        user_info_after.collateral,
        user_info.collateral + deposit_amount - guarantee_amount
    );

    let tab_status = recipient_client
        .recipient
        .get_tab_payment_status(tab_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get the tab payment status: {}", e))?;

    assert!(tab_status.remunerated);

    Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_double_remuneration_fails() -> anyhow::Result<()> {
    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string(),
        )
        .build()?;
    let user_config_clone = user_config.clone();

    let user_address = user_config_clone.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;
    log_signature_environment("double:user", &user_config_clone).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".to_string(),
        )
        .build()?;
    let recipient_config_clone = recipient_config.clone();

    let recipient_address = recipient_config_clone
        .wallet_private_key
        .address()
        .to_string();
    let recipient_client = Client::new(recipient_config).await?;
    log_signature_environment("double:recipient", &recipient_config_clone).await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            None,
            Some(3600 * 24 * 21),
        )
        .await?;

    let guarantee_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let claims = PaymentGuaranteeClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::from(0),
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };
    println!("[double] claims struct: {:?}", claims);

    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims.clone(), payment_sig.signature, payment_sig.scheme)
        .await?;
    println!(
        "[double] issued cert: claims=0x{} signature=0x{}",
        bls_cert.claims, bls_cert.signature
    );

    let claims_bytes = crypto::hex::decode_hex(&bls_cert.claims)?;
    println!(
        "[double] encoded claims bytes=0x{}",
        hex::encode(&claims_bytes)
    );
    let expected_bytes = crypto::guarantee::encode_guarantee_bytes(
        claims.tab_id,
        claims.req_id,
        &claims.user_address,
        &claims.recipient_address,
        claims.amount,
        &claims.asset_address,
        claims.timestamp,
    )?;
    println!(
        "[double] expected claims bytes=0x{}",
        hex::encode(&expected_bytes)
    );
    assert_eq!(claims_bytes, expected_bytes);

    recipient_client
        .recipient
        .remunerate(bls_cert.clone())
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let result = recipient_client.recipient.remunerate(bls_cert).await;

    assert!(matches!(
        result,
        Err(RemunerateError::TabPreviouslyRemunerated)
    ));

    Ok(())
}
