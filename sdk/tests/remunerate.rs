use alloy::hex;
use rpc::RpcProxy;
use rust_sdk_4mica::{
    Client, Config, PaymentGuaranteeRequestClaims, SigningScheme, U256, error::RemunerateError,
};
use std::time::{Duration, Instant};

use crate::common::{
    ETH_ASSET_ADDRESS, build_authed_recipient_config, build_authed_user_config,
    wait_for_collateral_increase,
};

mod common;

async fn ensure_core_available(tag: &str, config: &Config) -> anyhow::Result<()> {
    let rpc_url = config.rpc_url.as_str();
    tokio::time::timeout(Duration::from_secs(5), async {
        let rpc_proxy = RpcProxy::new(rpc_url)
            .map_err(|err| anyhow::anyhow!("[{tag}] core RPC at {rpc_url} unavailable: {err}"))?;
        rpc_proxy
            .get_public_params()
            .await
            .map_err(|err| anyhow::anyhow!("[{tag}] core RPC at {rpc_url} unavailable: {err}"))
    })
    .await
    .map_err(|_| anyhow::anyhow!("[{tag}] timed out waiting for core RPC at {rpc_url}"))??;
    Ok(())
}

async fn wait_for_tab_remunerated(recipient_client: &Client, tab_id: U256) -> anyhow::Result<()> {
    let poll_interval = Duration::from_millis(200);
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    loop {
        let status = recipient_client
            .recipient
            .get_tab_payment_status(tab_id)
            .await?;
        if status.remunerated {
            return Ok(());
        }

        if start.elapsed() > timeout {
            anyhow::bail!("timed out waiting for tab {tab_id:?} to be remunerated");
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[tokio::test]
#[serial_test::serial]
#[test_log::test]
async fn test_recipient_remuneration() -> anyhow::Result<()> {
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;
    let user_config_clone = user_config.clone();

    ensure_core_available("test_recipient_remuneration:user", &user_config_clone).await?;
    let user_address = user_config_clone.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = build_authed_recipient_config(
        "http://localhost:3000",
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    )
    .await?;
    let recipient_config_clone = recipient_config.clone();

    let recipient_address = recipient_config_clone
        .wallet_private_key
        .address()
        .to_string();
    let recipient_client = Client::new(recipient_config).await?;

    let user_info = user_client.user.get_user().await?;
    let eth_asset_before =
        common::extract_asset_info(&user_info, ETH_ASSET_ADDRESS).expect("ETH asset not found");

    let core_total_before = recipient_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    let user_info_after = user_client.user.get_user().await?;
    let eth_asset = common::extract_asset_info(&user_info_after, ETH_ASSET_ADDRESS)
        .expect("ETH asset not found");
    assert_eq!(
        eth_asset.collateral,
        eth_asset_before.collateral + deposit_amount
    );

    wait_for_collateral_increase(
        &recipient_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

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
    let claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::ZERO,
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };
    // println!("[recipient] claims struct: {:?}", claims);

    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    let bls_cert = user_client
        .user
        .issue_payment_guarantee(claims.clone(), payment_sig.signature, payment_sig.scheme)
        .await?;
    println!(
        "[recipient] issued cert:\nclaims=0x{}\nsignature=0x{}",
        bls_cert.claims, bls_cert.signature
    );

    let guarantee = recipient_client
        .recipient
        .verify_payment_guarantee(&bls_cert)?;

    println!("[recipient] verified guarantee:\n{:?}", guarantee);

    let claims_bytes = crypto::hex::decode_hex(&bls_cert.claims)?;
    // println!(
    //     "[recipient] encoded claims bytes=0x{}",
    //     hex::encode(&claims_bytes)
    // );
    let expected_bytes: Vec<u8> = guarantee.try_into()?;
    // println!(
    //     "[recipient] expected claims bytes=0x{}",
    //     hex::encode(&expected_bytes)
    // );
    assert_eq!(claims_bytes, expected_bytes);

    recipient_client
        .recipient
        .remunerate(bls_cert)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remunerate the tab: {}", e))?;

    wait_for_tab_remunerated(&recipient_client, tab_id).await?;

    let user_info_after = user_client.user.get_user().await?;
    let eth_asset = common::extract_asset_info(&user_info_after, ETH_ASSET_ADDRESS)
        .expect("ETH asset not found");
    assert_eq!(
        eth_asset.collateral,
        eth_asset_before.collateral + deposit_amount - guarantee_amount
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
#[test_log::test]
async fn test_double_remuneration_fails() -> anyhow::Result<()> {
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    )
    .await?;
    let user_config_clone = user_config.clone();

    let user_address = user_config_clone.wallet_private_key.address().to_string();
    ensure_core_available("test_double_remuneration_fails:user", &user_config_clone).await?;
    let user_client = Client::new(user_config).await?;

    let recipient_config = build_authed_recipient_config(
        "http://localhost:3000",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    )
    .await?;
    let recipient_config_clone = recipient_config.clone();

    let recipient_address = recipient_config_clone
        .wallet_private_key
        .address()
        .to_string();
    let recipient_client = Client::new(recipient_config).await?;

    let core_total_before = recipient_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &recipient_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

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
    let claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::ZERO,
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };
    println!("[double] claims struct: {:?}", claims);

    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    let bls_cert = user_client
        .user
        .issue_payment_guarantee(claims.clone(), payment_sig.signature, payment_sig.scheme)
        .await?;
    println!(
        "[double] issued cert: claims=0x{} signature=0x{}",
        bls_cert.claims, bls_cert.signature
    );

    let guarantee = recipient_client
        .recipient
        .verify_payment_guarantee(&bls_cert)?;

    let claims_bytes = crypto::hex::decode_hex(&bls_cert.claims)?;
    println!(
        "[double] encoded claims bytes=0x{}",
        hex::encode(&claims_bytes)
    );
    let expected_bytes: Vec<u8> = guarantee.try_into()?;
    println!(
        "[double] expected claims bytes=0x{}",
        hex::encode(&expected_bytes)
    );
    assert_eq!(claims_bytes, expected_bytes);

    recipient_client
        .recipient
        .remunerate(bls_cert.clone())
        .await?;

    wait_for_tab_remunerated(&recipient_client, tab_id).await?;

    let result = recipient_client.recipient.remunerate(bls_cert).await;

    assert!(matches!(
        result,
        Err(RemunerateError::TabPreviouslyRemunerated)
    ));

    Ok(())
}
