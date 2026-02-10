#![allow(dead_code)]

use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, bail};
use core_service::persist::{PersistCtx, repo};
use rpc::RpcProxy;
use sdk_4mica::{
    Address, Config, ConfigBuilder, U256, UserInfo, client::recipient::RecipientClient,
};
use serde::Deserialize;
use std::str::FromStr;
use std::time::{Duration, Instant};

pub mod x402;

pub const ETH_ASSET_ADDRESS: Address = Address::ZERO;
const ROLE_USER: &str = "user";
const ROLE_RECIPIENT: &str = "recipient";
const WALLET_STATUS_ACTIVE: &str = "active";
const SCOPE_TAB_CREATE: &str = "tab:create";
const SCOPE_TAB_READ: &str = "tab:read";
const SCOPE_GUARANTEE_ISSUE: &str = "guarantee:issue";

pub fn get_now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}

pub async fn get_chain_timestamp(config: &Config) -> anyhow::Result<u64> {
    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    let public_params = rpc_proxy.get_public_params().await?;
    let res = reqwest::Client::new()
        .post(public_params.ethereum_http_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": ["latest", false]
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload: serde_json::Value = res.json().await?;
    let ts_hex = payload
        .get("result")
        .and_then(|result| result.get("timestamp"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing timestamp in latest block response"))?;
    let ts = u64::from_str_radix(ts_hex.trim_start_matches("0x"), 16)?;
    Ok(ts)
}

pub async fn close_tab(tab_id: U256) -> anyhow::Result<()> {
    load_core_env();
    let ctx = PersistCtx::new()
        .await
        .context("connect to core database")?;
    repo::close_tab(&ctx, tab_id).await.context("close tab")?;
    Ok(())
}

pub fn extract_asset_info(assets: &[UserInfo], asset_address: Address) -> Option<&UserInfo> {
    assets
        .iter()
        .find(|info| info.asset == asset_address.to_string())
}

pub async fn wait_for_collateral_increase(
    recipient_client: &RecipientClient,
    user_address: &str,
    asset_address: Address,
    starting_total: U256,
    increase_by: U256,
) -> anyhow::Result<()> {
    let poll_interval = Duration::from_millis(200);
    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let user_address = user_address.to_string();
    let asset_address = asset_address.to_string();
    let target_total = starting_total + increase_by;
    let mut last_total = starting_total;

    loop {
        if let Some(balance) = recipient_client
            .get_user_asset_balance(user_address.clone(), asset_address.clone())
            .await?
        {
            last_total = balance.total;
            if last_total >= target_total {
                return Ok(());
            }
        }

        if start.elapsed() > timeout {
            bail!(
                "timed out waiting for collateral increase to {target_total:?} for user {user_address}, last observed total {last_total:?}"
            );
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[derive(Debug, Deserialize)]
struct AuthNonceResponse {
    nonce: String,
    siwe: SiweTemplateResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SiweTemplateResponse {
    domain: String,
    uri: String,
    chain_id: u64,
    statement: String,
    expiration: String,
    issued_at: String,
}

#[derive(Debug, Deserialize)]
struct AuthVerifyResponse {
    access_token: String,
}

fn build_siwe_message_from_template(
    template: &SiweTemplateResponse,
    address: &str,
    nonce: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{statement}\n\nURI: {uri}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration}",
        domain = template.domain,
        address = address,
        statement = template.statement,
        uri = template.uri,
        chain_id = template.chain_id,
        nonce = nonce,
        issued_at = template.issued_at,
        expiration = template.expiration,
    )
}

fn load_core_env() {
    dotenv::dotenv().ok();
    dotenv::from_filename("core/.env").ok();
    dotenv::from_filename("../core/.env").ok();
}

async fn ensure_wallet_role(address: &str, role: &str, scopes: &[String]) -> anyhow::Result<()> {
    load_core_env();
    let ctx = PersistCtx::new()
        .await
        .context("connect to core database")?;
    repo::upsert_wallet_role(&ctx, address, role, scopes, WALLET_STATUS_ACTIVE)
        .await
        .context("upsert wallet role")?;
    Ok(())
}

async fn login_with_siwe(
    base_url: &str,
    private_key: &str,
    role: &str,
    scopes: &[String],
) -> anyhow::Result<String> {
    let signer = PrivateKeySigner::from_str(private_key)?;
    let address = signer.address().to_string();
    ensure_wallet_role(&address, role, scopes).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_url}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, &address, &nonce_res.nonce);
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let verify_res = client
        .post(format!("{base_url}/auth/verify"))
        .json(&serde_json::json!({
            "address": address,
            "message": message,
            "signature": signature_hex,
        }))
        .send()
        .await?
        .error_for_status()?;
    let verify_res: AuthVerifyResponse = verify_res.json().await?;

    Ok(verify_res.access_token)
}

async fn build_authed_config(
    base_url: &str,
    private_key: &str,
    role: &str,
    scopes: &[String],
) -> anyhow::Result<Config> {
    let access_token = login_with_siwe(base_url, private_key, role, scopes).await?;
    let config = ConfigBuilder::default()
        .rpc_url(base_url.to_string())
        .wallet_private_key(private_key.to_string())
        .bearer_token(access_token)
        .build()?;
    Ok(config)
}

pub async fn build_authed_user_config(base_url: &str, private_key: &str) -> anyhow::Result<Config> {
    let scopes = vec![SCOPE_TAB_READ.to_string()];
    build_authed_config(base_url, private_key, ROLE_USER, &scopes).await
}

pub async fn build_authed_recipient_config(
    base_url: &str,
    private_key: &str,
) -> anyhow::Result<Config> {
    let scopes = vec![
        SCOPE_TAB_CREATE.to_string(),
        SCOPE_TAB_READ.to_string(),
        SCOPE_GUARANTEE_ISSUE.to_string(),
    ];
    build_authed_config(base_url, private_key, ROLE_RECIPIENT, &scopes).await
}
