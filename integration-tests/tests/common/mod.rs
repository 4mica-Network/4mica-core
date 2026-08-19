#![allow(dead_code)]

use alloy::network::TransactionBuilder;
use alloy::providers::{Provider, ProviderBuilder, ext::AnvilApi};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use anyhow::{Context, bail};
use core_service::persist::{PersistCtx, repo};
use crypto::hex::DecodeHexError;
use rpc::RpcProxy;
use sdk_4mica::{
    AccountClient, Address, Asset, Client, Config, ConfigBuilder, DepositPath, U256, UserInfo,
};
use serde::Deserialize;
use std::str::FromStr;
use std::time::{Duration, Instant};

pub mod clearing;
pub mod x402;

sol! {
    #[sol(rpc)]
    contract OwnedERC20 {
        function mint(address to, uint256 amount) external;
        function owner() external view returns (address);
        function balanceOf(address account) external view returns (uint256);
        function masterMinter() external view returns (address);
        function configureMinter(address minter, uint256 minterAllowedAmount) external returns (bool);
    }
}

sol! {
    #[sol(rpc)]
    contract Core4MicaView {
        function withdrawalGracePeriod() external view returns (uint256);
    }
}

pub const ETH_ASSET_ADDRESS: Address = Address::ZERO;
pub const LOCAL_CORE_URL: &str = "http://localhost:3000";
const LOCAL_CORE_E2E_ENV: &str = "SDK_LOCAL_E2E";
const ROLE_USER: &str = "user";
const ROLE_RECIPIENT: &str = "recipient";
const WALLET_STATUS_ACTIVE: &str = "active";
const SCOPE_PAYMENT_READ: &str = "payment:read";
const SCOPE_GUARANTEE_ISSUE: &str = "guarantee:issue";

pub fn normalize_and_decode_hex(value: &str) -> Result<Vec<u8>, DecodeHexError> {
    let normalized = if value.starts_with("0x") {
        value
    } else {
        &format!("0x{}", value)
    };

    let decoded = crypto::hex::decode_hex(normalized)?;
    Ok(decoded)
}

pub fn get_now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}

pub fn skip_without_local_core_stack() -> bool {
    if std::env::var_os(LOCAL_CORE_E2E_ENV).is_some() {
        return false;
    }

    eprintln!(
        "skipping test: set {LOCAL_CORE_E2E_ENV}=1 to run SDK tests against a local core/anvil stack"
    );
    true
}

pub async fn get_chain_timestamp<S>(config: &Config<S>) -> anyhow::Result<u64> {
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

pub async fn mine_confirmations<S>(config: &Config<S>, blocks: u64) -> anyhow::Result<()> {
    load_core_env();
    // The dev/CI core-service runs `CONFIRMATION_MODE=depth`; mine the extra
    // NUMBER_OF_BLOCKS_TO_CONFIRM blocks the scanner subtracts to reach its
    // confirmed head so the event surfaces.
    let confirmation_depth = std::env::var("NUMBER_OF_BLOCKS_TO_CONFIRM")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    let total_blocks = blocks.saturating_add(confirmation_depth);
    if total_blocks == 0 {
        return Ok(());
    }

    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    let public_params = rpc_proxy.get_public_params().await?;
    let response = reqwest::Client::new()
        .post(public_params.ethereum_http_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "anvil_mine",
            "params": [total_blocks]
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload: serde_json::Value = response.json().await?;
    if let Some(err) = payload.get("error") {
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or_default();
        if code == -32601 || message.contains("Method not found") {
            // Non-anvil RPCs do not support `anvil_mine`; tests will rely on natural block progress.
            return Ok(());
        }
        bail!("anvil_mine failed: code={code}, message={message}");
    }
    Ok(())
}

/// Resolve the Ethereum RPC URL the core service is bound to, from its public params.
/// Mirrors `DEPOSIT_AUTHORIZATION_TTL_SECS` in the SDK.
pub const DEPOSIT_AUTHORIZATION_TTL_SECS: u64 = 3600;

pub async fn eth_balance<S>(config: &Config<S>, who: Address) -> anyhow::Result<U256> {
    let rpc_url = eth_rpc_url(config).await?;
    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    Ok(provider.get_balance(who).await?)
}

/// The SDK stamps deposit deadlines from the host clock, but the token checks them against
/// `block.timestamp`. Other suites on this stack call `evm_increaseTime` (withdrawal grace
/// periods), which can leave the chain hours or days ahead of wall clock — at which point every
/// authorization signed here is already expired on arrival.
///
/// Rather than fail confusingly depending on which test ran first, detect the drift and skip.
pub async fn skip_on_chain_clock_drift<S>(config: &Config<S>) -> anyhow::Result<bool> {
    let chain_ts = get_chain_timestamp(config).await?;
    let host_ts = get_now().as_secs();
    if chain_ts >= host_ts.saturating_add(DEPOSIT_AUTHORIZATION_TTL_SECS) {
        eprintln!(
            "skipping test: chain clock is {}s ahead of the host, so a \
             {DEPOSIT_AUTHORIZATION_TTL_SECS}s authorization is already expired on-chain. Restart \
             the stack (`make dev-down dev-up`) to run this test.",
            chain_ts.saturating_sub(host_ts)
        );
        return Ok(true);
    }
    Ok(false)
}

pub async fn eth_rpc_url<S>(config: &Config<S>) -> anyhow::Result<String> {
    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    Ok(rpc_proxy.get_public_params().await?.ethereum_http_rpc_url)
}

/// Fast-forward the anvil chain clock by `seconds` and mine a block so the new
/// timestamp takes effect. Used to elapse on-chain time-locks (e.g. the
/// withdrawal grace period) without waiting in wall-clock time. No-op on RPCs
/// that don't expose `evm_increaseTime`.
pub async fn advance_chain_time<S>(config: &Config<S>, seconds: u64) -> anyhow::Result<()> {
    let url = eth_rpc_url(config).await?;
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "evm_increaseTime",
            "params": [seconds]
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload: serde_json::Value = response.json().await?;
    if let Some(err) = payload.get("error") {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or_default();
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if code == -32601 || message.contains("Method not found") {
            return Ok(());
        }
        bail!("evm_increaseTime failed: code={code}, message={message}");
    }
    // Mine a block so the increased time is reflected in `block.timestamp`.
    mine_confirmations(config, 1).await
}

/// Read the contract's current withdrawal grace period (seconds).
pub async fn withdrawal_grace_period<S>(config: &Config<S>) -> anyhow::Result<u64> {
    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    let public_params = rpc_proxy.get_public_params().await?;
    let contract_address = Address::from_str(&public_params.contract_address)?;
    let provider = ProviderBuilder::new()
        .connect(&public_params.ethereum_http_rpc_url)
        .await?;
    let grace = Core4MicaView::new(contract_address, &provider)
        .withdrawalGracePeriod()
        .call()
        .await?;
    Ok(grace.to::<u64>())
}

/// Mint `amount` of an owner-mintable test ERC20 to `user` by impersonating the
/// token owner on anvil (the forked token's owner is not an anvil account, so it
/// first gets funded with gas ETH).
pub async fn fund_user_with_erc20(
    rpc_url: &str,
    token: Address,
    user: Address,
    amount: U256,
) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    let probe = OwnedERC20::new(token, &provider);

    // A FiatToken (forked USDC) exposes both `masterMinter()` and `owner()`, but only accounts the
    // masterMinter has authorised may mint — so it must be checked first. An owner-mintable forked
    // token mints from its owner; an unrestricted mock (neither role) is minted straight from the
    // recipient.
    let (minter, needs_minter_role) = match probe.masterMinter().call().await {
        Ok(master_minter) => (master_minter, true),
        Err(_) => (probe.owner().call().await.unwrap_or(user), false),
    };

    provider.anvil_impersonate_account(minter).await?;
    // A forked token's owner is not an anvil account and holds no gas ETH, so top
    // it up. Never touch the recipient's own balance — anvil_set_balance
    // overwrites, and clobbering it would starve later deposits from that account.
    if minter != user {
        provider
            .anvil_set_balance(minter, U256::from(10u64).pow(U256::from(18)))
            .await?;
    }

    let send_from_minter = async |input: Vec<u8>| -> anyhow::Result<()> {
        let tx = TransactionRequest::default()
            .with_from(minter)
            .with_to(token)
            .with_input(input);
        provider.send_transaction(tx).await?.watch().await?;
        Ok(())
    };

    // The masterMinter can authorise itself, and the allowance is consumed by the mint below.
    if needs_minter_role {
        send_from_minter(
            OwnedERC20::configureMinterCall {
                minter,
                minterAllowedAmount: amount,
            }
            .abi_encode(),
        )
        .await?;
    }

    send_from_minter(OwnedERC20::mintCall { to: user, amount }.abi_encode()).await?;

    provider.anvil_stop_impersonating_account(minter).await?;
    Ok(())
}

pub async fn assert_core_contract_deployed<S>(config: &Config<S>) -> anyhow::Result<()> {
    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    let public_params = rpc_proxy.get_public_params().await?;

    let response = reqwest::Client::new()
        .post(public_params.ethereum_http_rpc_url.clone())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getCode",
            "params": [public_params.contract_address, "latest"]
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload: serde_json::Value = response.json().await?;
    let code = payload
        .get("result")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing result from eth_getCode response"))?;

    if code == "0x" || code == "0x0" {
        bail!(
            "core contract has no bytecode at configured address on current RPC; contract_address={}, ethereum_http_rpc_url={}",
            public_params.contract_address,
            public_params.ethereum_http_rpc_url
        );
    }

    Ok(())
}

pub fn extract_asset_info(assets: &[UserInfo], asset_address: Address) -> Option<&UserInfo> {
    assets
        .iter()
        .find(|info| info.asset == asset_address.to_string())
}

pub async fn wait_for_collateral_increase<S: Signer + Sync>(
    account: &AccountClient<S>,
    asset_address: Address,
    starting_total: U256,
    increase_by: U256,
) -> anyhow::Result<()> {
    let poll_interval = Duration::from_millis(200);
    let timeout = Duration::from_secs(60);
    let start = Instant::now();
    let asset_address = asset_address.to_string();
    let target_total = starting_total + increase_by;
    let mut last_total = starting_total;

    loop {
        if let Some(balance) = account.asset_balance(asset_address.clone()).await? {
            last_total = balance.total;
            if last_total >= target_total {
                return Ok(());
            }
        }

        if start.elapsed() > timeout {
            bail!(
                "timed out waiting for collateral increase to {target_total:?}, last observed total {last_total:?}"
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
) -> anyhow::Result<Config<PrivateKeySigner>> {
    let access_token = login_with_siwe(base_url, private_key, role, scopes).await?;
    let config = ConfigBuilder::default()
        .rpc_url(base_url.to_string())
        .signer(PrivateKeySigner::from_str(private_key)?)
        .bearer_token(access_token)
        .build()?;
    Ok(config)
}

pub async fn build_authed_user_config(
    base_url: &str,
    private_key: &str,
) -> anyhow::Result<Config<PrivateKeySigner>> {
    let scopes = vec![SCOPE_PAYMENT_READ.to_string()];
    build_authed_config(base_url, private_key, ROLE_USER, &scopes).await
}

pub async fn build_authed_recipient_config(
    base_url: &str,
    private_key: &str,
) -> anyhow::Result<Config<PrivateKeySigner>> {
    let scopes = vec![
        SCOPE_PAYMENT_READ.to_string(),
        SCOPE_GUARANTEE_ISSUE.to_string(),
    ];
    build_authed_config(base_url, private_key, ROLE_RECIPIENT, &scopes).await
}

/// Authenticated user-role client (and its config) against the local core.
pub async fn authed_user_client(
    private_key: &str,
) -> anyhow::Result<(Config<PrivateKeySigner>, Client<PrivateKeySigner>)> {
    let config = build_authed_user_config(LOCAL_CORE_URL, private_key).await?;
    let client = Client::new(config.clone()).await?;
    Ok((config, client))
}

/// Authenticated recipient-role client (payment:read + guarantee:issue).
pub async fn authed_recipient_client(
    private_key: &str,
) -> anyhow::Result<(Config<PrivateKeySigner>, Client<PrivateKeySigner>)> {
    let config = build_authed_recipient_config(LOCAL_CORE_URL, private_key).await?;
    let client = Client::new(config.clone()).await?;
    Ok((config, client))
}

/// Authenticated recipient-role client whose sponsored actions route through the facilitator at
/// `facilitator_url`.
pub async fn authed_recipient_client_with_facilitator(
    private_key: &str,
    facilitator_url: String,
) -> anyhow::Result<(Config<PrivateKeySigner>, Client<PrivateKeySigner>)> {
    let scopes = vec![
        SCOPE_PAYMENT_READ.to_string(),
        SCOPE_GUARANTEE_ISSUE.to_string(),
    ];
    let access_token =
        login_with_siwe(LOCAL_CORE_URL, private_key, ROLE_RECIPIENT, &scopes).await?;
    let config = ConfigBuilder::default()
        .rpc_url(LOCAL_CORE_URL.to_string())
        .signer(PrivateKeySigner::from_str(private_key)?)
        .bearer_token(access_token)
        .facilitator_url(facilitator_url)
        .build()?;
    let client = Client::new(config.clone()).await?;
    Ok((config, client))
}

/// Core's recorded total collateral for `asset`, used as a deposit baseline.
pub async fn core_total(client: &Client<PrivateKeySigner>, asset: Address) -> anyhow::Result<U256> {
    Ok(client
        .account
        .asset_balance(asset.to_string())
        .await?
        .map_or(U256::ZERO, |balance| balance.total))
}

/// Core's on-chain view of the signer's `asset` position, erroring if absent.
pub async fn user_asset(
    client: &Client<PrivateKeySigner>,
    asset: Address,
) -> anyhow::Result<UserInfo> {
    let assets = client.account.assets().await?;
    extract_asset_info(&assets, asset)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("asset {asset} not found in user info"))
}

pub async fn deposit_collateral_and_await(
    client: &Client<PrivateKeySigner>,
    config: &Config<PrivateKeySigner>,
    erc20_token: Option<String>,
    amount: U256,
) -> anyhow::Result<()> {
    let asset = match &erc20_token {
        Some(token) => Address::from_str(token)?,
        None => ETH_ASSET_ADDRESS,
    };
    let total_before = core_total(client, asset).await?;

    let deposit_asset = match &erc20_token {
        Some(_) => Asset::Erc20(asset),
        None => Asset::Native,
    };
    if erc20_token.is_some() {
        let rpc_url = eth_rpc_url(config).await?;
        fund_user_with_erc20(&rpc_url, asset, config.signer.address(), amount).await?;
        client.deposit.approve_erc20(asset, amount).await?;
    }

    client
        .deposit
        .send_via(DepositPath::SelfFunded, deposit_asset, amount)
        .await?;
    mine_confirmations(config, 2).await?;
    wait_for_collateral_increase(&client.account, asset, total_before, amount).await
}
