//! Both gasless deposit paths against a *running facilitator*: the SDK signs, the facilitator
//! submits and pays the gas, Core4Mica credits the signer. 1 USDC each.
//!
//! `gasless_deposit.rs` covers the same contract path with the submission done in-process, so it
//! needs no facilitator. This one is the only test that exercises the real HTTP service.
//!
//! Everything is hardcoded for the local stack: anvil forked from Base Sepolia (chain 84532, where
//! both tokens exist and the payer is funded), mock Aave plus Core4Mica deployed on top of it, core
//! on `:3000`, and a facilitator on `:8080` with a relayer key. Run it with:
//!
//! ```sh
//! cargo test -p integration-tests --test facilitator_gasless_deposit -- --nocapture
//! ```

use std::future::Future;

use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::client::facilitator::DepositReceipt;
use sdk_4mica::error::DepositError;
use sdk_4mica::{Address, Client, ConfigBuilder, U256};
use serde_json::{Value, json};

mod common;

const CORE_URL: &str = "http://localhost:3000";
const FACILITATOR_URL: &str = "http://localhost:8080";
const ETH_RPC: &str = "http://127.0.0.1:8545";

/// Anvil acct 1, seeded with both mock tokens by the dev stack.
const PAYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// The EIP-3009 mock USDC the dev stack deploys at the Base Sepolia USDC address.
const EIP3009_TOKEN: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
/// Aave's test USDC: EIP-2612 with no `receiveWithAuthorization`, so it can only go through
/// Permit2 — and only stays gasless because the approval is sponsored.
const PERMIT2_TOKEN: &str = "0xba50Cd2A20f6DA35D788639E581bca8d0B5d4D5f";

/// 1 USDC, 6 decimals.
const ONE_USDC: u64 = 1_000_000;

/// Mirrors `DEPOSIT_AUTHORIZATION_TTL_SECS` in the SDK.
const AUTHORIZATION_TTL_SECS: u64 = 3600;

async fn eth_balance(address: Address) -> anyhow::Result<U256> {
    let body: Value = reqwest::Client::new()
        .post(ETH_RPC)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_getBalance", "params": [address.to_string(), "latest"],
        }))
        .send()
        .await?
        .json()
        .await?;
    let hex = body["result"].as_str().unwrap_or("0x0");
    Ok(U256::from_str_radix(hex.trim_start_matches("0x"), 16)?)
}

/// Whether the chain's clock has run so far ahead of the host that the SDK's 1-hour authorization
/// is expired the moment it is signed.
///
/// A long-lived fork drifts, and the resulting failure is an opaque `SIMULATION_REVERTED` from
/// inside the facilitator's simulation. Detect it here and say so instead.
async fn chain_clock_is_ahead() -> anyhow::Result<bool> {
    let body: Value = reqwest::Client::new()
        .post(ETH_RPC)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_getBlockByNumber", "params": ["latest", false],
        }))
        .send()
        .await?
        .json()
        .await?;
    let hex = body["result"]["timestamp"]
        .as_str()
        .unwrap_or("0x0")
        .trim_start_matches("0x");
    let chain = u64::from_str_radix(hex, 16)?;
    let host = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let drift = chain.saturating_sub(host);
    if drift >= AUTHORIZATION_TTL_SECS {
        eprintln!(
            "skipping test: chain clock is {drift}s ahead of the host, so every \
             {AUTHORIZATION_TTL_SECS}s authorization is born expired — re-fork the chain"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Runs `deposit` between the balance reads and asserts it credited the signer for free.
///
/// The future is built by the caller but not awaited until here, so the "before" reads still
/// happen before anything is signed or submitted.
async fn assert_gasless(
    client: &Client<PrivateKeySigner>,
    token: &str,
    label: &str,
    deposit: impl Future<Output = Result<DepositReceipt, DepositError>>,
) -> anyhow::Result<()> {
    let payer = client.signer_address();
    let amount = U256::from(ONE_USDC);
    let collateral_before = client.user.get_principal_balance(token.to_string()).await?;
    let gas_before = eth_balance(payer).await?;

    let receipt = deposit.await?;

    assert_eq!(
        receipt.from, payer,
        "{label}: the facilitator must credit the signer, not itself"
    );
    assert_eq!(
        eth_balance(payer).await?,
        gas_before,
        "{label}: the payer sent a transaction — this was not gasless"
    );
    assert_eq!(
        client.user.get_principal_balance(token.to_string()).await? - collateral_before,
        amount,
        "{label}: expected 1 USDC of collateral to land on the payer"
    );

    println!(
        "[{label}] credited {amount} to {payer} in {:?}",
        receipt.tx_hash
    );
    Ok(())
}

#[tokio::test]
async fn deposits_one_usdc_without_spending_the_payers_gas() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() || chain_clock_is_ahead().await? {
        return Ok(());
    }

    let client = Client::new(
        ConfigBuilder::default()
            .signer(PAYER_KEY.parse::<PrivateKeySigner>()?)
            .rpc_url(CORE_URL.to_string())
            .facilitator_url(FACILITATOR_URL.to_string())
            .build()?,
    )
    .await?;
    let amount = U256::from(ONE_USDC);

    assert_gasless(
        &client,
        EIP3009_TOKEN,
        "eip3009",
        client
            .facilitator
            .deposit_with_authorization(EIP3009_TOKEN.to_string(), amount),
    )
    .await?;

    // Sponsored only while the payer's Permit2 allowance is still zero; later runs take the plain
    // Permit2 path and are gasless for the same reason.
    assert_gasless(
        &client,
        PERMIT2_TOKEN,
        "permit2",
        client
            .facilitator
            .deposit_with_sponsored_permit2(PERMIT2_TOKEN.to_string(), amount),
    )
    .await
}
