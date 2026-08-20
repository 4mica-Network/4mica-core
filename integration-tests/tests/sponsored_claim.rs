use sdk_4mica::client::model::{ClaimPath, PayPath};
use sdk_4mica::{Address, U256};

mod common;

use crate::common::{authed_user_client, eth_rpc_url, get_now};

/// Anvil accounts #8 (debtor) and #9 (creditor), distinct from the ones
/// `pay_debit.rs` uses so the two tests never share balance state.
const DEBTOR_KEY: &str = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97";
const CREDITOR_KEY: &str = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

/// The sponsored claim path end to end, through a *real* facilitator: a committed
/// cycle where the debtor pays their net debit, and the creditor collects via the
/// facilitator's `/clearing/claim` — the facilitator's relayer pays the gas, and
/// the payout lands on the creditor in full.
///
/// Needs the local core stack (`make dev-up`) plus a running facilitator (from
/// `facilitator-4mica`, pointed at this core), named via `E2E_FACILITATOR_URL`:
///
/// ```sh
/// E2E_FACILITATOR_URL=http://127.0.0.1:8080 cargo test --test sponsored_claim
/// ```
///
/// Skips with a notice when either is missing. The facilitator's own e2e suite
/// covers the negative half (an unknown cycle refused via core) without this setup.
#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_sponsored_claim_via_facilitator() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }
    let Some(facilitator_url) = std::env::var("E2E_FACILITATOR_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        eprintln!(
            "[sponsored-claim] skipped: set E2E_FACILITATOR_URL to a running facilitator \
             (see the facilitator-4mica repo) to exercise the sponsored claim path"
        );
        return Ok(());
    };

    let (debtor_config, debtor) = authed_user_client(DEBTOR_KEY).await?;
    let (creditor_config, creditor) =
        common::authed_recipient_client_with_facilitator(CREDITOR_KEY, facilitator_url).await?;
    assert!(creditor.settlement.is_gasless_available());
    let debtor_address = debtor_config.signer.address();
    let creditor_address = creditor_config.signer.address();

    let amount = U256::from(1_000_000_000_000_000u64); // 0.001 ETH net debit
    let cycle_id = format!("e2e-sponsored-claim:{}", get_now().as_nanos());

    // Same committed-cycle precondition as `pay_debit.rs`: inject a frozen,
    // backdated cycle and let the running scheduler net and commit it on-chain.
    common::clearing::inject_frozen_two_party_cycle(
        &cycle_id,
        debtor_address,
        creditor_address,
        amount,
    )
    .await?;
    let rpc_url = eth_rpc_url(&debtor_config).await?;
    common::clearing::wait_for_payment_window(&cycle_id, &rpc_url).await?;

    // The debtor funds the cycle; the claim is gated on full funding.
    let pay_receipt = debtor.settlement.pay_net_debit(cycle_id.clone()).await?;
    assert_eq!(pay_receipt.path, PayPath::SelfFunded);
    assert_eq!(pay_receipt.debtor, debtor_address);

    // Strictly the gasless route — no self-funded fallback — so a facilitator
    // refusal fails the test instead of quietly passing through the fallback.
    let balance_before = eth_balance(&rpc_url, creditor_address).await?;
    let receipt = creditor
        .settlement
        .claim_net_credit_gasless(cycle_id)
        .await?;
    assert_eq!(receipt.path, ClaimPath::Sponsored);
    assert_eq!(receipt.creditor, creditor_address);

    // The creditor sent no transaction, so their balance moves by exactly the
    // payout — the relayer's gas never touches them.
    let balance_after = eth_balance(&rpc_url, creditor_address).await?;
    assert_eq!(
        balance_after - balance_before,
        amount,
        "the full net credit must land on the creditor"
    );

    Ok(())
}

async fn eth_balance(rpc_url: &str, address: Address) -> anyhow::Result<U256> {
    let response: serde_json::Value = reqwest::Client::new()
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [format!("{address:#x}"), "latest"],
        }))
        .send()
        .await?
        .json()
        .await?;
    let raw = response["result"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("eth_getBalance returned no result: {response}"))?;
    Ok(U256::from_str_radix(raw.trim_start_matches("0x"), 16)?)
}
