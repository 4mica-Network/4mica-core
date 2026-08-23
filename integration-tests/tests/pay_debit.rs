use sdk_4mica::U256;
use sdk_4mica::client::model::TokenRoute;
use std::str::FromStr;

mod common;

use crate::common::{authed_recipient_client, authed_user_client, eth_rpc_url, get_now};

/// Anvil accounts #6 (debtor) and #7 (creditor), prefunded with ETH for gas and
/// the on-chain payment on the local stack.
const DEBTOR_KEY: &str = "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e";
const CREDITOR_KEY: &str = "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356";

/// Drive a full clearing settlement through the SDK: a committed cycle where the
/// debtor owes the creditor a net debit, the debtor pays it (`pay_net_debit`),
/// and the creditor claims their net credit (`claim_net_credit`).
///
/// Core has no endpoint to commit a cycle — the running service commits it on a
/// time-based scheduler — so the test injects a frozen, backdated cycle into the
/// DB and lets the running scheduler net and commit it on-chain, then exercises
/// the SDK's settlement calls against the open payment window.
#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_pay_net_debit_and_claim_net_credit() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (debtor_config, debtor) = authed_user_client(DEBTOR_KEY).await?;
    let (creditor_config, creditor) = authed_recipient_client(CREDITOR_KEY).await?;
    let debtor_address = debtor_config.signer.address();
    let creditor_address = creditor_config.signer.address();

    let amount = U256::from(1_000_000_000_000_000u64); // 0.001 ETH net debit
    let cycle_id = format!("e2e-pay-debit:{}", get_now().as_nanos());

    // Inject the committed-cycle precondition and wait for the running scheduler
    // to net and commit it on-chain.
    common::clearing::inject_frozen_two_party_cycle(
        &cycle_id,
        debtor_address,
        creditor_address,
        amount,
    )
    .await?;

    let rpc_url = eth_rpc_url(&debtor_config).await?;
    common::clearing::wait_for_payment_window(&cycle_id, &rpc_url).await?;

    // The debtor's settlement action should describe exactly the net debit owed.
    let pay_action = debtor.settlement.pay(cycle_id.clone()).action().await?;
    assert_eq!(pay_action.function_name, "payNetDebit");
    assert_eq!(U256::from_str(&pay_action.amount)?, amount);

    // Debtor pays the net debit on-chain; a successful receipt is the proof the
    // ClearingHouse accepted the payment (verifying the settlement itself, not
    // core's asynchronous event mirroring).
    let pay_receipt = debtor.settlement.pay(cycle_id.clone()).send().await?;
    assert_eq!(pay_receipt.route, TokenRoute::SelfFunded);
    assert_eq!(pay_receipt.account, debtor_address);

    // The creditor's action should mirror the same net credit, now fully funded
    // by the debtor's payment.
    let claim_action = creditor.settlement.claim(cycle_id.clone()).action().await?;
    assert_eq!(claim_action.function_name, "claimNetCreditFor");
    assert_eq!(U256::from_str(&claim_action.amount)?, amount);

    // Creditor claims the net credit on-chain. A successful return is the proof the ClearingHouse
    // paid out: a mined revert surfaces as `RevertedOnChain`. No facilitator is configured here,
    // so the claim must have gone out as the creditor's own transaction.
    let claim_receipt = creditor.settlement.claim(cycle_id.clone()).send().await?;
    assert!(!claim_receipt.route.is_gasless());

    Ok(())
}
