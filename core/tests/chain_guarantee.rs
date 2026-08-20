//! Chain-funded guarantee issuance: collateral arrives via a real on-chain
//! deposit (scanner → DB), then `issue_payment_guarantee` is invoked directly
//! with a constructed `AccessContext` — no HTTP server or SIWE. This closes the
//! gap where every HTTP issuance test seeds collateral straight into the DB.

use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::U256;
use alloy::signers::local::PrivateKeySigner;
use core_service::auth::access::AccessContext;
use core_service::auth::constants::SCOPE_GUARANTEE_ISSUE;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use test_log::test;

#[path = "common/mod.rs"]
mod common;
use common::api::build_signed_req;
use common::chain::{OPERATOR_KEY, mine_confirmations, setup_e2e_environment};
use common::fixtures::{ensure_user, random_address, read_collateral, read_locked_collateral};

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial_test::file_serial(db)]
async fn chain_funded_guarantee_increases_locked_collateral() -> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;
    let provider = env.provider.clone();
    let svc = env.core_service.clone();
    let persist_ctx = svc.persist_ctx();

    // The on-chain signer (operator) doubles as the depositing user so its
    // deposit credits collateral to the address that signs guarantee requests.
    let user_wallet = PrivateKeySigner::from_str(OPERATOR_KEY)?;
    let user_addr = format!("{:#x}", env.signer_addr);
    let recipient_addr = random_address();
    ensure_user(persist_ctx, &user_addr).await?;

    // Fund collateral via a real on-chain deposit → event scanner → DB.
    let deposit_amount = U256::from(10u64);
    env.contract
        .deposit()
        .value(deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    mine_confirmations(&provider, 1).await?;

    let mut tries = 0;
    loop {
        if read_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await? == deposit_amount
        {
            break;
        }
        if tries > 120 {
            panic!("on-chain deposit never reached the database");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let auth = AccessContext {
        wallet_address: recipient_addr.clone(),
        role: "recipient".to_string(),
        scopes: vec![SCOPE_GUARANTEE_ISSUE.to_string()],
    };
    let public_params = svc.system().public_params();

    let locked_before =
        read_locked_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(7u64),
        &user_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    svc.guarantees()
        .issue_payment_guarantee(&auth, req)
        .await
        .expect("chain-funded guarantee should issue");

    let locked_after =
        read_locked_collateral(persist_ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(
        locked_after - locked_before,
        U256::from(7u64),
        "issuing a guarantee should lock the guaranteed amount"
    );

    // A second request exceeding the remaining 3 units of collateral is rejected.
    let req_over = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        U256::from(10u64),
        &user_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    assert!(
        svc.guarantees()
            .issue_payment_guarantee(&auth, req_over)
            .await
            .is_err(),
        "guarantee exceeding remaining collateral must be rejected"
    );

    Ok(())
}
