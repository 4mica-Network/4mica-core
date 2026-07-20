use alloy::primitives::{Address, U256};
use sdk_4mica::Client;
use std::str::FromStr;

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, build_authed_user_config, eth_rpc_url, fund_user_with_erc20,
    mine_confirmations,
};

/// Default anvil account, prefunded with ETH for gas on the local stack.
const USER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_deposit_all_supported_erc20s_credit_collateral() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let user_config = build_authed_user_config("http://localhost:3000", USER_KEY).await?;
    let user_address = user_config.signer.address();
    let user_client = Client::new(user_config.clone()).await?;
    let supported = user_client.get_supported_tokens().await?;
    assert!(
        !supported.tokens.is_empty(),
        "core must advertise at least one supported ERC20"
    );

    let rpc_url = eth_rpc_url(&user_config).await?;

    for token in &supported.tokens {
        let token_address = Address::from_str(&token.address)?;

        // 1 whole token, in that token's own decimals (USDC is 6, not 18).
        let amount = U256::from(10u64).pow(U256::from(token.decimals));

        // Baseline comes from the endpoint the wait polls, so the two cannot disagree.
        let total_before = user_client
            .recipient
            .get_user_asset_balance(token.address.clone())
            .await?
            .map(|balance| balance.total)
            .unwrap_or(U256::ZERO);

        fund_user_with_erc20(&rpc_url, token_address, user_address, amount).await?;

        // The 4mica contract pulls the tokens, so it needs an allowance first.
        user_client
            .user
            .approve_erc20(token.address.clone(), amount)
            .await?;

        user_client
            .user
            .deposit(amount, Some(token.address.clone()))
            .await?;

        // The deposit only reaches core's DB once the scanner sees a confirmed block.
        mine_confirmations(&user_config, 2).await?;

        common::wait_for_collateral_increase(
            &user_client.recipient,
            token_address,
            total_before,
            amount,
        )
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "{} ({}) deposit did not credit collateral: {err}",
                token.symbol,
                token.address
            )
        })?;
    }

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_deposit_native_eth_credits_collateral() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let user_config = build_authed_user_config("http://localhost:3000", USER_KEY).await?;
    let user_client = Client::new(user_config.clone()).await?;

    let total_before = user_client
        .recipient
        .get_user_asset_balance(ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|balance| balance.total)
        .unwrap_or(U256::ZERO);

    let amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // `None` takes the contract's payable `deposit()`; nothing is pulled, so no approval.
    user_client.user.deposit(amount, None).await?;

    mine_confirmations(&user_config, 2).await?;

    common::wait_for_collateral_increase(
        &user_client.recipient,
        ETH_ASSET_ADDRESS,
        total_before,
        amount,
    )
    .await?;

    Ok(())
}
