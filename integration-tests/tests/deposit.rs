use alloy::primitives::{U256, utils::parse_ether};
mod common;
use crate::common::{authed_user_client, deposit_collateral_and_await};

/// Default anvil account, prefunded with ETH for gas on the local stack.
const USER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_deposit_all_supported_erc20s_credit_collateral() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (config, client) = authed_user_client(USER_KEY).await?;
    let supported = client.get_supported_tokens().await?;
    assert!(
        !supported.tokens.is_empty(),
        "core must advertise at least one supported ERC20"
    );

    for token in &supported.tokens {
        // 1 whole token, in that token's own decimals (USDC is 6, not 18).
        let amount = U256::from(10u64).pow(U256::from(token.decimals));
        deposit_collateral_and_await(&client, &config, Some(token.address.clone()), amount)
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

    let (config, client) = authed_user_client(USER_KEY).await?;
    deposit_collateral_and_await(&client, &config, None, parse_ether("1")?).await?;

    Ok(())
}
