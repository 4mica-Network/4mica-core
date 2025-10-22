use alloy::primitives::U256;
use alloy::providers::ext::AnvilApi;
use core_service::persist::{PersistCtx, repo};
use entities::{
    sea_orm_active_enums::{SettlementStatus, TabStatus},
    tabs,
};
use log::debug;
use sea_orm::{EntityTrait, Set};
use serial_test::serial;
use std::time::Duration;
use test_log::test;

mod common;
use crate::common::fixtures::{read_collateral, read_locked_collateral};
use crate::common::setup::{E2eEnvironment, setup_e2e_environment};

static NUMBER_OF_TRIALS: u32 = 60;

fn unique_addr() -> String {
    format!("0x{:040x}", rand::random::<u128>())
}

/// Insert a dummy tab so the listener can resolve user/server addresses.
async fn insert_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    user_addr: &str,
    server_addr: &str,
    asset_addr: &str,
) -> anyhow::Result<()> {
    use chrono::Utc;
    let now = Utc::now().naive_utc();

    let tab = tabs::ActiveModel {
        id: Set(format!("{tab_id:#x}")),
        user_address: Set(user_addr.to_string()),
        server_address: Set(server_addr.to_string()),
        asset_address: Set(asset_addr.to_string()),
        start_ts: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
        ttl: Set(3600i64),
    };

    tabs::Entity::insert(tab).exec(ctx.db.as_ref()).await?;
    Ok(())
}

//
// ────────────────────── TESTS ──────────────────────
//

/// `Transfer` → collateral unlocked.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn transfer_usdc_unlocks_collateral() -> anyhow::Result<()> {
    let E2eEnvironment {
        contract,
        core_service,
        usdc,
        signer_addr,
        ..
    } = setup_e2e_environment().await?;
    let persist_ctx = core_service.persist_ctx();

    let recipient_address = unique_addr();

    usdc.mint(signer_addr, U256::from(100u64))
        .send()
        .await?
        .watch()
        .await?;
    usdc.approve(*contract.address(), U256::from(100u64))
        .send()
        .await?
        .watch()
        .await?;

    let user_address = signer_addr.to_string();
    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_address).await?;

    // deposit 50 USDC
    contract
        .depositStablecoin(*usdc.address(), U256::from(50u64))
        .send()
        .await?
        .watch()
        .await?;

    let tab_id = U256::from(rand::random::<u64>());
    insert_tab(
        &persist_ctx,
        tab_id,
        &user_address,
        &recipient_address,
        &usdc.address().to_string(),
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let balance = repo::get_user_balance_on(
        persist_ctx.db.as_ref(),
        &user_address,
        &usdc.address().to_string(),
    )
    .await?;
    assert_eq!(balance.total.parse::<U256>().unwrap(), U256::from(50u64));

    // lock 20 USDC
    repo::update_user_balance_and_version_on(
        persist_ctx.db.as_ref(),
        &user_address,
        &usdc.address().to_string(),
        balance.version,
        balance.total.parse().unwrap(),
        U256::from(20u64),
    )
    .await?;

    debug!("After locking 20 USDC");

    // transfer 10 USDC to recipient
    contract
        .payTabInERC20Token(
            tab_id,
            *usdc.address(),
            U256::from(10u64),
            recipient_address.parse().unwrap(),
        )
        .send()
        .await?
        .watch()
        .await?;

    debug!("After transferring 10 USDC to recipient");

    // poll DB
    let mut tries = 0;
    loop {
        // we expect the user to have 10 USDC locked (20 - 10)
        let locked =
            read_locked_collateral(persist_ctx, &user_address, &usdc.address().to_string()).await?;
        if locked == U256::from(10u64) {
            break;
        }

        if tries > NUMBER_OF_TRIALS {
            panic!("Transaction not recorded in DB");
        }
        tries += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

/// `Withdrawal` flow for stablecoin → collateral withdrawn event reduces balance.
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[serial]
async fn stablecoin_withdrawn_event_reduces_balance() -> anyhow::Result<()> {
    let E2eEnvironment {
        provider,
        contract,
        core_service,
        usdc,
        signer_addr,
        ..
    } = setup_e2e_environment().await?;
    let user_addr = signer_addr.to_string();
    let persist_ctx = core_service.persist_ctx();

    // ensure user exists before deposit/withdrawal events
    repo::ensure_user_exists_on(persist_ctx.db.as_ref(), &user_addr).await?;

    // mint and approve USDC
    let deposit_amount = U256::from(2000u64);
    usdc.mint(signer_addr, deposit_amount)
        .send()
        .await?
        .watch()
        .await?;
    usdc.approve(*contract.address(), deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    // deposit USDC
    contract
        .depositStablecoin(*usdc.address(), deposit_amount)
        .send()
        .await?
        .watch()
        .await?;

    let withdraw_amount = U256::from(1000u64);
    contract
        .requestWithdrawal_1(*usdc.address(), withdraw_amount)
        .send()
        .await?
        .watch()
        .await?;

    // advance chain time past withdrawal grace period to finalize the withdrawal
    provider
        .anvil_set_block_timestamp_interval(23 * 24 * 60 * 60)
        .await?;
    contract
        .finalizeWithdrawal_1(*usdc.address())
        .send()
        .await?
        .watch()
        .await?;

    // wait until the user collateral shows the reduced balance
    let mut tries = 0;
    loop {
        let current =
            read_collateral(&persist_ctx, &user_addr, &usdc.address().to_string()).await?;
        if current == deposit_amount - withdraw_amount {
            break;
        }

        if tries > NUMBER_OF_TRIALS {
            panic!("Withdrawal finalization not reflected in DB");
        }
        tries += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}
