use alloy::primitives::{Address, U256, keccak256};
use alloy::sol_types::SolValue;
use anyhow::{Result, anyhow};
use chrono::Utc;
use core_service::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS},
    persist::{PersistCtx, repo},
};
use entities::{user, user_asset_balance};
use rand::random;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, Statement, sea_query::OnConflict,
};
use std::str::FromStr;

pub fn init_config() -> Result<AppConfig> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    AppConfig::fetch()
}

pub async fn init_test_env() -> Result<(AppConfig, PersistCtx)> {
    let cfg = init_config()?;
    let ctx = PersistCtx::new().await?;
    Ok((cfg, ctx))
}

pub fn random_address() -> String {
    format!("0x{:040x}", random::<u128>())
}

pub async fn ensure_user(ctx: &PersistCtx, addr: &str) -> Result<()> {
    let now = Utc::now().naive_utc();
    let am = user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        is_suspended: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    user::Entity::insert(am)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn ensure_user_with_collateral(ctx: &PersistCtx, addr: &str, amount: U256) -> Result<()> {
    ensure_user(ctx, addr).await?;
    repo::deposit(
        ctx,
        addr.to_string(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        amount,
    )
    .await?;
    Ok(())
}

pub async fn fetch_user(ctx: &PersistCtx, addr: &str) -> Result<user::Model> {
    user::Entity::find()
        .filter(user::Column::Address.eq(addr.to_string()))
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| anyhow!("user {addr} not found"))
}

pub async fn clear_tables(ctx: &PersistCtx, tables: &[&str]) -> Result<()> {
    for table in tables {
        ctx.db
            .as_ref()
            .execute(Statement::from_string(
                ctx.db.get_database_backend(),
                format!(r#"DELETE FROM "{table}";"#),
            ))
            .await?;
    }
    Ok(())
}

pub async fn clear_all_tables(ctx: &PersistCtx) -> Result<()> {
    clear_tables(
        ctx,
        &[
            "UserTransaction",
            "Withdrawal",
            "Guarantee",
            "Tabs",
            "CollateralEvent",
            "UserAssetBalance",
            "User",
            "AuthNonce",
            "AuthRefreshToken",
            "WalletRole",
            "BlockchainEvent",
            "BlockchainEventCursor",
            "ChainCursor",
        ],
    )
    .await?;

    Ok(())
}

pub async fn read_user_asset_balance(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
) -> Result<Option<user_asset_balance::Model>> {
    let balance = user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address))
        .one(ctx.db.as_ref())
        .await?;

    Ok(balance)
}

/// Read collateral for a user from the user_asset_balance table
pub async fn read_collateral(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
) -> Result<U256> {
    let Some(balance) = read_user_asset_balance(ctx, user_address, asset_address).await? else {
        return Ok(U256::ZERO);
    };
    U256::from_str(&balance.total).map_err(|e| anyhow!("invalid collateral: {}", e))
}

/// Read locked collateral for a user from the user_asset_balance table
pub async fn read_locked_collateral(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
) -> Result<U256> {
    let Some(balance) = read_user_asset_balance(ctx, user_address, asset_address).await? else {
        return Ok(U256::ZERO);
    };
    U256::from_str(&balance.locked).map_err(|e| anyhow!("invalid locked collateral: {}", e))
}

/// Force the user's locked collateral to the provided amount (keeping total constant).
pub async fn set_locked_collateral(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
    amount: U256,
) -> Result<()> {
    let balance = repo::get_user_balance_on(ctx.db.as_ref(), user_address, asset_address).await?;
    let total = U256::from_str(&balance.total)
        .map_err(|e| anyhow!("invalid collateral {}: {}", balance.total, e))?;
    if amount > total {
        return Err(anyhow!(
            "locked collateral {} exceeds total {}",
            amount,
            total
        ));
    }
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        user_address,
        asset_address,
        balance.version,
        total,
        amount,
    )
    .await?;
    Ok(())
}

pub fn compute_guarantee_domain_separator(
    chain_id: u64,
    contract: Address,
) -> anyhow::Result<[u8; 32]> {
    // Solidity: keccak256(abi.encode("4MICA_CORE_GUARANTEE_V1", block.chainid, address(this)))
    let encoded = (
        String::from("4MICA_CORE_GUARANTEE_V1"),
        U256::from(chain_id),
        contract,
    )
        .abi_encode_sequence();

    Ok(keccak256(encoded).into())
}
