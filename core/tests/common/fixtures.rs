use alloy::primitives::{Address, U256};
use anyhow::{Result, anyhow};
use chrono::Utc;
use core_service::{
    config::AppConfig,
    persist::{PersistCtx, repo},
};
use entities::user;
use rand::random;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, Statement, sea_query::OnConflict,
};
use std::str::FromStr;

pub fn init_config() -> Result<AppConfig> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    let cfg = AppConfig::fetch();
    let contract = Address::from_str(&cfg.ethereum_config.contract_address)
        .map_err(|e| anyhow!("invalid contract address: {e}"))?;
    crypto::guarantee::init_guarantee_domain_separator(cfg.ethereum_config.chain_id, contract)?;
    Ok(cfg)
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
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
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
    repo::deposit(ctx, addr.to_string(), amount).await?;
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
