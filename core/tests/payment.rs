use alloy::primitives::{Address, B256, U256};
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools::PaymentTx;
use core_service::{
    config::DEFAULT_ASSET_ADDRESS, error::CoreContractApiError, ethereum::CoreContractApi,
    persist::repo, service::payment::process_discovered_payment,
};
use entities::{tabs, user_transaction};
use rand::random;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{clear_all_tables, ensure_user, init_test_env, random_address};

struct FailingContractApi;

#[async_trait]
impl CoreContractApi for FailingContractApi {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError> {
        Ok(1)
    }

    async fn get_guarantee_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError> {
        Ok([0u8; 32])
    }

    async fn record_payment(
        &self,
        _tab_id: U256,
        _asset: Address,
        _amount: U256,
    ) -> Result<(), CoreContractApiError> {
        Err(CoreContractApiError::Other(anyhow!(
            "record_payment failed"
        )))
    }
}

#[test_log::test(tokio::test)]
async fn failed_record_payment_removes_pending_transaction() -> anyhow::Result<()> {
    let (_config, ctx) = init_test_env().await?;
    clear_all_tables(&ctx).await?;

    let now = chrono::Utc::now().naive_utc();
    let user_addr = random_address();
    let server_addr = Address::from_str(&random_address())?;
    let server_addr_str = server_addr.to_string();

    ensure_user(&ctx, &user_addr).await?;

    let tab_id = U256::from(42u64);
    let tab_am = tabs::ActiveModel {
        id: Set(format!("{:#x}", tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(server_addr_str.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(300),
    };
    tabs::Entity::insert(tab_am).exec(ctx.db.as_ref()).await?;

    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tx_hash = B256::from(random::<[u8; 32]>());
    let payment = PaymentTx {
        block_number: 1,
        tx_hash,
        from: Address::from_str(&user_addr)?,
        to: server_addr,
        amount: U256::from(10u64),
        tab_id,
        req_id: U256::ZERO,
        erc20_token: None,
    };
    let tx_hash_str = format!("{:#x}", tx_hash);

    let result = process_discovered_payment(&ctx, &FailingContractApi, payment).await;
    assert!(result.is_err());

    let tx_rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_hash_str))
        .all(ctx.db.as_ref())
        .await?;
    assert!(
        tx_rows.is_empty(),
        "pending transactions should be removed on failure: {tx_rows:?}"
    );

    clear_all_tables(&ctx).await?;
    Ok(())
}
