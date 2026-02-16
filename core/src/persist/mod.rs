use crate::error::{ServiceError, ServiceResult};
use alloy::primitives::U256;
use anyhow::anyhow;
use entities::user_transaction;
use rpc::UserTransactionInfo;
use sea_orm::{Database, DatabaseConnection};
use std::sync::Arc;

pub mod mapper;
pub mod repo;

#[derive(Clone)]
pub struct PersistCtx {
    pub db: Arc<DatabaseConnection>,
}

pub struct GuaranteeData {
    pub tab_id: U256,
    pub req_id: U256,
    pub from: String,
    pub to: String,
    pub asset: String,
    pub value: U256,
    pub start_ts: chrono::NaiveDateTime,
    pub cert: String,
    pub request: Option<String>,
}

impl PersistCtx {
    /// Connect using the `DATABASE_URL` environment variable.
    pub async fn new() -> anyhow::Result<Self> {
        let url = std::env::var("DATABASE_URL")?;
        let db = Database::connect(url).await?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Inject an existing `DatabaseConnection`.
    pub fn from_conn(conn: DatabaseConnection) -> Self {
        Self { db: Arc::new(conn) }
    }
}

/// Local trait to convert SeaORM models into RPC DTOs without hitting the orphan rule.
pub trait IntoUserTxInfo {
    fn into_user_tx_info(self) -> ServiceResult<UserTransactionInfo>;
}

impl IntoUserTxInfo for user_transaction::Model {
    fn into_user_tx_info(self) -> ServiceResult<UserTransactionInfo> {
        let created_at_ms = self.created_at.and_utc().timestamp_millis();
        let amount = self.amount.parse::<U256>().map_err(|e| {
            ServiceError::Other(anyhow!(
                "Failed to parse amount as U256 for tx {}: {e}",
                self.tx_id
            ))
        })?;
        Ok(UserTransactionInfo {
            user_address: self.user_address,
            recipient_address: self.recipient_address,
            tx_hash: self.tx_id,
            amount,
            verified: self.verified,
            finalized: self.finalized,
            failed: self.failed,
            created_at: created_at_ms,
        })
    }
}
