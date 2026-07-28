use alloy::providers::Provider;
use log::error;
use sea_orm::ConnectionTrait;
use serde::Serialize;

use crate::service::CoreService;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Fail,
}

impl From<bool> for CheckStatus {
    fn from(value: bool) -> Self {
        if value {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HealthReport {
    pub status: CheckStatus,
    pub db: CheckStatus,
    pub chain_rpc: CheckStatus,
    /// Whether the settlement-cycle timeline still leaves enough seizure margin
    /// under the current on-chain `withdrawalGracePeriod`.
    pub settlement_timing: CheckStatus,
}

impl HealthReport {
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, CheckStatus::Ok)
    }
}

impl CoreService {
    pub async fn run_health_checks(&self) -> HealthReport {
        let db_status = self.check_db().await;
        let rpc_status = self.check_rpc().await;
        let timing_status = self.check_settlement_timing();
        let overall_ok = db_status == CheckStatus::Ok
            && rpc_status == CheckStatus::Ok
            && timing_status == CheckStatus::Ok;

        HealthReport {
            status: overall_ok.into(),
            db: db_status,
            chain_rpc: rpc_status,
            settlement_timing: timing_status,
        }
    }

    fn check_settlement_timing(&self) -> CheckStatus {
        match self.check_settlement_timing_invariant() {
            Ok(()) => CheckStatus::Ok,
            Err(e) => {
                error!("settlement timing health check failed: {e:#}");
                CheckStatus::Fail
            }
        }
    }

    async fn check_db(&self) -> CheckStatus {
        let db = self.persist_ctx().db.as_ref();
        let stmt = sea_orm::Statement::from_string(db.get_database_backend(), "SELECT NOW()");
        match db.query_one_raw(stmt).await {
            Ok(_) => CheckStatus::Ok,
            Err(e) => {
                error!("DB health check failed: {e}");
                CheckStatus::Fail
            }
        }
    }

    async fn check_rpc(&self) -> CheckStatus {
        match self.read_provider().get_block_number().await {
            Ok(_) => CheckStatus::Ok,
            Err(e) => {
                error!("RPC health check failed: {e}");
                CheckStatus::Fail
            }
        }
    }
}
