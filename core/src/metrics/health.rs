use async_trait::async_trait;
use metrics_4mica::{Metric, MetricAccess, MetricLabels, measure};
use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::{
    metrics::misc::record_task_time,
    scheduler::Task,
    service::{CoreService, health::CheckStatus},
};

pub struct HealthCheckTask {
    service: CoreService,
    cron_pattern: String,
}

impl HealthCheckTask {
    pub fn new(service: CoreService, cron_pattern: String) -> Self {
        Self {
            service,
            cron_pattern,
        }
    }
}

#[async_trait]
impl Task for HealthCheckTask {
    fn cron_pattern(&self) -> String {
        self.cron_pattern.clone()
    }

    #[measure(record_task_time, name = "health_check")]
    async fn run(&self) -> anyhow::Result<()> {
        let report = self.service.run_health_checks().await;
        record_health_status(HealthScope::Db, report.db);
        record_health_status(HealthScope::ChainRpc, report.chain_rpc);
        record_health_status(HealthScope::Overall, report.status);

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum HealthScope {
    Db,
    ChainRpc,
    Overall,
}

impl Display for HealthScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            HealthScope::Db => f.write_str("db"),
            HealthScope::ChainRpc => f.write_str("chain_rpc"),
            HealthScope::Overall => f.write_str("overall"),
        }
    }
}

#[derive(Debug, Clone, MetricLabels)]
pub struct HealthLabels {
    pub scope: HealthScope,
}

#[derive(Clone, Metric)]
#[gauge(labels = HealthLabels, name = "health_status")]
pub struct HealthStatusMetric;

pub fn record_health_status(scope: HealthScope, status: CheckStatus) {
    let labels = HealthLabels { scope };
    HealthStatusMetric::get(&labels).set(match status {
        CheckStatus::Ok => 1.0,
        CheckStatus::Fail => 0.0,
    });
}
