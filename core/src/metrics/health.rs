use async_trait::async_trait;
use metrics_4mica::{Metric, MetricAccess, MetricLabels, measure};

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

impl ToString for HealthScope {
    fn to_string(&self) -> String {
        match self {
            HealthScope::Db => "db".to_string(),
            HealthScope::ChainRpc => "chain_rpc".to_string(),
            HealthScope::Overall => "overall".to_string(),
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
