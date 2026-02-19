use async_trait::async_trait;
use metrics_4mica::measure;

use crate::{
    metrics::record::{record_health_status, record_task_time},
    scheduler::Task,
    service::CoreService,
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
        record_health_status("db", report.db);
        record_health_status("chain_rpc", report.chain_rpc);
        record_health_status("overall", report.status);

        Ok(())
    }
}
