use std::time::Duration;

use anyhow::Context;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

pub async fn connect_readonly_pool(
    readonly_replica_dsn: &str,
    max_db_connections: u32,
) -> anyhow::Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(readonly_replica_dsn.to_owned());
    options
        .max_connections(max_db_connections)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(5))
        .sqlx_logging(false);

    Database::connect(options)
        .await
        .context("Failed to connect to TELEMETRY_EXPORTER_READONLY_REPLICA_DSN")
}
