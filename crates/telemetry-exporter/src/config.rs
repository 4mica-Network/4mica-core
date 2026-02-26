use anyhow::{Context, bail};
use envconfig::Envconfig;
use url::Url;

#[derive(Debug, Clone, Envconfig)]
pub struct ExporterConfig {
    #[envconfig(from = "TELEMETRY_EXPORTER_HOST", default = "0.0.0.0")]
    pub host: String,
    #[envconfig(from = "TELEMETRY_EXPORTER_PORT", default = "9464")]
    pub port: u16,
    #[envconfig(from = "LOG_LEVEL", default = "info")]
    pub log_level: log::Level,
    #[envconfig(from = "TELEMETRY_EXPORTER_READONLY_REPLICA_DSN")]
    pub readonly_replica_dsn: String,
    #[envconfig(from = "TELEMETRY_EXPORTER_SNAPSHOT_INTERVAL_SEC", default = "60")]
    pub snapshot_interval_sec: u64,
    #[envconfig(from = "TELEMETRY_EXPORTER_QUERY_TIMEOUT_MS", default = "5000")]
    pub query_timeout_ms: u64,
    #[envconfig(from = "TELEMETRY_EXPORTER_MAX_DB_CONNECTIONS", default = "5")]
    pub max_db_connections: u32,
    #[envconfig(from = "TELEMETRY_EXPORTER_STALE_AFTER_SEC", default = "180")]
    pub stale_after_sec: u64,
}

impl ExporterConfig {
    pub fn fetch() -> anyhow::Result<Self> {
        let cfg = Self::init_from_env().context("Failed to load exporter config")?;
        validate_readonly_replica_dsn(&cfg.readonly_replica_dsn)?;
        validate_max_db_connections(cfg.max_db_connections)?;
        Ok(cfg)
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn validate_readonly_replica_dsn(dsn: &str) -> anyhow::Result<()> {
    let trimmed = dsn.trim();
    if trimmed.is_empty() {
        bail!("TELEMETRY_EXPORTER_READONLY_REPLICA_DSN must be set");
    }

    let parsed = Url::parse(trimmed)
        .context("TELEMETRY_EXPORTER_READONLY_REPLICA_DSN is not a valid URL")?;
    match parsed.scheme() {
        "postgres" | "postgresql" => {}
        other => {
            bail!(
                "TELEMETRY_EXPORTER_READONLY_REPLICA_DSN must use postgres/postgresql scheme, got {other}"
            )
        }
    }

    if parsed.host_str().is_none() {
        bail!("TELEMETRY_EXPORTER_READONLY_REPLICA_DSN must include a host");
    }

    Ok(())
}

fn validate_max_db_connections(max_db_connections: u32) -> anyhow::Result<()> {
    if max_db_connections == 0 {
        bail!("TELEMETRY_EXPORTER_MAX_DB_CONNECTIONS must be greater than 0");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_max_db_connections, validate_readonly_replica_dsn};

    #[test]
    fn rejects_blank_dsn() {
        let err = validate_readonly_replica_dsn("   ").unwrap_err();
        assert!(err.to_string().contains("must be set"));
    }

    #[test]
    fn rejects_non_postgres_scheme() {
        let err = validate_readonly_replica_dsn("mysql://u:p@127.0.0.1:3306/db").unwrap_err();
        assert!(err.to_string().contains("postgres/postgresql"));
    }

    #[test]
    fn accepts_postgres_dsn() {
        validate_readonly_replica_dsn("postgres://monitor_ro:secret@replica.local:5432/core")
            .expect("postgres DSN should pass validation");
    }

    #[test]
    fn rejects_zero_max_db_connections() {
        let err = validate_max_db_connections(0).unwrap_err();
        assert!(err.to_string().contains("greater than 0"));
    }

    #[test]
    fn accepts_positive_max_db_connections() {
        validate_max_db_connections(5).expect("positive pool size should pass validation");
    }
}
