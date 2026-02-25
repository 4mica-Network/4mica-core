use anyhow::{Context, bail};
use envconfig::Envconfig;
use url::Url;

#[derive(Debug, Clone, Envconfig)]
pub struct ExporterConfig {
    #[envconfig(from = "METRICS_EXPORTER_HOST", default = "0.0.0.0")]
    pub host: String,
    #[envconfig(from = "METRICS_EXPORTER_PORT", default = "9464")]
    pub port: u16,
    #[envconfig(from = "LOG_LEVEL", default = "info")]
    pub log_level: log::Level,
    #[envconfig(from = "METRICS_EXPORTER_READONLY_REPLICA_DSN")]
    pub readonly_replica_dsn: String,
}

impl ExporterConfig {
    pub fn fetch() -> anyhow::Result<Self> {
        let cfg = Self::init_from_env().context("Failed to load exporter config")?;
        validate_readonly_replica_dsn(&cfg.readonly_replica_dsn)?;
        Ok(cfg)
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn validate_readonly_replica_dsn(dsn: &str) -> anyhow::Result<()> {
    let trimmed = dsn.trim();
    if trimmed.is_empty() {
        bail!("METRICS_EXPORTER_READONLY_REPLICA_DSN must be set");
    }

    let parsed = Url::parse(trimmed)
        .context("METRICS_EXPORTER_READONLY_REPLICA_DSN is not a valid URL")?;
    match parsed.scheme() {
        "postgres" | "postgresql" => {}
        other => {
            bail!(
                "METRICS_EXPORTER_READONLY_REPLICA_DSN must use postgres/postgresql scheme, got {other}"
            )
        }
    }

    if parsed.host_str().is_none() {
        bail!("METRICS_EXPORTER_READONLY_REPLICA_DSN must include a host");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_readonly_replica_dsn;

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
}
