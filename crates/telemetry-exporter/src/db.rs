use std::time::Duration;

use anyhow::{Context, bail};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};

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

pub async fn ensure_readonly_session(db: &DatabaseConnection) -> anyhow::Result<()> {
    let stmt = Statement::from_string(db.get_database_backend(), "SHOW transaction_read_only");
    let row = db
        .query_one(stmt)
        .await
        .context("Failed to run read-only probe query")?
        .context("Read-only probe returned no row")?;

    let value: String = row
        .try_get_by_index(0)
        .context("Failed to decode read-only probe result")?;
    if parse_readonly_setting(&value)? {
        return Ok(());
    }

    bail!("Read-only probe failed: transaction_read_only is off")
}

fn parse_readonly_setting(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" => Ok(true),
        "off" | "false" | "0" => Ok(false),
        other => bail!("Unexpected transaction_read_only value: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_readonly_setting;

    #[test]
    fn parses_on_values() {
        assert!(parse_readonly_setting("on").expect("on should parse"));
        assert!(parse_readonly_setting("TRUE").expect("true should parse"));
        assert!(parse_readonly_setting("1").expect("1 should parse"));
    }

    #[test]
    fn parses_off_values() {
        assert!(!parse_readonly_setting("off").expect("off should parse"));
        assert!(!parse_readonly_setting("false").expect("false should parse"));
        assert!(!parse_readonly_setting("0").expect("0 should parse"));
    }

    #[test]
    fn rejects_unknown_value() {
        let err = parse_readonly_setting("maybe").unwrap_err();
        assert!(
            err.to_string()
                .contains("Unexpected transaction_read_only value")
        );
    }
}
