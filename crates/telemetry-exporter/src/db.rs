use std::future::Future;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, QueryResult, Statement,
};

#[derive(Debug)]
pub enum QueryExecutionError {
    Timeout { timeout_ms: u64 },
    Query(anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveUsersWindowCounts {
    pub active_users_1h: u64,
    pub active_users_24h: u64,
    pub active_users_7d: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TabStatusAggregate {
    pub status: String,
    pub tabs_count: u64,
    pub total_amount_sum: f64,
    pub paid_amount_sum: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusAmountAggregate {
    pub status: String,
    pub count: u64,
    pub amount_sum: f64,
}

impl QueryExecutionError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }
}

impl std::fmt::Display for QueryExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { timeout_ms } => write!(f, "query timed out after {timeout_ms}ms"),
            Self::Query(err) => write!(f, "query failed: {err}"),
        }
    }
}

impl std::error::Error for QueryExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Timeout { .. } => None,
            Self::Query(err) => Some(err.as_ref()),
        }
    }
}

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

pub async fn ensure_readonly_session(
    db: &DatabaseConnection,
    query_timeout_ms: u64,
) -> anyhow::Result<()> {
    let row = query_one_with_timeout(db, "SHOW transaction_read_only", query_timeout_ms)
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

pub async fn query_one_with_timeout(
    db: &DatabaseConnection,
    sql: &str,
    timeout_ms: u64,
) -> Result<Option<QueryResult>, QueryExecutionError> {
    let stmt = Statement::from_string(db.get_database_backend(), sql.to_owned());
    with_timeout(timeout_ms, async move {
        db.query_one(stmt).await.map_err(anyhow::Error::from)
    })
    .await
}

pub async fn query_all_with_timeout(
    db: &DatabaseConnection,
    sql: &str,
    timeout_ms: u64,
) -> Result<Vec<QueryResult>, QueryExecutionError> {
    let stmt = Statement::from_string(db.get_database_backend(), sql.to_owned());
    with_timeout(timeout_ms, async move {
        db.query_all(stmt).await.map_err(anyhow::Error::from)
    })
    .await
}

pub async fn fetch_users_total(
    db: &DatabaseConnection,
    timeout_ms: u64,
) -> Result<u64, QueryExecutionError> {
    let row = query_one_with_timeout(
        db,
        r#"SELECT COUNT(*)::bigint AS users_total FROM "User""#,
        timeout_ms,
    )
    .await?
    .ok_or_else(|| {
        QueryExecutionError::Query(anyhow!(r#"users_total query returned no row from "User""#))
    })?;

    let users_total: i64 = row
        .try_get("", "users_total")
        .context("Failed to decode users_total query result")
        .map_err(QueryExecutionError::Query)?;

    parse_non_negative_count(users_total).map_err(QueryExecutionError::Query)
}

pub async fn fetch_active_users_window_counts(
    db: &DatabaseConnection,
    timeout_ms: u64,
) -> Result<ActiveUsersWindowCounts, QueryExecutionError> {
    let row = query_one_with_timeout(
        db,
        r#"
        SELECT
            COUNT(DISTINCT user_address) FILTER (
                WHERE created_at >= NOW() - INTERVAL '1 hour'
            )::bigint AS active_users_1h,
            COUNT(DISTINCT user_address) FILTER (
                WHERE created_at >= NOW() - INTERVAL '24 hours'
            )::bigint AS active_users_24h,
            COUNT(DISTINCT user_address) FILTER (
                WHERE created_at >= NOW() - INTERVAL '7 days'
            )::bigint AS active_users_7d
        FROM "UserTransaction"
        "#,
        timeout_ms,
    )
    .await?
    .ok_or_else(|| {
        QueryExecutionError::Query(anyhow!(
            r#"active users query returned no row from "UserTransaction""#
        ))
    })?;

    let active_users_1h = parse_non_negative_count(
        row.try_get("", "active_users_1h")
            .context("Failed to decode active_users_1h")
            .map_err(QueryExecutionError::Query)?,
    )
    .map_err(QueryExecutionError::Query)?;
    let active_users_24h = parse_non_negative_count(
        row.try_get("", "active_users_24h")
            .context("Failed to decode active_users_24h")
            .map_err(QueryExecutionError::Query)?,
    )
    .map_err(QueryExecutionError::Query)?;
    let active_users_7d = parse_non_negative_count(
        row.try_get("", "active_users_7d")
            .context("Failed to decode active_users_7d")
            .map_err(QueryExecutionError::Query)?,
    )
    .map_err(QueryExecutionError::Query)?;

    Ok(ActiveUsersWindowCounts {
        active_users_1h,
        active_users_24h,
        active_users_7d,
    })
}

pub async fn fetch_tabs_status_aggregates(
    db: &DatabaseConnection,
    timeout_ms: u64,
) -> Result<Vec<TabStatusAggregate>, QueryExecutionError> {
    let rows = query_all_with_timeout(
        db,
        r#"
        SELECT
            s::text AS status,
            COUNT(t.id)::bigint AS tabs_count,
            COALESCE(SUM(NULLIF(t.total_amount, '')::numeric), 0)::double precision AS total_amount_sum,
            COALESCE(SUM(NULLIF(t.paid_amount, '')::numeric), 0)::double precision AS paid_amount_sum
        FROM unnest(enum_range(NULL::tab_status)) AS s
        LEFT JOIN "Tabs" t ON t.status = s
        GROUP BY s
        ORDER BY s::text
        "#,
        timeout_ms,
    )
    .await?;

    let mut aggregates = Vec::with_capacity(rows.len());
    for row in rows {
        let status: String = row
            .try_get("", "status")
            .context("Failed to decode tabs status")
            .map_err(QueryExecutionError::Query)?;
        let tabs_count = parse_non_negative_count(
            row.try_get("", "tabs_count")
                .context("Failed to decode tabs_count")
                .map_err(QueryExecutionError::Query)?,
        )
        .map_err(QueryExecutionError::Query)?;
        let total_amount_sum = parse_non_negative_amount(
            row.try_get("", "total_amount_sum")
                .context("Failed to decode total_amount_sum")
                .map_err(QueryExecutionError::Query)?,
            "total_amount_sum",
        )
        .map_err(QueryExecutionError::Query)?;
        let paid_amount_sum = parse_non_negative_amount(
            row.try_get("", "paid_amount_sum")
                .context("Failed to decode paid_amount_sum")
                .map_err(QueryExecutionError::Query)?,
            "paid_amount_sum",
        )
        .map_err(QueryExecutionError::Query)?;

        aggregates.push(TabStatusAggregate {
            status,
            tabs_count,
            total_amount_sum,
            paid_amount_sum,
        });
    }

    Ok(aggregates)
}

pub async fn fetch_guarantee_status_aggregates(
    db: &DatabaseConnection,
    timeout_ms: u64,
) -> Result<Vec<StatusAmountAggregate>, QueryExecutionError> {
    let rows = query_all_with_timeout(
        db,
        r#"
        SELECT
            s::text AS status,
            COUNT(g.tab_id)::bigint AS guarantees_count,
            COALESCE(SUM(NULLIF(g.value, '')::numeric), 0)::double precision AS guarantees_amount_sum
        FROM unnest(enum_range(NULL::settlement_status)) AS s
        LEFT JOIN "Tabs" t ON t.settlement_status = s
        LEFT JOIN "Guarantee" g ON g.tab_id = t.id
        GROUP BY s
        ORDER BY s::text
        "#,
        timeout_ms,
    )
    .await?;

    let mut aggregates = Vec::with_capacity(rows.len());
    for row in rows {
        let status: String = row
            .try_get("", "status")
            .context("Failed to decode guarantee status")
            .map_err(QueryExecutionError::Query)?;
        let count = parse_non_negative_count(
            row.try_get("", "guarantees_count")
                .context("Failed to decode guarantees_count")
                .map_err(QueryExecutionError::Query)?,
        )
        .map_err(QueryExecutionError::Query)?;
        let amount_sum = parse_non_negative_amount(
            row.try_get("", "guarantees_amount_sum")
                .context("Failed to decode guarantees_amount_sum")
                .map_err(QueryExecutionError::Query)?,
            "guarantees_amount_sum",
        )
        .map_err(QueryExecutionError::Query)?;

        aggregates.push(StatusAmountAggregate {
            status,
            count,
            amount_sum,
        });
    }

    Ok(aggregates)
}

pub async fn fetch_settlement_status_aggregates(
    db: &DatabaseConnection,
    timeout_ms: u64,
) -> Result<Vec<StatusAmountAggregate>, QueryExecutionError> {
    let rows = query_all_with_timeout(
        db,
        r#"
        SELECT
            s::text AS status,
            COUNT(ut.tx_id)::bigint AS settlements_count,
            COALESCE(SUM(NULLIF(ut.amount, '')::numeric), 0)::double precision AS settlements_amount_sum
        FROM unnest(enum_range(NULL::user_transaction_status)) AS s
        LEFT JOIN "UserTransaction" ut ON ut.status = s
        GROUP BY s
        ORDER BY s::text
        "#,
        timeout_ms,
    )
    .await?;

    let mut aggregates = Vec::with_capacity(rows.len());
    for row in rows {
        let status: String = row
            .try_get("", "status")
            .context("Failed to decode settlement status")
            .map_err(QueryExecutionError::Query)?;
        let count = parse_non_negative_count(
            row.try_get("", "settlements_count")
                .context("Failed to decode settlements_count")
                .map_err(QueryExecutionError::Query)?,
        )
        .map_err(QueryExecutionError::Query)?;
        let amount_sum = parse_non_negative_amount(
            row.try_get("", "settlements_amount_sum")
                .context("Failed to decode settlements_amount_sum")
                .map_err(QueryExecutionError::Query)?,
            "settlements_amount_sum",
        )
        .map_err(QueryExecutionError::Query)?;

        aggregates.push(StatusAmountAggregate {
            status,
            count,
            amount_sum,
        });
    }

    Ok(aggregates)
}

async fn with_timeout<T, F>(timeout_ms: u64, fut: F) -> Result<T, QueryExecutionError>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let timeout_ms = timeout_ms.max(1);
    match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
        Ok(result) => result.map_err(QueryExecutionError::Query),
        Err(_) => Err(QueryExecutionError::Timeout { timeout_ms }),
    }
}

fn parse_readonly_setting(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" => Ok(true),
        "off" | "false" | "0" => Ok(false),
        other => bail!("Unexpected transaction_read_only value: {other}"),
    }
}

fn parse_non_negative_count(value: i64) -> anyhow::Result<u64> {
    if value < 0 {
        bail!("count must be non-negative, got {value}");
    }
    Ok(value as u64)
}

fn parse_non_negative_amount(value: f64, field_name: &str) -> anyhow::Result<f64> {
    if !value.is_finite() {
        bail!("{field_name} must be finite, got {value}");
    }
    if value < 0.0 {
        bail!("{field_name} must be non-negative, got {value}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_non_negative_amount, parse_non_negative_count, parse_readonly_setting, with_timeout,
    };
    use std::time::Duration;

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

    #[tokio::test]
    async fn timeout_wrapper_returns_timeout_error() {
        let result: Result<(), _> = with_timeout(5, async {
            tokio::time::sleep(Duration::from_millis(25)).await;
            Ok(())
        })
        .await;
        let err = result.expect_err("expected timeout");
        assert!(err.is_timeout());
    }

    #[test]
    fn parses_non_negative_count() {
        assert_eq!(parse_non_negative_count(0).expect("zero should pass"), 0);
        assert_eq!(
            parse_non_negative_count(12).expect("positive should pass"),
            12
        );
    }

    #[test]
    fn rejects_negative_count() {
        let err = parse_non_negative_count(-1).unwrap_err();
        assert!(err.to_string().contains("non-negative"));
    }

    #[test]
    fn parses_non_negative_amount() {
        assert_eq!(
            parse_non_negative_amount(12.5, "amount").expect("positive should pass"),
            12.5
        );
        assert_eq!(
            parse_non_negative_amount(0.0, "amount").expect("zero should pass"),
            0.0
        );
    }

    #[test]
    fn rejects_negative_amount() {
        let err = parse_non_negative_amount(-0.01, "amount").unwrap_err();
        assert!(err.to_string().contains("non-negative"));
    }

    #[test]
    fn rejects_non_finite_amount() {
        let err = parse_non_negative_amount(f64::NAN, "amount").unwrap_err();
        assert!(err.to_string().contains("finite"));
    }
}
