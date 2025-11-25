use crate::error::PersistDbError;
use alloy::primitives::Address as AlloyAddress;
use chrono::NaiveDateTime;
use sea_orm::sqlx;
use sea_orm::{DbErr, RuntimeErr};
use std::str::FromStr;
use uuid::Uuid;

/// Thin newtype to guarantee we only move around validated on-chain addresses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address(String);

impl Address {
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, PersistDbError> {
        let trimmed = raw.as_ref().trim();
        let _ = AlloyAddress::from_str(trimmed).map_err(|e| {
            PersistDbError::InvariantViolation(format!("invalid address {trimmed}: {e}"))
        })?;
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

pub fn now() -> NaiveDateTime {
    crate::util::now_naive()
}

pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

pub fn constraint_name(err: &DbErr) -> Option<String> {
    match err {
        DbErr::Exec(RuntimeErr::SqlxError(sqlx::Error::Database(db_err)))
        | DbErr::Query(RuntimeErr::SqlxError(sqlx::Error::Database(db_err))) => {
            db_err.constraint().map(|c| c.to_string())
        }
        _ => None,
    }
}

pub fn is_foreign_key_violation(err: &DbErr) -> bool {
    match err {
        DbErr::Exec(RuntimeErr::SqlxError(sqlx::Error::Database(db_err)))
        | DbErr::Query(RuntimeErr::SqlxError(sqlx::Error::Database(db_err))) => {
            db_err.code().map(|c| c == "23503").unwrap_or(false)
        }
        _ => false,
    }
}

pub fn map_pending_withdrawal_err(
    err: DbErr,
    user_address: &str,
    asset_address: &str,
) -> PersistDbError {
    match constraint_name(&err).as_deref() {
        Some("uniq_user_asset_pending_withdrawal") => PersistDbError::MultiplePendingWithdrawals {
            user: user_address.to_owned(),
            asset: asset_address.to_owned(),
            count: 2,
        },
        _ => PersistDbError::DatabaseFailure(err),
    }
}

pub fn parse_address(addr: impl AsRef<str>) -> Result<Address, PersistDbError> {
    Address::parse(addr)
}
