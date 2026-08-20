use crate::error::PersistDbError;
use crate::persist::canonical::Canonical;
use alloy::primitives::Address as AlloyAddress;
use chrono::NaiveDateTime;
use sea_orm::sqlx;
use sea_orm::{DbErr, RuntimeErr};
use std::str::FromStr;
use uuid::Uuid;

pub fn now() -> NaiveDateTime {
    crate::util::now_naive()
}

pub fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn database_error(err: &DbErr) -> Option<&dyn sqlx::error::DatabaseError> {
    let runtime_err = match err {
        DbErr::Exec(e) | DbErr::Query(e) => e,
        _ => return None,
    };
    let RuntimeErr::SqlxError(sqlx_err) = runtime_err else {
        return None;
    };
    match sqlx_err.as_ref() {
        sqlx::Error::Database(db_err) => Some(db_err.as_ref()),
        _ => None,
    }
}

pub fn constraint_name(err: &DbErr) -> Option<String> {
    database_error(err)?.constraint().map(|c| c.to_string())
}

pub fn is_foreign_key_violation(err: &DbErr) -> bool {
    database_error(err)
        .and_then(|e| e.code())
        .is_some_and(|c| c == "23503")
}

pub fn is_unique_violation(err: &DbErr) -> bool {
    database_error(err)
        .and_then(|e| e.code())
        .is_some_and(|c| c == "23505")
}

pub fn map_pending_withdrawal_err(
    err: DbErr,
    user_address: AlloyAddress,
    asset_address: AlloyAddress,
) -> PersistDbError {
    match constraint_name(&err).as_deref() {
        Some("uniq_user_asset_pending_withdrawal") => PersistDbError::MultiplePendingWithdrawals {
            user: user_address.canonical(),
            asset: asset_address.canonical(),
            count: 2,
        },
        _ => PersistDbError::DatabaseFailure(err),
    }
}

pub fn map_guarantee_validation_err(
    err: DbErr,
    guarantee_id: &str,
    subject: &str,
) -> PersistDbError {
    if !is_unique_violation(&err) {
        return PersistDbError::DatabaseFailure(err);
    }
    match constraint_name(&err).as_deref() {
        Some("uniq_guarantee_validation_subject") => PersistDbError::InvariantViolation(format!(
            "validation subject {subject} is already in use"
        )),
        _ => PersistDbError::InvariantViolation(format!(
            "guarantee {guarantee_id} already has a validation requirement"
        )),
    }
}

/// Parse an address that arrived as text on a wire type we do not own.
///
/// Prefer taking an [`AlloyAddress`] directly; this exists for the few repo inputs that still
/// carry raw strings from request payloads.
pub fn parse_address(addr: impl AsRef<str>) -> Result<AlloyAddress, PersistDbError> {
    let trimmed = addr.as_ref().trim();
    AlloyAddress::from_str(trimmed)
        .map_err(|e| PersistDbError::InvariantViolation(format!("invalid address {trimmed}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::canonical::Canonical;

    #[test]
    fn parse_normalizes_addresses_to_lowercase_hex() {
        let parsed =
            parse_address("  0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  ").expect("valid address");

        assert_eq!(
            parsed.canonical(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }
}
