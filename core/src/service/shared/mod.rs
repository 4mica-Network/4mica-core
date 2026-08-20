//! Shared primitives every domain service is allowed to build on.
//!
//! Modules here depend only on [`Ctx`](super::ctx::Ctx), the repo layer, and the chain seam —
//! never on each other's peers in the domain layer. That restriction is what keeps the
//! dependency graph acyclic.

pub mod clearing_proofs;
pub mod cycle;
pub mod guarantee;
pub mod settlement_ledger;

use crate::error::ServiceError;

/// Flatten a sea-orm transaction error into the service error it wraps.
pub fn map_transaction_error(err: sea_orm::TransactionError<ServiceError>) -> ServiceError {
    match err {
        sea_orm::TransactionError::Transaction(inner) => inner,
        sea_orm::TransactionError::Connection(err) => {
            crate::error::PersistDbError::DatabaseFailure(err).into()
        }
    }
}
