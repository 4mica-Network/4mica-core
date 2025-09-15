use thiserror::Error;
#[derive(Debug, Error)]
pub enum BlockchainListenerError {
    #[error("Failed to decode blockchain logs: {0}")]
    DecodingFailure(#[from] alloy::sol_types::Error),

    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

    #[error("Tab not found: {0}")]
    TabNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    /// Any other unexpected error.
    #[error("Unexpected error: {0}")]
    Other(#[from] anyhow::Error),
}
