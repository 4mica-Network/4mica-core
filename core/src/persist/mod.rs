use sea_orm::{Database, DatabaseConnection};
use std::sync::Arc;

pub mod canonical;
pub mod mapper;
pub mod repo;
pub mod rows;

#[derive(Clone)]
pub struct PersistCtx {
    pub db: Arc<DatabaseConnection>,
}

impl PersistCtx {
    /// Connect using the `DATABASE_URL` environment variable.
    pub async fn new() -> anyhow::Result<Self> {
        let url = std::env::var("DATABASE_URL")?;
        let db = Database::connect(url).await?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Inject an existing `DatabaseConnection`.
    pub fn from_conn(conn: DatabaseConnection) -> Self {
        Self { db: Arc::new(conn) }
    }
}
