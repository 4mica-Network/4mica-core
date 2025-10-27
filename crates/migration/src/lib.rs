pub use sea_orm_migration::prelude::*;

mod m20250901_000001_create_table;
mod m20250901_000002_multi_asset;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250901_000001_create_table::Migration),
            Box::new(m20250901_000002_multi_asset::Migration),
        ]
    }
}
