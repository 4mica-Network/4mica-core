pub use sea_orm_migration::prelude::*;

mod m20250901_000001_create_table;
mod m20250901_000002_multi_asset;
mod m20250901_000003_user_suspension;
mod m20251116_000005_blockchain_event;
mod m20251118_000006_tab_payment_totals;
mod m20251120_000007_auth_tables;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250901_000001_create_table::Migration),
            Box::new(m20250901_000002_multi_asset::Migration),
            Box::new(m20250901_000003_user_suspension::Migration),
            Box::new(m20251116_000005_blockchain_event::Migration),
            Box::new(m20251118_000006_tab_payment_totals::Migration),
            Box::new(m20251120_000007_auth_tables::Migration),
        ]
    }
}
