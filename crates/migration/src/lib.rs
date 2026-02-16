pub use sea_orm_migration::prelude::*;

mod m20250901_000001_create_table;
mod m20250901_000002_multi_asset;
mod m20250901_000003_user_suspension;
mod m20250901_000004_admin_api_keys;
mod m20251116_000005_blockchain_event;
mod m20251118_000006_tab_payment_totals;
mod m20251120_000007_auth_tables;
mod m20260210_000008_payment_confirmations;
mod m20260210_000009_user_transaction_tab_id;
mod m20260210_000010_user_transaction_record_tx;
mod m20260210_000015_tab_version_and_last_req_id;
mod m20260211_000011_blockchain_event_cursor;
mod m20260213_000012_blockchain_event_v2;
mod m20260213_000013_event_metadata;
mod m20260213_000014_user_transaction_status_enum;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250901_000001_create_table::Migration),
            Box::new(m20250901_000002_multi_asset::Migration),
            Box::new(m20250901_000003_user_suspension::Migration),
            Box::new(m20250901_000004_admin_api_keys::Migration),
            Box::new(m20251116_000005_blockchain_event::Migration),
            Box::new(m20251118_000006_tab_payment_totals::Migration),
            Box::new(m20251120_000007_auth_tables::Migration),
            Box::new(m20260210_000008_payment_confirmations::Migration),
            Box::new(m20260210_000009_user_transaction_tab_id::Migration),
            Box::new(m20260210_000010_user_transaction_record_tx::Migration),
            Box::new(m20260210_000015_tab_version_and_last_req_id::Migration),
            Box::new(m20260211_000011_blockchain_event_cursor::Migration),
            Box::new(m20260213_000012_blockchain_event_v2::Migration),
            Box::new(m20260213_000013_event_metadata::Migration),
            Box::new(m20260213_000014_user_transaction_status_enum::Migration),
        ]
    }
}
