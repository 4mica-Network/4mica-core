use entities::sea_orm_active_enums;
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::{prelude::*, sea_orm::Schema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        let schema = Schema::new(db_backend);

        if let Err(err) = manager
            .create_type(
                schema
                    .create_enum_from_active_enum::<sea_orm_active_enums::UserTransactionStatus>(),
            )
            .await
            && !is_duplicate_type_error(&err)
        {
            return Err(err);
        }

        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE "UserTransaction"
ALTER COLUMN status DROP DEFAULT;
ALTER TABLE "UserTransaction"
ALTER COLUMN status
TYPE user_transaction_status
USING status::user_transaction_status;
ALTER TABLE "UserTransaction"
ALTER COLUMN status
SET DEFAULT 'CONFIRMED'::user_transaction_status;
"#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE "UserTransaction"
ALTER COLUMN status
TYPE text
USING status::text;
"#,
            )
            .await?;

        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name("user_transaction_status")
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

fn is_duplicate_type_error(err: &DbErr) -> bool {
    err.to_string().contains("already exists")
}
