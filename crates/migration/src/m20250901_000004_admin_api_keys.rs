use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AdminApiKey {
    #[sea_orm(iden = "AdminApiKey")]
    Table,
    Id,
    Name,
    KeyHash,
    Scopes,
    CreatedAt,
    RevokedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AdminApiKey::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AdminApiKey::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AdminApiKey::Name).string().not_null())
                    .col(ColumnDef::new(AdminApiKey::KeyHash).string().not_null())
                    .col(ColumnDef::new(AdminApiKey::Scopes).json_binary().not_null())
                    .col(
                        ColumnDef::new(AdminApiKey::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AdminApiKey::RevokedAt).timestamp().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AdminApiKey::Table).to_owned())
            .await
    }
}
