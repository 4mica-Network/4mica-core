use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthNonce::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AuthNonce::Address).string().not_null())
                    .col(ColumnDef::new(AuthNonce::Nonce).string().not_null())
                    .col(ColumnDef::new(AuthNonce::ExpiresAt).timestamp().not_null())
                    .col(ColumnDef::new(AuthNonce::UsedAt).timestamp().null())
                    .primary_key(
                        Index::create()
                            .col(AuthNonce::Address)
                            .col(AuthNonce::Nonce),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_auth_nonce_address")
                    .table(AuthNonce::Table)
                    .col(AuthNonce::Address)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_nonce_nonce")
                    .table(AuthNonce::Table)
                    .col(AuthNonce::Nonce)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_nonce_expires_at")
                    .table(AuthNonce::Table)
                    .col(AuthNonce::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AuthRefreshToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuthRefreshToken::TokenHash)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AuthRefreshToken::Address)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthRefreshToken::IssuedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthRefreshToken::ExpiresAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(AuthRefreshToken::RevokedAt)
                            .timestamp()
                            .null(),
                    )
                    .col(ColumnDef::new(AuthRefreshToken::ReplacedBy).string().null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_auth_refresh_token_address")
                    .table(AuthRefreshToken::Table)
                    .col(AuthRefreshToken::Address)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_refresh_token_hash")
                    .table(AuthRefreshToken::Table)
                    .col(AuthRefreshToken::TokenHash)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_refresh_token_expires_at")
                    .table(AuthRefreshToken::Table)
                    .col(AuthRefreshToken::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WalletRole::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WalletRole::Address)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WalletRole::Role).string().not_null())
                    .col(ColumnDef::new(WalletRole::Scopes).json_binary().not_null())
                    .col(ColumnDef::new(WalletRole::Status).string().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_refresh_token_expires_at")
                    .table(AuthRefreshToken::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_refresh_token_hash")
                    .table(AuthRefreshToken::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_refresh_token_address")
                    .table(AuthRefreshToken::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_nonce_expires_at")
                    .table(AuthNonce::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_nonce_nonce")
                    .table(AuthNonce::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_auth_nonce_address")
                    .table(AuthNonce::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(WalletRole::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AuthRefreshToken::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AuthNonce::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum AuthNonce {
    #[sea_orm(iden = "AuthNonce")]
    Table,
    Address,
    Nonce,
    ExpiresAt,
    UsedAt,
}

#[derive(DeriveIden)]
enum AuthRefreshToken {
    #[sea_orm(iden = "AuthRefreshToken")]
    Table,
    TokenHash,
    Address,
    IssuedAt,
    ExpiresAt,
    RevokedAt,
    ReplacedBy,
}

#[derive(DeriveIden)]
enum WalletRole {
    #[sea_orm(iden = "WalletRole")]
    Table,
    Address,
    Role,
    Scopes,
    Status,
}
