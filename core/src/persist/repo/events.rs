use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use entities::blockchain_event;
use sea_orm::ColumnTrait;
use sea_orm::sea_query::OnConflict;
use sea_orm::{EntityTrait, QueryFilter, QueryOrder, Set};

use super::common::now;

pub async fn get_last_processed_blockchain_event(
    ctx: &PersistCtx,
) -> Result<Option<blockchain_event::Model>, PersistDbError> {
    blockchain_event::Entity::find()
        .order_by_desc(blockchain_event::Column::BlockNumber)
        .order_by_desc(blockchain_event::Column::LogIndex)
        .one(ctx.db.as_ref())
        .await
        .map_err(Into::into)
}

pub async fn store_blockchain_event(
    ctx: &PersistCtx,
    signature: &str,
    block_number: u64,
    log_index: u64,
) -> Result<bool, PersistDbError> {
    let event = blockchain_event::ActiveModel {
        block_number: Set(block_number as i64),
        log_index: Set(log_index as i64),
        signature: Set(signature.to_string()),
        created_at: Set(now()),
    };

    let affected = blockchain_event::Entity::insert(event)
        .on_conflict(
            OnConflict::columns([
                blockchain_event::Column::BlockNumber,
                blockchain_event::Column::LogIndex,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(affected == 1)
}

pub async fn delete_blockchain_event(
    ctx: &PersistCtx,
    block_number: u64,
    log_index: u64,
) -> Result<(), PersistDbError> {
    blockchain_event::Entity::delete_many()
        .filter(blockchain_event::Column::BlockNumber.eq(block_number as i64))
        .filter(blockchain_event::Column::LogIndex.eq(log_index as i64))
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}
