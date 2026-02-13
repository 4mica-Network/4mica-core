use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use entities::{blockchain_block, blockchain_event, blockchain_event_cursor};
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

#[allow(clippy::too_many_arguments)]
pub async fn store_blockchain_event(
    ctx: &PersistCtx,
    chain_id: u64,
    signature: &str,
    block_number: u64,
    block_hash: &str,
    tx_hash: &str,
    log_index: u64,
    address: &str,
    data: &str,
) -> Result<bool, PersistDbError> {
    let event = blockchain_event::ActiveModel {
        chain_id: Set(chain_id as i64),
        block_number: Set(block_number as i64),
        block_hash: Set(block_hash.to_string()),
        tx_hash: Set(tx_hash.to_string()),
        log_index: Set(log_index as i64),
        signature: Set(signature.to_string()),
        address: Set(address.to_string()),
        data: Set(data.to_string()),
        created_at: Set(now()),
    };

    let affected = blockchain_event::Entity::insert(event)
        .on_conflict(
            OnConflict::columns([
                blockchain_event::Column::ChainId,
                blockchain_event::Column::BlockHash,
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
    chain_id: u64,
    block_number: u64,
    block_hash: &str,
    log_index: u64,
) -> Result<(), PersistDbError> {
    blockchain_event::Entity::delete_many()
        .filter(blockchain_event::Column::ChainId.eq(chain_id as i64))
        .filter(blockchain_event::Column::BlockNumber.eq(block_number as i64))
        .filter(blockchain_event::Column::BlockHash.eq(block_hash))
        .filter(blockchain_event::Column::LogIndex.eq(log_index as i64))
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn get_blockchain_events_after(
    ctx: &PersistCtx,
    chain_id: u64,
    block_number: u64,
) -> Result<Vec<blockchain_event::Model>, PersistDbError> {
    let rows = blockchain_event::Entity::find()
        .filter(blockchain_event::Column::ChainId.eq(chain_id as i64))
        .filter(blockchain_event::Column::BlockNumber.gt(block_number as i64))
        .order_by_desc(blockchain_event::Column::BlockNumber)
        .order_by_desc(blockchain_event::Column::LogIndex)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn delete_blockchain_events_after(
    ctx: &PersistCtx,
    chain_id: u64,
    block_number: u64,
) -> Result<u64, PersistDbError> {
    let result = blockchain_event::Entity::delete_many()
        .filter(blockchain_event::Column::ChainId.eq(chain_id as i64))
        .filter(blockchain_event::Column::BlockNumber.gt(block_number as i64))
        .exec(ctx.db.as_ref())
        .await?;
    Ok(result.rows_affected)
}

pub async fn get_blockchain_event_cursor(
    ctx: &PersistCtx,
    chain_id: u64,
) -> Result<Option<blockchain_event_cursor::Model>, PersistDbError> {
    blockchain_event_cursor::Entity::find()
        .filter(blockchain_event_cursor::Column::ChainId.eq(chain_id as i64))
        .one(ctx.db.as_ref())
        .await
        .map_err(Into::into)
}

pub async fn upsert_blockchain_event_cursor(
    ctx: &PersistCtx,
    chain_id: u64,
    last_confirmed_block_number: u64,
    last_confirmed_block_hash: Option<String>,
) -> Result<(), PersistDbError> {
    let now = now();
    let row = blockchain_event_cursor::ActiveModel {
        chain_id: Set(chain_id as i64),
        last_confirmed_block_number: Set(last_confirmed_block_number as i64),
        last_confirmed_block_hash: Set(last_confirmed_block_hash),
        created_at: Set(now),
        updated_at: Set(now),
    };

    blockchain_event_cursor::Entity::insert(row)
        .on_conflict(
            OnConflict::column(blockchain_event_cursor::Column::ChainId)
                .update_columns([
                    blockchain_event_cursor::Column::LastConfirmedBlockNumber,
                    blockchain_event_cursor::Column::LastConfirmedBlockHash,
                    blockchain_event_cursor::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(())
}

pub async fn upsert_blockchain_block(
    ctx: &PersistCtx,
    chain_id: u64,
    block_number: u64,
    block_hash: &str,
) -> Result<(), PersistDbError> {
    let now = now();
    let row = blockchain_block::ActiveModel {
        chain_id: Set(chain_id as i64),
        block_number: Set(block_number as i64),
        block_hash: Set(block_hash.to_string()),
        created_at: Set(now),
    };

    blockchain_block::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([
                blockchain_block::Column::ChainId,
                blockchain_block::Column::BlockNumber,
            ])
            .update_column(blockchain_block::Column::BlockHash)
            .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(())
}

pub async fn get_blockchain_block_hash(
    ctx: &PersistCtx,
    chain_id: u64,
    block_number: u64,
) -> Result<Option<String>, PersistDbError> {
    let row = blockchain_block::Entity::find()
        .filter(blockchain_block::Column::ChainId.eq(chain_id as i64))
        .filter(blockchain_block::Column::BlockNumber.eq(block_number as i64))
        .one(ctx.db.as_ref())
        .await?;
    Ok(row.map(|r| r.block_hash))
}

pub async fn delete_blockchain_blocks_after(
    ctx: &PersistCtx,
    chain_id: u64,
    block_number: u64,
) -> Result<u64, PersistDbError> {
    let result = blockchain_block::Entity::delete_many()
        .filter(blockchain_block::Column::ChainId.eq(chain_id as i64))
        .filter(blockchain_block::Column::BlockNumber.gt(block_number as i64))
        .exec(ctx.db.as_ref())
        .await?;
    Ok(result.rows_affected)
}
