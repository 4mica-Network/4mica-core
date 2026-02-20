use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use entities::chain_cursor;
use metrics_4mica::measure;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

use super::common::now;
use crate::metrics::misc::record_db_time;

#[measure(record_db_time)]
pub async fn get_chain_cursor(
    ctx: &PersistCtx,
    chain_id: u64,
) -> Result<Option<chain_cursor::Model>, PersistDbError> {
    let row = chain_cursor::Entity::find()
        .filter(chain_cursor::Column::ChainId.eq(chain_id as i64))
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

#[measure(record_db_time)]
pub async fn upsert_chain_cursor(
    ctx: &PersistCtx,
    chain_id: u64,
    last_confirmed_block_number: u64,
    last_confirmed_block_hash: String,
) -> Result<(), PersistDbError> {
    let now = now();
    let row = chain_cursor::ActiveModel {
        chain_id: Set(chain_id as i64),
        last_confirmed_block_number: Set(last_confirmed_block_number as i64),
        last_confirmed_block_hash: Set(last_confirmed_block_hash),
        created_at: Set(now),
        updated_at: Set(now),
    };

    chain_cursor::Entity::insert(row)
        .on_conflict(
            OnConflict::column(chain_cursor::Column::ChainId)
                .update_columns([
                    chain_cursor::Column::LastConfirmedBlockNumber,
                    chain_cursor::Column::LastConfirmedBlockHash,
                    chain_cursor::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(())
}
