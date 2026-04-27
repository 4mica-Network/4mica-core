use crate::error::PersistDbError;
use crate::metrics::misc::record_db_time;
use crate::persist::PersistCtx;
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::SettlementCycleStatus;
use entities::settlement_cycle;
use metrics_4mica::measure;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

pub struct CreateSettlementCycleInput {
    pub id: String,
    pub asset_address: String,
    pub period_start: NaiveDateTime,
    pub period_end: NaiveDateTime,
    pub resolution_cutoff: NaiveDateTime,
    pub clearing_commit_deadline: NaiveDateTime,
    pub payment_submission_deadline: NaiveDateTime,
    pub payment_finality_deadline: NaiveDateTime,
}

#[measure(record_db_time)]
pub async fn get_open_cycle_by_asset(
    ctx: &PersistCtx,
    asset_address: &str,
) -> Result<Option<settlement_cycle::Model>, PersistDbError> {
    get_open_cycle_by_asset_on(ctx.db.as_ref(), asset_address).await
}

#[measure(record_db_time)]
pub async fn get_open_cycle_by_asset_on<C: ConnectionTrait>(
    conn: &C,
    asset_address: &str,
) -> Result<Option<settlement_cycle::Model>, PersistDbError> {
    let model = settlement_cycle::Entity::find()
        .filter(settlement_cycle::Column::AssetAddress.eq(asset_address))
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::Open))
        .order_by_desc(settlement_cycle::Column::PeriodStart)
        .one(conn)
        .await?;
    Ok(model)
}

#[measure(record_db_time)]
pub async fn get_cycle_by_id_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Option<settlement_cycle::Model>, PersistDbError> {
    let model = settlement_cycle::Entity::find_by_id(cycle_id.to_string())
        .one(conn)
        .await?;
    Ok(model)
}

#[measure(record_db_time)]
pub async fn create_settlement_cycle_on<C: ConnectionTrait>(
    conn: &C,
    input: CreateSettlementCycleInput,
) -> Result<settlement_cycle::Model, PersistDbError> {
    let now = chrono::Utc::now().naive_utc();
    let active_model = settlement_cycle::ActiveModel {
        id: Set(input.id.clone()),
        asset_address: Set(input.asset_address),
        period_start: Set(input.period_start),
        period_end: Set(input.period_end),
        resolution_cutoff: Set(input.resolution_cutoff),
        clearing_commit_deadline: Set(input.clearing_commit_deadline),
        payment_submission_deadline: Set(input.payment_submission_deadline),
        payment_finality_deadline: Set(input.payment_finality_deadline),
        status: Set(SettlementCycleStatus::Open),
        gross_payable_amount: Set("0".to_string()),
        gross_receivable_amount: Set("0".to_string()),
        net_settlement_amount: Set("0".to_string()),
        clearing_batch_hash: Set(None),
        commit_tx_hash: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let inserted = settlement_cycle::Entity::insert(active_model)
        .exec_with_returning(conn)
        .await?;
    Ok(inserted)
}

#[measure(record_db_time)]
pub async fn list_open_cycles_ending_before_on<C: ConnectionTrait>(
    conn: &C,
    now: NaiveDateTime,
) -> Result<Vec<settlement_cycle::Model>, PersistDbError> {
    let rows = settlement_cycle::Entity::find()
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::Open))
        .filter(settlement_cycle::Column::PeriodEnd.lte(now))
        .order_by_asc(settlement_cycle::Column::PeriodEnd)
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn freeze_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let result = settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::Open))
        .filter(settlement_cycle::Column::PeriodEnd.lte(now))
        .set(settlement_cycle::ActiveModel {
            status: Set(SettlementCycleStatus::Frozen),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected == 1)
}
