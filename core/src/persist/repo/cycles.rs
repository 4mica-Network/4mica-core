use crate::error::PersistDbError;
use crate::metrics::misc::record_db_time;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::{
    ParticipantCycleRole, ParticipantCycleStatus, SettlementCycleStatus,
};
use entities::{clearing_batch, cycle_exposure_edge, cycle_participant_position, settlement_cycle};
use metrics_4mica::measure;
use sea_orm::sea_query::OnConflict;
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

pub struct CreateClearingBatchInput {
    pub cycle_id: String,
    pub asset_address: String,
    pub batch_hash: String,
    pub merkle_root: String,
    pub total_net_debit: String,
    pub total_net_credit: String,
    pub debtor_count: i64,
    pub creditor_count: i64,
    pub committed_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct CycleExposureEdgeInput {
    pub cycle_id: String,
    pub payer: String,
    pub payee: String,
    pub asset_address: String,
    pub gross_amount: U256,
    pub finalized_payable_amount: U256,
    pub disputed_amount: U256,
    pub cancelled_amount: U256,
    pub guarantee_count: i64,
}

#[derive(Debug, Clone)]
pub struct CycleParticipantPositionInput {
    pub cycle_id: String,
    pub participant: String,
    pub asset_address: String,
    pub gross_outgoing: U256,
    pub gross_incoming: U256,
    pub net_debit: U256,
    pub net_credit: U256,
    pub role: ParticipantCycleRole,
    pub status: ParticipantCycleStatus,
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
pub async fn get_cycle_by_id(
    ctx: &PersistCtx,
    cycle_id: &str,
) -> Result<Option<settlement_cycle::Model>, PersistDbError> {
    get_cycle_by_id_on(ctx.db.as_ref(), cycle_id).await
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
pub async fn list_frozen_cycles_resolution_due_on<C: ConnectionTrait>(
    conn: &C,
    now: NaiveDateTime,
) -> Result<Vec<settlement_cycle::Model>, PersistDbError> {
    let rows = settlement_cycle::Entity::find()
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::Frozen))
        .filter(settlement_cycle::Column::ResolutionCutoff.lte(now))
        .order_by_asc(settlement_cycle::Column::ResolutionCutoff)
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn list_netting_computed_cycles_commit_due_on<C: ConnectionTrait>(
    conn: &C,
    now: NaiveDateTime,
) -> Result<Vec<settlement_cycle::Model>, PersistDbError> {
    let rows = settlement_cycle::Entity::find()
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::NettingComputed))
        .filter(settlement_cycle::Column::ClearingCommitDeadline.lte(now))
        .order_by_asc(settlement_cycle::Column::ClearingCommitDeadline)
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn list_payment_window_cycles_finality_due_on<C: ConnectionTrait>(
    conn: &C,
    now: NaiveDateTime,
) -> Result<Vec<settlement_cycle::Model>, PersistDbError> {
    let rows = settlement_cycle::Entity::find()
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::PaymentWindowOpen))
        .filter(settlement_cycle::Column::PaymentFinalityDeadline.lte(now))
        .order_by_asc(settlement_cycle::Column::PaymentFinalityDeadline)
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

#[measure(record_db_time)]
pub async fn mark_cycle_netting_computed_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let result = settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::Frozen))
        .set(settlement_cycle::ActiveModel {
            status: Set(SettlementCycleStatus::NettingComputed),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected == 1)
}

#[measure(record_db_time)]
pub async fn mark_cycle_payment_window_open_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    commit_tx_hash: Option<String>,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let result = settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::NettingComputed))
        .set(settlement_cycle::ActiveModel {
            status: Set(SettlementCycleStatus::PaymentWindowOpen),
            commit_tx_hash: Set(commit_tx_hash),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected == 1)
}

#[measure(record_db_time)]
pub async fn mark_cycle_defaulted_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let result = settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .filter(settlement_cycle::Column::Status.eq(SettlementCycleStatus::PaymentWindowOpen))
        .set(settlement_cycle::ActiveModel {
            status: Set(SettlementCycleStatus::Defaulted),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected == 1)
}

#[measure(record_db_time)]
pub async fn mark_cycle_finalized_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let result = settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .filter(settlement_cycle::Column::Status.is_in([
            SettlementCycleStatus::PaymentWindowOpen,
            SettlementCycleStatus::Defaulted,
        ]))
        .set(settlement_cycle::ActiveModel {
            status: Set(SettlementCycleStatus::Finalized),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected == 1)
}

#[measure(record_db_time)]
pub async fn get_clearing_batch_by_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Option<clearing_batch::Model>, PersistDbError> {
    let row = clearing_batch::Entity::find_by_id(cycle_id.to_string())
        .one(conn)
        .await?;
    Ok(row)
}

#[measure(record_db_time)]
pub async fn create_clearing_batch_on<C: ConnectionTrait>(
    conn: &C,
    input: CreateClearingBatchInput,
) -> Result<clearing_batch::Model, PersistDbError> {
    let now = chrono::Utc::now().naive_utc();
    let model = clearing_batch::ActiveModel {
        cycle_id: Set(input.cycle_id.clone()),
        asset_address: Set(input.asset_address),
        batch_hash: Set(input.batch_hash.clone()),
        merkle_root: Set(input.merkle_root),
        total_net_debit: Set(input.total_net_debit),
        total_net_credit: Set(input.total_net_credit),
        debtor_count: Set(input.debtor_count),
        creditor_count: Set(input.creditor_count),
        committed_at: Set(input.committed_at),
        commit_tx_hash: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let inserted = clearing_batch::Entity::insert(model)
        .on_conflict(
            OnConflict::column(clearing_batch::Column::CycleId)
                .do_nothing()
                .to_owned(),
        )
        .exec_with_returning(conn)
        .await;

    match inserted {
        Ok(row) => {
            settlement_cycle::Entity::update_many()
                .filter(settlement_cycle::Column::Id.eq(&input.cycle_id))
                .set(settlement_cycle::ActiveModel {
                    clearing_batch_hash: Set(Some(input.batch_hash)),
                    updated_at: Set(now),
                    ..Default::default()
                })
                .exec(conn)
                .await?;
            Ok(row)
        }
        Err(err) => {
            if let Some(existing) = get_clearing_batch_by_cycle_on(conn, &input.cycle_id).await? {
                Ok(existing)
            } else {
                Err(err.into())
            }
        }
    }
}

#[measure(record_db_time)]
pub async fn replace_cycle_exposure_edges_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    edges: Vec<CycleExposureEdgeInput>,
) -> Result<(), PersistDbError> {
    let now = chrono::Utc::now().naive_utc();

    cycle_exposure_edge::Entity::delete_many()
        .filter(cycle_exposure_edge::Column::CycleId.eq(cycle_id))
        .exec(conn)
        .await?;

    if edges.is_empty() {
        return Ok(());
    }

    let models = edges
        .into_iter()
        .map(|edge| cycle_exposure_edge::ActiveModel {
            cycle_id: Set(edge.cycle_id),
            payer: Set(edge.payer),
            payee: Set(edge.payee),
            asset_address: Set(edge.asset_address),
            gross_amount: Set(edge.gross_amount.to_string()),
            finalized_payable_amount: Set(edge.finalized_payable_amount.to_string()),
            disputed_amount: Set(edge.disputed_amount.to_string()),
            cancelled_amount: Set(edge.cancelled_amount.to_string()),
            guarantee_count: Set(edge.guarantee_count),
            created_at: Set(now),
            updated_at: Set(now),
        });

    cycle_exposure_edge::Entity::insert_many(models)
        .exec_without_returning(conn)
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn list_exposure_edges_for_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Vec<cycle_exposure_edge::Model>, PersistDbError> {
    let rows = cycle_exposure_edge::Entity::find()
        .filter(cycle_exposure_edge::Column::CycleId.eq(cycle_id))
        .order_by_asc(cycle_exposure_edge::Column::AssetAddress)
        .order_by_asc(cycle_exposure_edge::Column::Payer)
        .order_by_asc(cycle_exposure_edge::Column::Payee)
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn replace_cycle_participant_positions_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    positions: Vec<CycleParticipantPositionInput>,
) -> Result<(), PersistDbError> {
    let now = chrono::Utc::now().naive_utc();

    cycle_participant_position::Entity::delete_many()
        .filter(cycle_participant_position::Column::CycleId.eq(cycle_id))
        .exec(conn)
        .await?;

    if positions.is_empty() {
        return Ok(());
    }

    let models = positions
        .into_iter()
        .map(|position| cycle_participant_position::ActiveModel {
            cycle_id: Set(position.cycle_id),
            participant: Set(position.participant),
            asset_address: Set(position.asset_address),
            gross_outgoing: Set(position.gross_outgoing.to_string()),
            gross_incoming: Set(position.gross_incoming.to_string()),
            net_debit: Set(position.net_debit.to_string()),
            net_credit: Set(position.net_credit.to_string()),
            role: Set(position.role),
            status: Set(position.status),
            settlement_tx_hash: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        });

    cycle_participant_position::Entity::insert_many(models)
        .exec_without_returning(conn)
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn update_cycle_netting_totals_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    gross_payable_amount: U256,
    gross_receivable_amount: U256,
    net_settlement_amount: U256,
) -> Result<(), PersistDbError> {
    let now = chrono::Utc::now().naive_utc();
    settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .set(settlement_cycle::ActiveModel {
            gross_payable_amount: Set(gross_payable_amount.to_string()),
            gross_receivable_amount: Set(gross_receivable_amount.to_string()),
            net_settlement_amount: Set(net_settlement_amount.to_string()),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn update_cycle_net_settlement_amount_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    net_settlement_amount: U256,
) -> Result<(), PersistDbError> {
    let now = chrono::Utc::now().naive_utc();
    settlement_cycle::Entity::update_many()
        .filter(settlement_cycle::Column::Id.eq(cycle_id))
        .set(settlement_cycle::ActiveModel {
            net_settlement_amount: Set(net_settlement_amount.to_string()),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn list_unpaid_debtors_for_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Vec<cycle_participant_position::Model>, PersistDbError> {
    let rows = cycle_participant_position::Entity::find()
        .filter(cycle_participant_position::Column::CycleId.eq(cycle_id))
        .filter(cycle_participant_position::Column::Status.eq(ParticipantCycleStatus::Unpaid))
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn list_participant_positions_for_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Vec<cycle_participant_position::Model>, PersistDbError> {
    let rows = cycle_participant_position::Entity::find()
        .filter(cycle_participant_position::Column::CycleId.eq(cycle_id))
        .all(conn)
        .await?;
    Ok(rows)
}
