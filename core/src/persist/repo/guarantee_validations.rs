use chrono::{NaiveDateTime, Utc};
use entities::guarantee_validation;
use entities::sea_orm_active_enums::GuaranteeValidationStatus;
use metrics_4mica::measure;
use sea_orm::{
    ActiveEnum, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    prelude::Expr,
};

use crate::error::PersistDbError;
use crate::metrics::misc::record_db_time;

use super::common::map_guarantee_validation_err;

pub struct StoreGuaranteeValidationInput {
    pub guarantee_id: String,
    pub validator: String,
    pub subject: String,
    pub deadline: NaiveDateTime,
    pub params: Vec<u8>,
}

#[measure(record_db_time)]
pub async fn store_guarantee_validation_on<C: ConnectionTrait>(
    conn: &C,
    input: StoreGuaranteeValidationInput,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let active_model = guarantee_validation::ActiveModel {
        guarantee_id: Set(input.guarantee_id.clone()),
        validator: Set(input.validator),
        subject: Set(input.subject.clone()),
        deadline: Set(input.deadline),
        params: Set(input.params),
        status: Set(GuaranteeValidationStatus::Pending),
        evidence: Set(None),
        last_polled_at: Set(None),
        decided_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    guarantee_validation::Entity::insert(active_model)
        .exec_without_returning(conn)
        .await
        .map_err(|err| map_guarantee_validation_err(err, &input.guarantee_id, &input.subject))?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn get_guarantee_validation_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
) -> Result<Option<guarantee_validation::Model>, PersistDbError> {
    Ok(guarantee_validation::Entity::find_by_id(guarantee_id)
        .one(conn)
        .await?)
}

#[measure(record_db_time)]
pub async fn list_pending_guarantee_validations_on<C: ConnectionTrait>(
    conn: &C,
) -> Result<Vec<guarantee_validation::Model>, PersistDbError> {
    Ok(guarantee_validation::Entity::find()
        .filter(guarantee_validation::Column::Status.eq(GuaranteeValidationStatus::Pending))
        .order_by_asc(guarantee_validation::Column::Deadline)
        .order_by_asc(guarantee_validation::Column::GuaranteeId)
        .all(conn)
        .await?)
}

#[measure(record_db_time)]
pub async fn record_guarantee_validation_poll_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
    evidence: Option<Vec<u8>>,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let mut update = guarantee_validation::Entity::update_many()
        .col_expr(
            guarantee_validation::Column::LastPolledAt,
            Expr::value(Some(now)),
        )
        .col_expr(guarantee_validation::Column::UpdatedAt, Expr::value(now));

    if evidence.as_ref().is_some_and(|bytes| !bytes.is_empty()) {
        update = update.col_expr(
            guarantee_validation::Column::Evidence,
            Expr::value(evidence),
        );
    }

    update
        .filter(guarantee_validation::Column::GuaranteeId.eq(guarantee_id))
        .exec(conn)
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn decide_guarantee_validation_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
    status: GuaranteeValidationStatus,
    evidence: Option<Vec<u8>>,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    guarantee_validation::Entity::update_many()
        .col_expr(guarantee_validation::Column::Status, status.as_enum())
        .col_expr(
            guarantee_validation::Column::Evidence,
            Expr::value(evidence),
        )
        .col_expr(
            guarantee_validation::Column::DecidedAt,
            Expr::value(Some(now)),
        )
        .col_expr(
            guarantee_validation::Column::LastPolledAt,
            Expr::value(Some(now)),
        )
        .col_expr(guarantee_validation::Column::UpdatedAt, Expr::value(now))
        .filter(guarantee_validation::Column::GuaranteeId.eq(guarantee_id))
        .filter(guarantee_validation::Column::Status.eq(GuaranteeValidationStatus::Pending))
        .exec(conn)
        .await?;
    Ok(())
}
