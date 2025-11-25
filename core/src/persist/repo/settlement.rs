use crate::error::PersistDbError;
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::SettlementStatus;
use entities::tabs;
use log::info;
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, Set};

/// Centralized, monotonic settlement transitions for tabs:
/// Pending → Settled → Remunerated. Later transitions are idempotent no-ops.
pub async fn transition_settlement<C: ConnectionTrait>(
    conn: &C,
    tab_id: &str,
    target: SettlementStatus,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let mut condition = Condition::all().add(tabs::Column::Id.eq(tab_id));
    match target {
        SettlementStatus::Settled => {
            condition = condition
                .add(tabs::Column::SettlementStatus.ne(SettlementStatus::Settled))
                .add(tabs::Column::SettlementStatus.ne(SettlementStatus::Remunerated));
        }
        SettlementStatus::Remunerated => {
            condition =
                condition.add(tabs::Column::SettlementStatus.ne(SettlementStatus::Remunerated));
        }
        other => {
            return Err(PersistDbError::InvariantViolation(format!(
                "unsupported settlement transition target: {other:?}"
            )));
        }
    }

    let res = tabs::Entity::update_many()
        .filter(condition)
        .set(tabs::ActiveModel {
            settlement_status: Set(target.clone()),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;

    if res.rows_affected == 1 {
        info!("tab {} transitioned to {:?}", tab_id, target);
    }

    Ok(res.rows_affected == 1)
}
