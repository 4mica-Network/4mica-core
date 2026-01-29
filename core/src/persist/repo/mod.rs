use crate::error::PersistDbError;
use crate::persist::PersistCtx;

pub mod auth;
pub mod balances;
pub mod collateral;
pub mod common;
pub mod events;
pub mod guarantees;
pub mod settlement;
pub mod tabs;
pub mod transactions;
pub mod users;
pub mod withdrawals;

pub use auth::*;
pub use balances::*;
pub use collateral::*;
pub use common::Address;
pub use events::*;
pub use guarantees::*;
pub use tabs::*;
pub use transactions::*;
pub use users::*;
pub use withdrawals::*;

/// Shared query helpers that cross module boundaries.
pub async fn get_collateral_events_for_tab(
    ctx: &PersistCtx,
    tab_id: alloy::primitives::U256,
) -> Result<Vec<entities::collateral_event::Model>, PersistDbError> {
    use crate::util::u256_to_string;
    use entities::collateral_event;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

    let rows = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .order_by_desc(collateral_event::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}
