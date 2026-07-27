//! `SeaORM` Entity for the validation requirement attached to a validation-gated guarantee.

use super::sea_orm_active_enums::GuaranteeValidationStatus;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "GuaranteeValidation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub guarantee_id: String,
    /// Validator identity.
    #[sea_orm(column_type = "Text")]
    pub validator: String,
    /// 0x-prefixed bytes32. Unique across guarantees.
    #[sea_orm(column_type = "Text", unique)]
    pub subject: String,
    /// Enforced deadline.
    pub deadline: DateTime,
    /// Validator-specific policy the payer signed.
    pub params: Vec<u8>,
    pub status: GuaranteeValidationStatus,
    /// Verbatim payload observed from the validator, kept for audit.
    pub evidence: Option<Vec<u8>>,
    pub last_polled_at: Option<DateTime>,
    pub decided_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::guarantee::Entity",
        from = "Column::GuaranteeId",
        to = "super::guarantee::Column::GuaranteeId",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Guarantee,
}

impl Related<super::guarantee::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Guarantee.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
