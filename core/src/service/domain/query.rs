//! Read-only lookups served straight from the ledger.

use std::sync::Arc;

use rpc::{AssetBalanceInfo, UserTransactionInfo};

use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_PAYMENT_READ;
use crate::error::ServiceResult;
use crate::persist::mapper;
use crate::persist::repo;
use crate::service::ctx::Ctx;

pub struct QueryService {
    ctx: Arc<Ctx>,
}

impl QueryService {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    pub async fn list_recipient_payments(
        &self,
        auth: &AccessContext,
        recipient_address: String,
    ) -> ServiceResult<Vec<UserTransactionInfo>> {
        access::require_scope(auth, SCOPE_PAYMENT_READ)?;
        access::require_recipient_match(auth, &recipient_address)?;

        let rows = repo::get_recipient_transactions(
            &self.ctx.persist,
            crate::evm::parse_address("recipient", &recipient_address)?,
        )
        .await?;
        Ok(rows
            .into_iter()
            .map(mapper::user_transaction_to_info)
            .collect())
    }

    pub async fn get_user_asset_balance(
        &self,
        auth: &AccessContext,
        user_address: String,
        asset_address: String,
    ) -> ServiceResult<Option<AssetBalanceInfo>> {
        access::require_scope(auth, SCOPE_PAYMENT_READ)?;
        access::require_user_match_or_privileged(auth, &user_address)?;

        let Some(balance) = repo::get_user_asset_balance(
            &self.ctx.persist,
            crate::evm::parse_address("user", &user_address)?,
            crate::evm::parse_address("asset", &asset_address)?,
        )
        .await?
        else {
            return Ok(None);
        };

        Ok(Some(mapper::asset_balance_to_info(balance)))
    }
}
