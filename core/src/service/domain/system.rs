//! Public parameters and chain metadata served to clients before they transact.

use std::sync::Arc;

use anyhow::anyhow;
use rpc::{CorePublicParameters, SupportedTokensResponse};

use crate::error::{ServiceError, ServiceResult};
use crate::service::ctx::Ctx;

pub struct SystemService {
    ctx: Arc<Ctx>,
}

impl SystemService {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    pub fn public_params(&self) -> CorePublicParameters {
        self.ctx.public_params.clone()
    }

    pub fn clearing_house_address(&self) -> String {
        self.ctx
            .config
            .ethereum_config
            .clearing_house_address
            .clone()
    }

    pub async fn get_supported_tokens(&self) -> ServiceResult<SupportedTokensResponse> {
        let tokens = self
            .ctx
            .chain
            .get_supported_tokens()
            .await
            .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        Ok(SupportedTokensResponse {
            chain_id: self.ctx.public_params.chain_id,
            tokens,
        })
    }
}
