use async_trait::async_trait;
use crypto::bls::BLSCert;
use log::{debug, error};
use rpc::common::PaymentGuaranteeClaims;
use rpc::core::{CoreApiClient, CorePublicParameters};
use rpc::proxy::RpcProxy;
use rpc::recipient::RecipientApiServer;
use rpc::RpcResult;

use crate::config::AppConfig;

pub struct RecipientService {
    core_params: CorePublicParameters,
}

impl RecipientService {
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let core_proxy = RpcProxy::new(&config.proxy_config.core_addr).await?;
        let core_params = core_proxy.get_public_params().await?;

        Ok(Self { core_params })
    }
}

#[async_trait]
impl RecipientApiServer for RecipientService {
    async fn verify_payment_guarantee(
        &self,
        user_addr: String,
        cert: BLSCert,
    ) -> RpcResult<Option<PaymentGuaranteeClaims>> {
        let cert_is_valid = cert.verify(&self.core_params.public_key).map_err(|err| {
            error!("Failed to verify payment for user {}: {}", user_addr, err);
            rpc::internal_error()
        })?;

        if !cert_is_valid {
            debug!("Received invalid payment signature from {}", user_addr);
            return Ok(None);
        }

        let claims: PaymentGuaranteeClaims = cert
            .claims_bytes()
            .map_err(|_err| rpc::invalid_params_error("Failed to decode payment claims"))?
            .try_into()
            .map_err(|_err| rpc::invalid_params_error("Failed to deserialize payment claims"))?;
        if user_addr != claims.user_addr {
            debug!("Received non-matching user address: {}", user_addr);
            return Ok(None);
        }

        Ok(Some(claims))
    }
}
