use async_trait::async_trait;
use crypto::bls::BLSCert;
use log::{debug, error};
use rpc::common::{
    PaymentGuaranteeClaims, PaymentVerificationResult, TransactionVerificationResult,
};
use rpc::core::{CoreApiClient, CorePublicParameters};
use rpc::proxy::RpcProxy;
use rpc::recipient::RecipientApiServer;
use rpc::RpcResult;

use crate::config::AppConfig;

pub struct RecipientService {
    core_params: CorePublicParameters,
    core_proxy: RpcProxy,
}

impl RecipientService {
    pub async fn new(config: &AppConfig) -> anyhow::Result<Self> {
        let core_proxy = RpcProxy::new(&config.proxy_config.core_addr).await?;
        let core_params = core_proxy.get_public_params().await?;

        Ok(Self {
            core_params,
            core_proxy,
        })
    }
}

#[async_trait]
impl RecipientApiServer for RecipientService {
    async fn verify_payment_guarantee(
        &self,
        cert: BLSCert,
    ) -> RpcResult<PaymentVerificationResult> {
        let cert_is_valid = cert.verify(&self.core_params.public_key).map_err(|err| {
            error!("Failed to verify payment cert {}", err);
            rpc::internal_error()
        })?;

        if !cert_is_valid {
            debug!("Received invalid payment signature");
            return Ok(PaymentVerificationResult::InvalidCertificate);
        }
        let claims: PaymentGuaranteeClaims = cert
            .claims_bytes()
            .map_err(|_err| rpc::invalid_params_error("Failed to decode payment claims"))?
            .try_into()
            .map_err(|_err| rpc::invalid_params_error("Failed to deserialize payment claims"))?;

        let core_result = self
            .core_proxy
            .verify_transaction(claims.tx_hash.clone())
            .await
            .map_err(|err| {
                error!("Failed to verify transaction {}", err);
                rpc::internal_error()
            })?;

        Ok(match core_result {
            TransactionVerificationResult::Verified => PaymentVerificationResult::Verified(claims),
            TransactionVerificationResult::AlreadyVerified => {
                PaymentVerificationResult::AlreadyVerified(claims)
            }
            TransactionVerificationResult::NotFound => {
                PaymentVerificationResult::InvalidCertificate
            }
        })
    }
}
