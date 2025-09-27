use crate::{
    RpcResult,
    common::{CreatePaymentTabRequest, CreatePaymentTabResult, PaymentGuaranteeRequest},
};
use crypto::bls::BLSCert;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct CorePublicParameters {
    pub public_key: Vec<u8>, // existing BLS pubkey
    // new (helps clients sign EIP-712 correctly)
    pub eip712_name: String,    // e.g., "4mica"
    pub eip712_version: String, // e.g., "1"
    pub chain_id: u64,          // Ethereum chain id used for signing domain
}
#[rpc(server, client, namespace = "core")]
pub trait CoreApi {
    #[method(name = "getPublicParams")]
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters>;

    #[method(name = "issueGuarantee")]
    async fn issue_guarantee(&self, req: PaymentGuaranteeRequest) -> RpcResult<BLSCert>;

    #[method(name = "createPaymentTab")]
    async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> RpcResult<CreatePaymentTabResult>;
}
