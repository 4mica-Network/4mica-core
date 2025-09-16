use crate::RpcResult;
use alloy_primitives::U256;
use crypto::bls::BLSCert;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePublicParameters {
    pub public_key: Vec<u8>,
}

#[rpc(server, client, namespace = "core")]
pub trait CoreApi {
    #[method(name = "getPublicParams")]
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters>;

    #[method(name = "issueGuarantee")]
    async fn issue_guarantee(
        &self,
        user_addr: String,
        recipient_addr: String,
        tab_id: String,
        req_id: String,
        amount: U256,
    ) -> RpcResult<BLSCert>;
}
