use crate::RpcResult;
use crate::common::{UserInfo, UserTransactionInfo};
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

    #[method(name = "addCollateral")]
    async fn deposit(&self, user_addr: String, amount: U256) -> RpcResult<()>;

    #[method(name = "getUser")]
    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>>;

    #[method(name = "issueGuarantee")]
    async fn issue_guarantee(
        &self,
        user_addr: String,
        recipient_addr: String,
        tab_id: String,
        req_id: String,
        transaction_id: String,
        amount: U256,
    ) -> RpcResult<BLSCert>;

    #[method(name = "getTransactionsByHash")]
    async fn get_transactions_by_hash(
        &self,
        hashes: Vec<String>,
    ) -> RpcResult<Vec<UserTransactionInfo>>;
}
