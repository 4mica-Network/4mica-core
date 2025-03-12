use crate::RpcResult;
use crypto::bls::BLSCert;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use crate::common::UserInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePublicParameters {
    pub public_key: Vec<u8>,
}

#[rpc(server, client, namespace = "core")]
pub trait CoreApi {
    #[method(name = "getPublicParams")]
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters>;

    #[method(name = "registerUser")]
    async fn register_user(&self, user_addr: String) -> RpcResult<()>;

    #[method(name = "registerRecipient")]
    async fn register_recipient(&self, user_addr: String) -> RpcResult<()>;
    
    #[method(name = "getUser")]
    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>>;

    #[method(name = "getRecipient")]
    async fn get_recipient(&self, user_addr: String) -> RpcResult<Option<UserInfo>>;
    

    #[method(name = "issuePaymentCert")]
    async fn issue_payment_cert(
        &self,
        user_addr: String,
        transaction_id: String,
        amount: f64,
    ) -> RpcResult<BLSCert>;
}
