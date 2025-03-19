use crate::common::{TransactionVerificationResult, UserInfo, UserTransactionInfo};
use crate::RpcResult;
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

    #[method(name = "registerUser")]
    async fn register_user(&self, user_addr: String) -> RpcResult<()>;

    #[method(name = "getUser")]
    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>>;

    #[method(name = "issuePaymentCert")]
    async fn issue_payment_cert(
        &self,
        user_addr: String,
        transaction_id: String,
        amount: f64,
    ) -> RpcResult<BLSCert>;

    #[method(name = "getTransactionsByHash")]
    async fn get_transactions_by_hash(
        &self,
        hashes: Vec<String>,
    ) -> RpcResult<Vec<UserTransactionInfo>>;

    #[method(name = "verifyTransaction")]
    async fn verify_transaction(&self, tx_hash: String)
        -> RpcResult<TransactionVerificationResult>;
}
