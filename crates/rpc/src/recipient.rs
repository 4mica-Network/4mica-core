use crate::common::PaymentGuaranteeClaims;
use crypto::bls::BLSCert;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client, namespace = "recipient")]
pub trait RecipientApi {
    #[method(name = "verifyPaymentGuarantee")]
    async fn verify_payment_guarantee(
        &self,
        user_addr: String,
        cert: BLSCert,
    ) -> RpcResult<Option<PaymentGuaranteeClaims>>;
}
