use alloy_primitives::U256;

use crate::{
    RpcResult,
    common::{
        AssetBalanceInfo, CollateralEventInfo, CreatePaymentTabRequest, CreatePaymentTabResult,
        GuaranteeInfo, PaymentGuaranteeRequest, PendingRemunerationInfo, TabInfo,
        UserTransactionInfo,
    },
};
use crypto::bls::BLSCert;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct CorePublicParameters {
    pub public_key: Vec<u8>, // BLS pubkey
    pub contract_address: String,
    pub ethereum_http_rpc_url: String,
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

    #[method(name = "listSettledTabs")]
    async fn list_settled_tabs(&self, recipient_address: String) -> RpcResult<Vec<TabInfo>>;

    #[method(name = "listPendingRemunerations")]
    async fn list_pending_remunerations(
        &self,
        recipient_address: String,
    ) -> RpcResult<Vec<PendingRemunerationInfo>>;

    #[method(name = "getTab")]
    async fn get_tab(&self, tab_id: U256) -> RpcResult<Option<TabInfo>>;

    #[method(name = "listRecipientTabs")]
    async fn list_recipient_tabs(
        &self,
        recipient_address: String,
        settlement_statuses: Option<Vec<String>>,
    ) -> RpcResult<Vec<TabInfo>>;

    #[method(name = "getTabGuarantees")]
    async fn get_tab_guarantees(&self, tab_id: U256) -> RpcResult<Vec<GuaranteeInfo>>;

    #[method(name = "getLatestGuarantee")]
    async fn get_latest_guarantee(&self, tab_id: U256) -> RpcResult<Option<GuaranteeInfo>>;

    #[method(name = "getGuarantee")]
    async fn get_guarantee(&self, tab_id: U256, req_id: U256) -> RpcResult<Option<GuaranteeInfo>>;

    #[method(name = "listRecipientPayments")]
    async fn list_recipient_payments(
        &self,
        recipient_address: String,
    ) -> RpcResult<Vec<UserTransactionInfo>>;

    #[method(name = "getCollateralEventsForTab")]
    async fn get_collateral_events_for_tab(
        &self,
        tab_id: U256,
    ) -> RpcResult<Vec<CollateralEventInfo>>;

    #[method(name = "getUserAssetBalance")]
    async fn get_user_asset_balance(
        &self,
        user_address: String,
        asset_address: String,
    ) -> RpcResult<Option<AssetBalanceInfo>>;
}
