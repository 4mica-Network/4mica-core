use alloy_primitives::U256;
use reqwest::header::AUTHORIZATION;
use reqwest::{Client, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{
    ADMIN_API_KEY_HEADER, ApiClientError,
    common::{
        AdminApiKeyInfo, AdminApiKeySecret, AssetBalanceInfo, CollateralEventInfo,
        CreateAdminApiKeyRequest, CreatePaymentTabRequest, CreatePaymentTabResult, GuaranteeInfo,
        PendingRemunerationInfo, TabInfo, UpdateUserSuspensionRequest, UserSuspensionStatus,
        UserTransactionInfo,
    },
    core::CorePublicParameters,
    guarantee::PaymentGuaranteeRequest,
};
use crypto::bls::BLSCert;

fn serialize_tab_id(val: U256) -> String {
    format!("{:#x}", val)
}

#[derive(Debug, Clone)]
pub struct RpcProxy {
    client: Client,
    base_url: Url,
    admin_api_key: Option<String>,
    bearer_token: Option<String>,
}

impl RpcProxy {
    pub fn new(endpoint: &str) -> anyhow::Result<Self> {
        let client = Client::builder().build()?;
        let mut base_url = Url::parse(endpoint)?;
        if base_url.path().is_empty() {
            base_url.set_path("/");
        }
        Ok(Self {
            client,
            base_url,
            admin_api_key: None,
            bearer_token: None,
        })
    }

    pub fn with_admin_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.admin_api_key = Some(api_key.into());
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    fn url(&self, path: &str) -> Result<Url, ApiClientError> {
        self.base_url.join(path).map_err(ApiClientError::InvalidUrl)
    }

    fn apply_admin_header(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(key) = &self.admin_api_key {
            builder.header(ADMIN_API_KEY_HEADER, key)
        } else {
            builder
        }
    }

    fn apply_auth_header(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.bearer_token {
            builder.header(AUTHORIZATION, format!("Bearer {token}"))
        } else {
            builder
        }
    }

    fn apply_admin_and_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let builder = self.apply_admin_header(builder);
        self.apply_auth_header(builder)
    }

    async fn get<T>(&self, url: Url) -> Result<T, ApiClientError>
    where
        T: DeserializeOwned,
    {
        let builder = self.client.get(url);
        let builder = self.apply_admin_header(builder);
        let builder = self.apply_auth_header(builder);
        let response = builder.send().await?;
        Self::decode_response(response).await
    }

    async fn post<Req, Resp>(&self, url: Url, body: &Req) -> Result<Resp, ApiClientError>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        let builder = self.client.post(url).json(body);
        let builder = self.apply_admin_header(builder);
        let builder = self.apply_auth_header(builder);
        let response = builder.send().await?;
        Self::decode_response(response).await
    }

    async fn decode_response<T>(response: reqwest::Response) -> Result<T, ApiClientError>
    where
        T: DeserializeOwned,
    {
        let status = response.status();
        let bytes = response.bytes().await?;
        if status.is_success() {
            let value = serde_json::from_slice(&bytes)?;
            Ok(value)
        } else {
            let message = parse_error_message(&bytes);
            Err(ApiClientError::Api { status, message })
        }
    }

    pub async fn get_public_params(&self) -> Result<CorePublicParameters, ApiClientError> {
        let url = self.url("/core/public-params")?;
        self.get(url).await
    }

    pub async fn issue_guarantee(
        &self,
        req: PaymentGuaranteeRequest,
    ) -> Result<BLSCert, ApiClientError> {
        let url = self.url("/core/guarantees")?;
        self.post(url, &req).await
    }

    pub async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> Result<CreatePaymentTabResult, ApiClientError> {
        let url = self.url("/core/payment-tabs")?;
        self.post(url, &req).await
    }

    pub async fn list_settled_tabs(
        &self,
        recipient_address: String,
    ) -> Result<Vec<TabInfo>, ApiClientError> {
        let path = format!("/core/recipients/{recipient_address}/settled-tabs");
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn list_pending_remunerations(
        &self,
        recipient_address: String,
    ) -> Result<Vec<PendingRemunerationInfo>, ApiClientError> {
        let path = format!("/core/recipients/{recipient_address}/pending-remunerations");
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn get_tab(&self, tab_id: U256) -> Result<Option<TabInfo>, ApiClientError> {
        let path = format!("/core/tabs/{}", serialize_tab_id(tab_id));
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn list_recipient_tabs(
        &self,
        recipient_address: String,
        settlement_statuses: Option<Vec<String>>,
    ) -> Result<Vec<TabInfo>, ApiClientError> {
        let path = format!("/core/recipients/{recipient_address}/tabs");
        let mut url = self.url(&path)?;
        if let Some(statuses) = settlement_statuses {
            {
                let mut pairs = url.query_pairs_mut();
                for status in statuses {
                    pairs.append_pair("settlement_status", &status);
                }
            }
        }
        self.get(url).await
    }

    pub async fn get_tab_guarantees(
        &self,
        tab_id: U256,
    ) -> Result<Vec<GuaranteeInfo>, ApiClientError> {
        let path = format!("/core/tabs/{}/guarantees", serialize_tab_id(tab_id));
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn get_latest_guarantee(
        &self,
        tab_id: U256,
    ) -> Result<Option<GuaranteeInfo>, ApiClientError> {
        let path = format!("/core/tabs/{}/guarantees/latest", serialize_tab_id(tab_id));
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn get_guarantee(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> Result<Option<GuaranteeInfo>, ApiClientError> {
        let path = format!(
            "/core/tabs/{}/guarantees/{}",
            serialize_tab_id(tab_id),
            req_id
        );
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn list_recipient_payments(
        &self,
        recipient_address: String,
    ) -> Result<Vec<UserTransactionInfo>, ApiClientError> {
        let path = format!("/core/recipients/{recipient_address}/payments");
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn get_collateral_events_for_tab(
        &self,
        tab_id: U256,
    ) -> Result<Vec<CollateralEventInfo>, ApiClientError> {
        let path = format!("/core/tabs/{}/collateral-events", serialize_tab_id(tab_id));
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn get_user_asset_balance(
        &self,
        user_address: String,
        asset_address: String,
    ) -> Result<Option<AssetBalanceInfo>, ApiClientError> {
        let path = format!("/core/users/{user_address}/assets/{asset_address}");
        let url = self.url(&path)?;
        self.get(url).await
    }

    pub async fn update_user_suspension(
        &self,
        user_address: String,
        suspended: bool,
    ) -> Result<UserSuspensionStatus, ApiClientError> {
        let path = format!("/core/users/{user_address}/suspension");
        let url = self.url(&path)?;
        let body = UpdateUserSuspensionRequest { suspended };
        let request = self.apply_admin_and_auth(self.client.post(url).json(&body));
        let response = request.send().await?;
        Self::decode_response(response).await
    }

    pub async fn create_admin_api_key(
        &self,
        req: CreateAdminApiKeyRequest,
    ) -> Result<AdminApiKeySecret, ApiClientError> {
        let url = self.url("/core/admin/api-keys")?;
        let request = self.apply_admin_and_auth(self.client.post(url).json(&req));
        let response = request.send().await?;
        Self::decode_response(response).await
    }

    pub async fn list_admin_api_keys(&self) -> Result<Vec<AdminApiKeyInfo>, ApiClientError> {
        let url = self.url("/core/admin/api-keys")?;
        let request = self.apply_admin_and_auth(self.client.get(url));
        let response = request.send().await?;
        Self::decode_response(response).await
    }

    pub async fn revoke_admin_api_key(
        &self,
        id: String,
    ) -> Result<AdminApiKeyInfo, ApiClientError> {
        let path = format!("/core/admin/api-keys/{id}/revoke");
        let url = self.url(&path)?;
        let request = self.apply_admin_and_auth(self.client.post(url));
        let response = request.send().await?;
        Self::decode_response(response).await
    }
}

fn parse_error_message(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "unknown error".to_string();
    }

    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(msg) = value.get("error").and_then(|v| v.as_str()) {
            return msg.to_string();
        }
        if let Some(msg) = value.get("message").and_then(|v| v.as_str()) {
            return msg.to_string();
        }
    }

    match std::str::from_utf8(bytes) {
        Ok(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => "unknown error".to_string(),
    }
}
