use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthNonceRequest {
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct AuthNonceResponse {
    pub nonce: String,
    pub siwe: SiweTemplate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiweTemplate {
    pub domain: String,
    pub uri: String,
    pub chain_id: u64,
    pub statement: String,
    pub expiration: String,
    pub issued_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthVerifyRequest {
    pub address: String,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct AuthVerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthLogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthLogoutResponse {
    pub revoked: bool,
}
