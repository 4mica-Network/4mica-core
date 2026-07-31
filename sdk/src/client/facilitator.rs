//! Transport for the service that submits signed authorizations and pays the gas for them.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::DepositError;

pub(super) struct Facilitator {
    http: reqwest::Client,
    /// `None` when none was configured; every call then fails with
    /// [`DepositError::FacilitatorNotConfigured`] rather than silently doing nothing.
    base_url: Option<Url>,
}

impl Clone for Facilitator {
    fn clone(&self) -> Self {
        Self {
            http: self.http.clone(),
            base_url: self.base_url.clone(),
        }
    }
}

impl Facilitator {
    pub(super) fn new(base_url: Option<Url>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
        }
    }

    pub(super) fn is_configured(&self) -> bool {
        self.base_url.is_some()
    }

    pub(super) async fn post<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp, DepositError>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let url = self.endpoint(path)?;
        let response =
            self.http.post(url).json(body).send().await.map_err(|err| {
                DepositError::Transport(format!("facilitator request failed: {err}"))
            })?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|err| {
            DepositError::Transport(format!("failed to read facilitator response: {err}"))
        })?;

        // Rejections are reported in the body with a 200, so a non-success status is a transport or
        // routing problem rather than a refused request.
        if !status.is_success() {
            return Err(DepositError::Transport(format!(
                "facilitator returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }

        serde_json::from_slice(&bytes).map_err(|err| {
            DepositError::Transport(format!("malformed facilitator response: {err}"))
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, DepositError> {
        let base = self
            .base_url
            .as_ref()
            .ok_or(DepositError::FacilitatorNotConfigured)?;
        base.join(path).map_err(|err| {
            DepositError::InvalidParams(format!("invalid facilitator URL for {path}: {err}"))
        })
    }
}

/// Failure detail shared by every facilitator response, whatever it was asked to do.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FacilitatorFailure {
    permit2_allowance: Option<Permit2AllowanceResponse>,
    error_code: Option<String>,
    retryable: Option<bool>,
}

impl FacilitatorFailure {
    pub(super) fn into_error(self, message: Option<String>) -> DepositError {
        let eip2612_nonce = self
            .permit2_allowance
            .and_then(|allowance| allowance.eip2612_nonce)
            .and_then(|raw| raw.parse().ok());
        DepositError::from_facilitator(
            self.error_code,
            message,
            // Absent means "not retryable": a facilitator that omits it is not promising anything.
            self.retryable.unwrap_or(false),
            eip2612_nonce,
        )
    }
}

/// Detail attached to `PERMIT2_ALLOWANCE_REQUIRED`, carrying the one value a client with no chain
/// access cannot compute: the owner's current EIP-2612 nonce.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Permit2AllowanceResponse {
    eip2612_nonce: Option<String>,
}
