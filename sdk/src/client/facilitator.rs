//! Transport for the service that submits signed authorizations and pays the gas for them.

use alloy::primitives::U256;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{DepositError, SponsorshipError};

pub(super) struct Facilitator {
    http: reqwest::Client,
    /// `None` when none was configured; every call then fails with
    /// [`SponsorshipError::NotConfigured`] rather than silently doing nothing.
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

    pub(super) async fn post<Req, Resp>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, SponsorshipError>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let url = self.endpoint(path)?;
        let response = self.http.post(url).json(body).send().await.map_err(|err| {
            let message = format!("facilitator request failed: {err}");
            if err.is_connect() || err.is_builder() {
                SponsorshipError::Transport(message)
            } else {
                SponsorshipError::OutcomeUnknown(message)
            }
        })?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|err| {
            SponsorshipError::OutcomeUnknown(format!("failed to read facilitator response: {err}"))
        })?;

        // Rejections are reported in the body with a 200, so a non-success status is a transport or
        // routing problem rather than a refused request.
        if !status.is_success() {
            let message = format!(
                "facilitator returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
            return Err(
                if status.is_client_error() && status != StatusCode::REQUEST_TIMEOUT {
                    SponsorshipError::Transport(message)
                } else {
                    SponsorshipError::OutcomeUnknown(message)
                },
            );
        }

        serde_json::from_slice(&bytes).map_err(|err| {
            SponsorshipError::OutcomeUnknown(format!("malformed facilitator response: {err}"))
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, SponsorshipError> {
        let base = self
            .base_url
            .as_ref()
            .ok_or(SponsorshipError::NotConfigured)?;
        base.join(path).map_err(|err| {
            SponsorshipError::InvalidParams(format!("invalid facilitator URL for {path}: {err}"))
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
    /// The EIP-2612 nonce attached to a `PERMIT2_ALLOWANCE_REQUIRED` rejection, for callers that
    /// unpack the allowance detail themselves rather than through [`Self::into_error`].
    pub(super) fn eip2612_nonce(&self) -> Option<U256> {
        self.permit2_allowance
            .as_ref()
            .and_then(|allowance| allowance.eip2612_nonce.as_ref())
            .and_then(|raw| raw.parse().ok())
    }

    /// The generic rejection, for sponsored actions with no scheme-specific detail to unpack.
    pub(super) fn into_sponsorship_error(self, message: Option<String>) -> SponsorshipError {
        SponsorshipError::Rejected {
            code: self.error_code.unwrap_or_else(|| "UNKNOWN".into()),
            message: message.unwrap_or_else(|| "facilitator gave no reason".into()),
            // Absent means "not retryable": a facilitator that omits it is not promising anything.
            retryable: self.retryable.unwrap_or(false),
        }
    }

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
