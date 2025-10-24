use reqwest::StatusCode;
use thiserror::Error;
use url::ParseError;

#[derive(Debug, Error)]
pub enum ApiClientError {
    #[error("invalid base URL: {0}")]
    InvalidUrl(#[from] ParseError),

    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("failed to decode response body: {0}")]
    Decode(#[from] serde_json::Error),

    #[error("server returned {status}: {message}")]
    Api { status: StatusCode, message: String },
}

impl ApiClientError {
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_returns_some_for_api_errors() {
        let err = ApiClientError::Api {
            status: StatusCode::BAD_REQUEST,
            message: "oops".into(),
        };
        assert_eq!(err.status(), Some(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn status_returns_none_for_other_variants() {
        let decode_err: ApiClientError = serde_json::from_str::<serde_json::Value>("not-json")
            .unwrap_err()
            .into();
        assert!(matches!(decode_err, ApiClientError::Decode(_)));
        assert_eq!(decode_err.status(), None);
    }
}
