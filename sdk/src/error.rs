use crate::contract::Core4Mica;
use alloy::contract as alloy_contract;
use alloy::primitives::{Address, Bytes};
use anyhow::Error;
use reqwest::StatusCode;
use rpc::ApiClientError;
use serde_json::Value;
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid config value: {0}")]
    InvalidValue(String),
    #[error("missing config: {0}")]
    Missing(String),
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid auth URL: {0}")]
    InvalidUrl(#[from] ParseError),
    #[error("auth request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("failed to decode auth response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("auth server returned {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("auth config is missing")]
    MissingConfig,
    #[error("refresh token not available")]
    MissingRefreshToken,
    #[error("auth state error: {0}")]
    Internal(String),
}

impl From<AuthError> for ApiClientError {
    fn from(val: AuthError) -> Self {
        let status = match &val {
            AuthError::Api { status, .. } => *status,
            AuthError::InvalidUrl(_) | AuthError::MissingConfig => StatusCode::BAD_REQUEST,
            AuthError::MissingRefreshToken => StatusCode::UNAUTHORIZED,
            AuthError::Transport(_) => StatusCode::SERVICE_UNAVAILABLE,
            AuthError::Decode(_) => StatusCode::BAD_GATEWAY,
            AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Signing(_) => StatusCode::UNAUTHORIZED,
        };

        match val {
            AuthError::InvalidUrl(err) => ApiClientError::InvalidUrl(err),
            AuthError::Transport(err) => ApiClientError::Transport(err),
            AuthError::Decode(err) => ApiClientError::Decode(err),
            AuthError::Api { status, message } => ApiClientError::Api { status, message },
            other => ApiClientError::Api {
                status,
                message: other.to_string(),
            },
        }
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("client RPC error: {0}")]
    Rpc(String),

    #[error("client provider error: {0}")]
    Provider(String),

    #[error("client initialization error: {0}")]
    Initialization(String),
}

#[derive(Debug, Error)]
pub enum SignPaymentError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("address mismatch: signer={signer:?} != claims.user_address={claims}")]
    AddressMismatch { signer: Address, claims: String },
    #[error("invalid user address in claims")]
    InvalidUserAddress,
    #[error("invalid recipient address in claims")]
    InvalidRecipientAddress,
    #[error("failed to sign the payment: {0}")]
    Failed(String),

    #[error(transparent)]
    Rpc(#[from] ApiClientError),
}

#[derive(Debug, Error)]
pub enum FinalizeWithdrawalError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("no withdrawal requested")]
    NoWithdrawalRequested,
    #[error("grace period not elapsed")]
    GracePeriodNotElapsed,
    #[error("transfer failed")]
    TransferFailed,
    #[error("unsupported asset: {0}")]
    UnsupportedAsset(Address),
    #[error("stablecoin withdraw shortfall for {asset}: requested {requested}, actual {actual}")]
    StablecoinWithdrawShortfall {
        asset: Address,
        requested: String,
        actual: String,
    },

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum RequestWithdrawalError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("amount is zero")]
    AmountZero,
    #[error("insufficient available")]
    InsufficientAvailable,
    #[error("unsupported asset: {0}")]
    UnsupportedAsset(Address),

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum CancelWithdrawalError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("no withdrawal requested")]
    NoWithdrawalRequested,

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum DepositError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("amount is zero")]
    AmountZero,
    #[error("unsupported asset: {0}")]
    UnsupportedAsset(Address),
    #[error("Aave is not configured")]
    AaveNotConfigured,

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum ApproveErc20Error {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum ClearingSettlementError {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error(transparent)]
    Rpc(#[from] ApiClientError),

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum GetUserError {
    #[error("unsupported asset: {0}")]
    UnsupportedAsset(Address),
    #[error("Aave is not configured")]
    AaveNotConfigured,
    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum IssuePaymentGuaranteeError {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error(transparent)]
    Rpc(#[from] ApiClientError),
}

#[derive(Debug, Error)]
pub enum RecipientQueryError {
    #[error(transparent)]
    Rpc(#[from] ApiClientError),
}

#[derive(Debug, Error)]
pub enum VerifyGuaranteeError {
    #[error("invalid BLS certificate")]
    InvalidCertificate(#[source] Error),
    #[error("certificate signature mismatch")]
    CertificateMismatch,
    #[error("guarantee version mismatch: expected {expected}, got {actual}")]
    GuaranteeVersionMismatch { expected: u64, actual: u64 },
    #[error("guarantee domain mismatch")]
    GuaranteeDomainMismatch,
    #[error("unsupported guarantee version: {0}")]
    UnsupportedGuaranteeVersion(u64),
}

#[derive(Debug, Error)]
pub enum X402Error {
    #[error("invalid scheme: {0}")]
    InvalidScheme(String),
    #[error("invalid x402 version: {0}")]
    InvalidVersion(String),
    #[error("invalid facilitator url: {0}")]
    InvalidFacilitatorUrl(String),
    #[error("failed to encode payment envelope: {0}")]
    EncodeEnvelope(String),
    #[error("invalid paymentRequirements.extra: {0}")]
    InvalidExtra(String),
    #[error("invalid number for field {field}: {source}")]
    InvalidNumber { field: String, source: Error },
    #[error("settlement failed with status {status}: {body}")]
    SettlementFailed { status: StatusCode, body: Value },
    #[error(transparent)]
    Signing(#[from] SignPaymentError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// Minimal context for a revert we could decode from the contract call.
#[derive(Debug, Clone)]
struct RevertDetails {
    selector: u32,
    data: Vec<u8>,
}

impl RevertDetails {
    fn from_error(e: &alloy_contract::Error) -> Option<Self> {
        e.as_revert_data().map(|bytes: Bytes| {
            let data = bytes.to_vec();
            let selector = if data.len() >= 4 {
                u32::from_be_bytes([data[0], data[1], data[2], data[3]])
            } else {
                0
            };
            Self { selector, data }
        })
    }
}

trait ContractErrorTarget {
    fn from_unknown_revert(revert: RevertDetails) -> Self;
    fn from_transport(err: alloy_contract::Error) -> Self;
}

fn map_contract_error<T, F>(error: alloy_contract::Error, map_decoded: F) -> T
where
    T: ContractErrorTarget,
    F: FnOnce(Core4Mica::Core4MicaErrors) -> Option<T>,
{
    if let Some(decoded) = error.as_decoded_interface_error::<Core4Mica::Core4MicaErrors>()
        && let Some(mapped) = map_decoded(decoded)
    {
        return mapped;
    }

    if let Some(revert) = RevertDetails::from_error(&error) {
        return T::from_unknown_revert(revert);
    }

    T::from_transport(error)
}

macro_rules! impl_from_alloy_error {
    ($target:ty, { $($contract_err:pat => $target_err:expr),* $(,)? }) => {
        impl From<alloy_contract::Error> for $target {
            fn from(e: alloy_contract::Error) -> Self {
                map_contract_error(e, |decoded| match decoded {
                    $(
                        $contract_err => Some($target_err),
                    )*
                    _ => None,
                })
            }
        }
    };
    ($target:ty) => {
        impl From<alloy_contract::Error> for $target {
            fn from(e: alloy_contract::Error) -> Self {
                map_contract_error(e, |_| None)
            }
        }
    };
}

macro_rules! impl_contract_error_target {
    ($target:ty) => {
        impl ContractErrorTarget for $target {
            fn from_unknown_revert(revert: RevertDetails) -> Self {
                Self::UnknownRevert {
                    selector: revert.selector,
                    data: revert.data,
                }
            }

            fn from_transport(err: alloy_contract::Error) -> Self {
                Self::Transport(err.to_string())
            }
        }
    };
}

impl_contract_error_target!(FinalizeWithdrawalError);
impl_contract_error_target!(RequestWithdrawalError);
impl_contract_error_target!(CancelWithdrawalError);
impl_contract_error_target!(DepositError);
impl_contract_error_target!(ApproveErc20Error);
impl_contract_error_target!(ClearingSettlementError);
impl_contract_error_target!(GetUserError);

impl_from_alloy_error!(FinalizeWithdrawalError, {
    Core4Mica::Core4MicaErrors::NoWithdrawalRequested(_) => Self::NoWithdrawalRequested,
    Core4Mica::Core4MicaErrors::GracePeriodNotElapsed(_) => Self::GracePeriodNotElapsed,
    Core4Mica::Core4MicaErrors::TransferFailed(_) => Self::TransferFailed,
    Core4Mica::Core4MicaErrors::UnsupportedAsset(err) => Self::UnsupportedAsset(err.asset),
    Core4Mica::Core4MicaErrors::StablecoinWithdrawShortfall(err) => Self::StablecoinWithdrawShortfall {
        asset: err.asset,
        requested: err.requested.to_string(),
        actual: err.actual.to_string(),
    },
});

impl_from_alloy_error!(RequestWithdrawalError, {
    Core4Mica::Core4MicaErrors::AmountZero(_) => Self::AmountZero,
    Core4Mica::Core4MicaErrors::InsufficientAvailable(_) => Self::InsufficientAvailable,
    Core4Mica::Core4MicaErrors::UnsupportedAsset(err) => Self::UnsupportedAsset(err.asset),
});

impl_from_alloy_error!(CancelWithdrawalError, {
    Core4Mica::Core4MicaErrors::NoWithdrawalRequested(_) => Self::NoWithdrawalRequested,
});

impl_from_alloy_error!(DepositError, {
    Core4Mica::Core4MicaErrors::AmountZero(_) => Self::AmountZero,
    Core4Mica::Core4MicaErrors::UnsupportedAsset(err) => Self::UnsupportedAsset(err.asset),
    Core4Mica::Core4MicaErrors::AaveNotConfigured(_) => Self::AaveNotConfigured,
});

impl_from_alloy_error!(ClearingSettlementError);

impl_from_alloy_error!(ApproveErc20Error);

impl_from_alloy_error!(GetUserError, {
    Core4Mica::Core4MicaErrors::UnsupportedAsset(err) => Self::UnsupportedAsset(err.asset),
    Core4Mica::Core4MicaErrors::AaveNotConfigured(_) => Self::AaveNotConfigured,
});
