use crate::contract::Core4Mica;
use alloy::contract as alloy_contract;
use alloy::primitives::{Address, Bytes};
use anyhow::Error;
use crypto::hex::FromHexError;
use rpc::ApiClientError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("invalid config value: {0}")]
    InvalidValue(String),
    #[error("missing config: {0}")]
    Missing(String),
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
pub enum RemunerateError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("failed to decode guarantee claims hex")]
    ClaimsHex(#[source] Error),
    #[error("failed to decode guarantee claims")]
    ClaimsDecode(#[source] Error),
    #[error("failed to convert guarantee claims into contract type")]
    GuaranteeConversion(#[source] Error),
    #[error("failed to decode signature hex")]
    SignatureHex(#[source] FromHexError),
    #[error("failed to decode BLS signature")]
    SignatureDecode(#[source] Error),
    #[error("tab not yet overdue")]
    TabNotYetOverdue,
    #[error("tab expired")]
    TabExpired,
    #[error("tab previously remunerated")]
    TabPreviouslyRemunerated,
    #[error("tab already paid")]
    TabAlreadyPaid,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("double spending detected")]
    DoubleSpendingDetected,
    #[error("invalid recipient")]
    InvalidRecipient,
    #[error("amount is zero")]
    AmountZero,
    #[error("transfer failed")]
    TransferFailed,
    #[error("certificate verification failed: {0}")]
    CertificateInvalid(#[source] Error),
    #[error("certificate signature mismatch before submission")]
    CertificateMismatch,
    #[error("guarantee domain mismatch")]
    GuaranteeDomainMismatch,
    #[error("unsupported guarantee version: {0}")]
    UnsupportedGuaranteeVersion(u64),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
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

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum ApproveErc20Error {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum PayTabError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("invalid asset")]
    InvalidAsset,

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum GetUserError {
    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum TabPaymentStatusError {
    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    #[error("provider/transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Error)]
pub enum CreateTabError {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error(transparent)]
    Rpc(#[from] ApiClientError),
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
    #[error("guarantee domain mismatch")]
    GuaranteeDomainMismatch,
    #[error("unsupported guarantee version: {0}")]
    UnsupportedGuaranteeVersion(u64),
}

fn extract_selector_and_data(e: &alloy_contract::Error) -> Option<(u32, Vec<u8>)> {
    e.as_revert_data().map(|bytes: Bytes| {
        let data = bytes.to_vec();
        let selector = if data.len() >= 4 {
            u32::from_be_bytes([data[0], data[1], data[2], data[3]])
        } else {
            0
        };
        (selector, data)
    })
}

macro_rules! impl_from_alloy_error {
    ($target:ty, { $($contract_err:pat => $target_err:expr),* $(,)? }) => {
        impl From<alloy_contract::Error> for $target {
            fn from(e: alloy_contract::Error) -> Self {
                if let Some(decoded) = e.as_decoded_interface_error::<Core4Mica::Core4MicaErrors>() {
                    return match decoded {
                        $(
                            $contract_err => $target_err,
                        )*
                        _ => match extract_selector_and_data(&e) {
                            Some((selector, data)) => Self::UnknownRevert { selector, data },
                            None => Self::Transport(e.to_string()),
                        },
                    };
                }

                match extract_selector_and_data(&e) {
                    Some((selector, data)) => Self::UnknownRevert { selector, data },
                    None => Self::Transport(e.to_string()),
                }
            }
        }
    };
    ($target:ty) => {
        impl From<alloy_contract::Error> for $target {
            fn from(e: alloy_contract::Error) -> Self {
                match extract_selector_and_data(&e) {
                    Some((selector, data)) => Self::UnknownRevert { selector, data },
                    None => Self::Transport(e.to_string()),
                }
            }
        }
    };
}

impl_from_alloy_error!(RemunerateError, {
    Core4Mica::Core4MicaErrors::TabNotYetOverdue(_) => Self::TabNotYetOverdue,
    Core4Mica::Core4MicaErrors::TabExpired(_) => Self::TabExpired,
    Core4Mica::Core4MicaErrors::TabPreviouslyRemunerated(_) => Self::TabPreviouslyRemunerated,
    Core4Mica::Core4MicaErrors::TabAlreadyPaid(_) => Self::TabAlreadyPaid,
    Core4Mica::Core4MicaErrors::InvalidSignature(_) => Self::InvalidSignature,
    Core4Mica::Core4MicaErrors::DoubleSpendingDetected(_) => Self::DoubleSpendingDetected,
    Core4Mica::Core4MicaErrors::InvalidRecipient(_) => Self::InvalidRecipient,
    Core4Mica::Core4MicaErrors::AmountZero(_) => Self::AmountZero,
    Core4Mica::Core4MicaErrors::TransferFailed(_) => Self::TransferFailed,
    Core4Mica::Core4MicaErrors::InvalidGuaranteeDomain(_) => Self::GuaranteeDomainMismatch,
    Core4Mica::Core4MicaErrors::UnsupportedGuaranteeVersion(err) => Self::UnsupportedGuaranteeVersion(err.version),
});

impl_from_alloy_error!(FinalizeWithdrawalError, {
    Core4Mica::Core4MicaErrors::NoWithdrawalRequested(_) => Self::NoWithdrawalRequested,
    Core4Mica::Core4MicaErrors::GracePeriodNotElapsed(_) => Self::GracePeriodNotElapsed,
    Core4Mica::Core4MicaErrors::TransferFailed(_) => Self::TransferFailed,
});

impl_from_alloy_error!(RequestWithdrawalError, {
    Core4Mica::Core4MicaErrors::AmountZero(_) => Self::AmountZero,
    Core4Mica::Core4MicaErrors::InsufficientAvailable(_) => Self::InsufficientAvailable,
});

impl_from_alloy_error!(CancelWithdrawalError, {
    Core4Mica::Core4MicaErrors::NoWithdrawalRequested(_) => Self::NoWithdrawalRequested,
});

impl_from_alloy_error!(DepositError, {
    Core4Mica::Core4MicaErrors::AmountZero(_) => Self::AmountZero,
});

impl_from_alloy_error!(PayTabError, {
    Core4Mica::Core4MicaErrors::InvalidAsset(_) => Self::InvalidAsset,
});

impl_from_alloy_error!(ApproveErc20Error);

impl_from_alloy_error!(GetUserError);

impl_from_alloy_error!(TabPaymentStatusError);
