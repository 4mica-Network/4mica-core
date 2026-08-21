use crate::contract::Core4Mica;
use alloy::contract as alloy_contract;
use alloy::primitives::{Address, B256, Bytes, U256};
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

    /// No Ethereum endpoint is available, so anything that reads chain state or sends a transaction
    /// is out of reach. Sponsored deposits and withdrawals are unaffected — they never touch the
    /// chain — so this is only ever raised by the paths that do.
    #[error(
        "no Ethereum RPC endpoint is available; set 4MICA_ETHEREUM_HTTP_RPC_URL or \
         ConfigBuilder::ethereum_http_rpc_url"
    )]
    ChainRpcUnavailable,

    /// Core publishes no EIP-712 domain separator for this token — it is either absent from the
    /// supported-token list or listed without one — so no EIP-3009 or EIP-2612 digest can be
    /// built for it. Scheme-scoped, not fatal: Permit2 and self-funded routes need no token
    /// domain and remain available, which is why the composite routes treat this as "try the
    /// next scheme" rather than an error.
    #[error(
        "no EIP-712 domain separator is published for {token}; the token is either unsupported \
         or does not implement EIP-3009"
    )]
    MissingTokenDomainSeparator { token: Address },
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

/// A sponsored action the facilitator declined, or could not be asked to perform at all.
///
/// Shared by every gasless route: the rejection envelope is the same whatever is being sponsored,
/// so a caller branches on `code` identically no matter which client produced the error.
#[derive(Debug, Error)]
pub enum SponsorshipError {
    /// No facilitator URL was configured, so there is nobody to pay the gas. Every client falls
    /// back to the caller's own transaction on this, rather than surfacing it.
    #[error(
        "no facilitator configured; set 4MICA_FACILITATOR_URL or ConfigBuilder::facilitator_url"
    )]
    NotConfigured,
    /// The facilitator refused. `code` is carried verbatim so a caller can still branch on a code
    /// this SDK predates.
    #[error("facilitator rejected the request ({code}): {message}")]
    Rejected {
        code: String,
        message: String,
        /// Whether retrying the identical request may succeed.
        retryable: bool,
    },
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// The facilitator never received the request, so it cannot have acted on it.
    #[error("provider/transport error: {0}")]
    Transport(String),
    /// The request reached the facilitator but no usable answer came back, so whether it submitted a
    /// transaction is unknown.
    #[error("facilitator outcome unknown: {0}")]
    OutcomeUnknown(String),
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
    Sponsorship(#[from] SponsorshipError),

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
    Sponsorship(#[from] SponsorshipError),

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
    Sponsorship(#[from] SponsorshipError),

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
    /// The token delivered less than `amount` — typically a fee-on-transfer token. The
    /// authorization is unusable as signed; re-sign for the amount that will actually arrive.
    #[error("asset transfer delivered {actual} but {expected} was expected")]
    ValueMismatch { expected: String, actual: String },
    /// `amount` was too small to mint any scaled collateral. Permanently unusable — a submitter
    /// should drop the authorization rather than retry it.
    #[error("deposit of {amount} in {asset} credits zero collateral")]
    ZeroCollateralCredit { asset: Address, amount: String },
    /// The authorization's `validBefore`/`deadline` has already elapsed. Detected client-side,
    /// before any gas is spent.
    #[error("authorization expired at {expires_at} (now {now})")]
    AuthorizationExpired { expires_at: u64, now: u64 },

    /// Permit2 needs a one-time on-chain `approve(PERMIT2, ...)` that the payer has not made.
    ///
    /// Actionable in two ways. When `eip2612_nonce` is present the token supports EIP-2612, so the
    /// approval can be *signed* rather than transacted — see
    /// [`DepositClient::send_sponsored_permit2`](crate::DepositClient::send_sponsored_permit2),
    /// which does exactly that. When it is absent the payer must send `approve(PERMIT2, ...)`
    /// themselves and pay for it.
    #[error("permit2 requires a prior approve(PERMIT2, ...): {message}")]
    Permit2AllowanceRequired {
        message: String,
        /// The owner's current EIP-2612 nonce. The one input a client with no chain access cannot
        /// derive for itself.
        eip2612_nonce: Option<U256>,
    },
    /// Every gasless route was refused, and the self-funded fallback would revert too: it pulls
    /// the funds via `transferFrom`, which needs an ERC-20 allowance the gasless routes never
    /// did. Checked before falling back, so the caller is told what to fix rather than handed an
    /// opaque revert from inside the token.
    ///
    /// Grant the allowance with [`DepositClient::approve_erc20`](crate::DepositClient::approve_erc20)
    /// and retry — or approve Permit2 once to restore the gasless route.
    #[error(
        "no gasless route is available and the self-funded fallback needs an allowance: {needed} \
         of {token} required but only {allowance} approved to {spender}; call approve_erc20 first"
    )]
    Erc20AllowanceRequired {
        token: Address,
        spender: Address,
        allowance: U256,
        needed: U256,
    },
    /// No facilitator URL was configured, so gasless deposits are unavailable. Deposit with
    /// [`DepositPath::SelfFunded`](crate::DepositPath::SelfFunded) instead.
    #[error(
        "no facilitator configured; set 4MICA_FACILITATOR_URL or ConfigBuilder::facilitator_url"
    )]
    FacilitatorNotConfigured,
    /// A rejection the facilitator reported that has no dedicated variant here — including codes
    /// added after this SDK was built, which is why `code` is carried verbatim.
    #[error("facilitator rejected the deposit ({code}): {message}")]
    Facilitator {
        code: String,
        message: String,
        /// Whether retrying the identical request may succeed.
        retryable: bool,
    },

    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("unknown revert (selector {selector:#x})")]
    UnknownRevert { selector: u32, data: Vec<u8> },
    /// The facilitator never received the deposit, so it cannot have acted on it.
    #[error("provider/transport error: {0}")]
    Transport(String),
    /// The facilitator was asked but gave no usable answer, so whether it submitted a transaction
    /// is unknown. Read the payer's balance before resending — a second authorization is a second
    /// deposit, not a retry.
    #[error("facilitator outcome unknown: {0}")]
    OutcomeUnknown(String),
}

/// Deposits predate the shared sponsorship type and keep their own richer variants, so transport
/// failures are folded into those rather than carried as a nested error.
impl From<SponsorshipError> for DepositError {
    fn from(err: SponsorshipError) -> Self {
        match err {
            SponsorshipError::NotConfigured => Self::FacilitatorNotConfigured,
            SponsorshipError::InvalidParams(message) => Self::InvalidParams(message),
            SponsorshipError::Transport(message) => Self::Transport(message),
            SponsorshipError::OutcomeUnknown(message) => Self::OutcomeUnknown(message),
            SponsorshipError::Rejected {
                code,
                message,
                retryable,
            } => Self::from_facilitator(Some(code), Some(message), retryable, None),
        }
    }
}

impl DepositError {
    /// Maps a facilitator `errorCode` onto a typed variant where one exists.
    ///
    /// Unrecognised codes fall through to [`Self::Facilitator`] carrying the raw code rather than
    /// being flattened into a string, so a client can still branch on a code this SDK predates.
    pub(crate) fn from_facilitator(
        code: Option<String>,
        message: Option<String>,
        retryable: bool,
        eip2612_nonce: Option<U256>,
    ) -> Self {
        let code = code.unwrap_or_else(|| "UNKNOWN".into());
        let message = message.unwrap_or_else(|| "facilitator gave no reason".into());

        match code.as_str() {
            "PERMIT2_ALLOWANCE_REQUIRED" => Self::Permit2AllowanceRequired {
                message,
                eip2612_nonce,
            },
            "NO_RELAYER_CONFIGURED" | "NO_RELAYER" => Self::FacilitatorNotConfigured,
            "UNSUPPORTED_ASSET" => Self::InvalidParams(message),
            _ => Self::Facilitator {
                code,
                message,
                retryable,
            },
        }
    }

    /// Whether a rejection means "this token cannot take an EIP-3009 authorization" rather than "this
    /// deposit is bad".
    ///
    /// A token without `receiveWithAuthorization` reverts opaquely from inside Core4Mica, which the
    /// facilitator reports as a failed simulation — indistinguishable, from here, from any other
    /// revert. Retrying over Permit2 is therefore a guess, but a cheap one: the simulation spent no
    /// gas, and a genuinely bad deposit fails again on the second route with its own error.
    ///
    /// A token with no published domain separator refuses earlier still — the EIP-3009 digest
    /// cannot even be built — and that is no reason to give up: Permit2's domain derives from the
    /// chain id, so its route stays open.
    pub(crate) fn refuses_the_authorization(&self) -> bool {
        matches!(
            self,
            DepositError::Facilitator { code, .. }
                if code == "SIMULATION_REVERTED" || code == "UNSUPPORTED_TRANSFER_METHOD"
        ) || matches!(
            self,
            DepositError::Client(ClientError::MissingTokenDomainSeparator { .. })
        )
    }
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

    #[error(transparent)]
    Sponsorship(#[from] SponsorshipError),

    /// Permit2 needs a one-time on-chain `approve(PERMIT2, ...)` that the debtor has not made.
    ///
    /// Actionable in two ways. When `eip2612_nonce` is present the token supports EIP-2612, so the
    /// approval can be *signed* rather than transacted — see
    /// [`SettlementClient::pay_net_debit_sponsored_permit2`](crate::SettlementClient::pay_net_debit_sponsored_permit2),
    /// which does exactly that. When it is absent the debtor must send `approve(PERMIT2, ...)`
    /// themselves and pay for it.
    #[error("permit2 requires a prior approve(PERMIT2, ...): {message}")]
    Permit2AllowanceRequired {
        message: String,
        /// The debtor's current EIP-2612 nonce. The one input a client with no chain access cannot
        /// derive for itself.
        eip2612_nonce: Option<U256>,
    },

    /// Every gasless route was refused, and the self-funded fallback would revert too: paying
    /// self-funded pulls the debit via `transferFrom`, which needs an ERC-20 allowance the
    /// gasless routes never did. Checked before falling back, so the caller is told what to fix
    /// rather than handed an opaque revert from inside the token.
    ///
    /// Grant the allowance with [`SettlementClient::approve_erc20`](crate::SettlementClient::approve_erc20)
    /// and retry — or approve Permit2 once to restore the gasless route.
    #[error(
        "no gasless route is available and the self-funded fallback needs an allowance: {needed} \
         of {token} required but only {allowance} approved to {spender}; call approve_erc20 first"
    )]
    Erc20AllowanceRequired {
        token: Address,
        spender: Address,
        allowance: U256,
        needed: U256,
    },

    /// Mined and reverted, so gas *was* spent — as opposed to a refusal before broadcasting.
    #[error("claim {tx_hash} reverted on-chain")]
    RevertedOnChain { tx_hash: B256 },

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
    #[error(transparent)]
    Client(#[from] ClientError),
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
    Core4Mica::Core4MicaErrors::ValueMismatch(err) => Self::ValueMismatch {
        expected: err.expected.to_string(),
        actual: err.actual.to_string(),
    },
    Core4Mica::Core4MicaErrors::ZeroCollateralCredit(err) => Self::ZeroCollateralCredit {
        asset: err.asset,
        amount: err.amount.to_string(),
    },
});

impl_from_alloy_error!(ClearingSettlementError);

impl_from_alloy_error!(ApproveErc20Error);

impl_from_alloy_error!(GetUserError, {
    Core4Mica::Core4MicaErrors::UnsupportedAsset(err) => Self::UnsupportedAsset(err.asset),
    Core4Mica::Core4MicaErrors::AaveNotConfigured(_) => Self::AaveNotConfigured,
});
