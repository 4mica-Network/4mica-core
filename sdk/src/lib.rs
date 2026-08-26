pub mod auth;
pub mod client;
pub mod config;
/// Core4Mica contract bindings.
///
/// Public so a gas-sponsoring submitter (e.g. a facilitator service) can build and send
/// `depositStablecoinWithAuthorization` / `depositStablecoinWithPermit2` against the same ABI and
/// revert decoding this crate uses, rather than redeclaring it and drifting.
pub mod contract;
/// EIP-712 digests for every authorization this SDK signs.
///
/// Public for the same reason [`contract`] is: a gas-sponsoring submitter verifies the signatures
/// it is asked to pay for, and it should check them against the same digests the signer produced
/// rather than reimplementing the type strings and drifting.
pub mod digest;
pub mod error;
mod sig;
mod validators;
pub mod x402;

pub use alloy::primitives::{Address, U256};
pub use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequestClaims, SigningScheme, ValidationRequirement,
};

pub use auth::{AuthClient, AuthSession, AuthTokens};
pub use client::model::{
    Asset, AssetBalanceInfo, AssetPosition, ClaimReceipt, DepositReceipt, PayReceipt,
    RecipientPaymentInfo, Route, StablecoinPosition, TokenRoute, WithdrawReceipt,
};
pub use client::route;
pub use client::{
    Client, account::AccountClient, deposit::DepositClient, payment::PaymentClient,
    settlement::SettlementClient, tokens::TokensClient, withdraw::WithdrawClient,
};
pub use config::{AuthConfig, ClientBuilder, Config, Credentials, CredentialsConfig, Network};
// The gasless authorizations cross a process boundary: a client signs one here, a submitter
// redeems it elsewhere. Surfaced at the crate root since both sides need the type.
pub use contract::Core4Mica::{
    Permit2Authorization, ReceiveAuthorization, WithdrawalCancelAuthorization,
    WithdrawalRequestAuthorization,
};
pub use crypto::bls::BLSCert;
pub use error::Error;
pub use sig::PaymentSignature;
pub use x402::{FlowSigner, X402Flow, X402SettledPayment, X402SignedPayment};

/// The names most integrations need, importable in one line.
pub mod prelude {
    pub use crate::{
        Address, Asset, ClaimReceipt, Client, ClientBuilder, Credentials, DepositReceipt, Error,
        Network, PayReceipt, Route, TokenRoute, U256, WithdrawReceipt,
    };
}
