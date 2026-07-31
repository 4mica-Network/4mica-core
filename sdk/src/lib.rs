pub mod auth;
pub mod client;
pub mod config;
/// Core4Mica contract bindings.
///
/// Public so a gas-sponsoring submitter (e.g. a facilitator service) can build and send
/// `depositStablecoinWithAuthorization` / `depositStablecoinWithPermit2` against the same ABI and
/// revert decoding this crate uses, rather than redeclaring it and drifting.
pub mod contract;
mod digest;
pub mod error;
mod sig;
mod validators;
pub mod x402;

pub use alloy::primitives::{Address, U256};
pub use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequestClaims, SigningScheme, ValidationRequirement,
};

pub use crate::error::RecipientQueryError;
pub use auth::{AuthClient, AuthSession, AuthTokens};
pub use client::Client;
pub use client::model::{
    Asset, AssetBalanceInfo, DepositPath, DepositReceipt, RecipientPaymentInfo, StablecoinPosition,
    UserInfo,
};
pub use client::{
    account::AccountClient, deposit::DepositClient, payment::PaymentClient,
    settlement::SettlementClient, withdraw::WithdrawClient,
};
pub use config::AuthConfig;
pub use config::{Config, ConfigBuilder};
// The gasless-deposit authorizations cross a process boundary: a client signs one here, a
// submitter redeems it elsewhere. Surfaced at the crate root since both sides need the type.
pub use contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization};
pub use crypto::bls::BLSCert;
pub use sig::PaymentSignature;
pub use x402::X402Flow;
/// Alternative name for [`X402Flow`].
pub use x402::X402Flow as FacilitatorFlow;
pub use x402::{FlowSigner, X402SettledPayment, X402SignedPayment};
