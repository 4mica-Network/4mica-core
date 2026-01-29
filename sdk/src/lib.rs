pub mod auth;
pub mod client;
pub mod config;
mod contract;
mod digest;
pub mod error;
mod sig;
mod validators;
pub mod x402;

pub use alloy::primitives::{Address, U256};
pub use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequestClaimsV1 as PaymentGuaranteeRequestClaims,
    SigningScheme,
};

pub use crate::error::RecipientQueryError;
pub use auth::{AuthClient, AuthSession, AuthTokens};
pub use client::Client;
pub use client::model::{
    AssetBalanceInfo, CollateralEventInfo, GuaranteeInfo, PendingRemunerationInfo,
    RecipientPaymentInfo, TabInfo, TabPaymentStatus, UserInfo,
};
pub use config::AuthConfig;
pub use config::{Config, ConfigBuilder};
pub use crypto::bls::BLSCert;
pub use sig::PaymentSignature;
pub use x402::X402Flow;
pub use x402::{FlowSigner, X402SettledPayment, X402SignedPayment};
// Backwards compatibility with earlier facilitator naming.
pub use x402::X402Flow as FacilitatorFlow;
