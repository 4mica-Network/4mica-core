//! Domain services — one per area of behaviour.
//!
//! Nothing here imports a sibling: a service that needs shared behaviour reaches down into
//! [`shared`](super::shared) instead, and orchestration across services belongs in
//! [`app`](super::app).

pub mod auth;
pub mod clearing;
pub mod guarantee;
pub mod health;
pub mod netting;
pub mod query;
pub mod system;
pub mod validation;
