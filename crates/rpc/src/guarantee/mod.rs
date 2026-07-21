pub mod codec;
pub mod signing;
mod types;

pub use signing::{
    SolGuaranteeRequestClaimsV1, SolValidatedGuaranteeRequestClaimsV1, SolValidation,
};
pub use types::{
    GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1, SigningScheme,
    ValidationRequirement,
};

/// Guarantee claims versions this build can decode, newest last. Clients sign at
/// [`GUARANTEE_CLAIMS_VERSION`] while core accepts the whole set, so older clients keep working.
///
/// To add VN: append N here, add a [`PaymentGuaranteeRequestClaims`] variant, and teach
/// [`codec`] the new layout.
pub const SUPPORTED_GUARANTEE_VERSIONS: &[u64] = &[GUARANTEE_CLAIMS_VERSION];

pub fn is_supported_guarantee_version(version: u64) -> bool {
    SUPPORTED_GUARANTEE_VERSIONS.contains(&version)
}

#[cfg(test)]
mod tests;
