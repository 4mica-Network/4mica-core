pub mod codec;
mod types;
mod validation;

pub use types::{
    GUARANTEE_CLAIMS_VERSION, GUARANTEE_CLAIMS_VERSION_V2, PaymentGuaranteeClaims,
    PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeRequestClaimsV2Builder,
    PaymentGuaranteeRequestEssentials, PaymentGuaranteeValidationPolicyV2, SigningScheme,
};
pub use validation::{
    VALIDATION_REQUEST_BINDING_DOMAIN_V1, VALIDATION_SUBJECT_BINDING_DOMAIN_V1,
    compute_validation_request_hash, compute_validation_subject_hash,
};

/// All guarantee claim versions this build of the RPC crate supports.
/// Add new version constants here when introducing VN.
pub const SUPPORTED_GUARANTEE_VERSIONS: &[u64] =
    &[GUARANTEE_CLAIMS_VERSION, GUARANTEE_CLAIMS_VERSION_V2];

/// Returns `true` if `version` is a known, supported guarantee claims version.
pub fn is_supported_guarantee_version(version: u64) -> bool {
    SUPPORTED_GUARANTEE_VERSIONS.contains(&version)
}

#[cfg(test)]
mod tests;
