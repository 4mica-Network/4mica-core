pub mod codec;
pub mod signing;
mod types;
mod validation;

pub use signing::{SolGuaranteeRequestClaimsV1, SolGuaranteeRequestClaimsV2};
pub use types::{
    GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeRequestClaimsV2Builder,
    PaymentGuaranteeRequestEssentials, PaymentGuaranteeValidationPolicyV2, SigningScheme,
};
pub use validation::{
    VALIDATION_REQUEST_BINDING_DOMAIN_V2, VALIDATION_SUBJECT_BINDING_DOMAIN_V1,
    compute_validation_request_hash, compute_validation_subject_hash,
};

/// All guarantee claim versions this build of the RPC crate supports.
/// To add VN: append N to this slice and add a corresponding enum variant.
pub const SUPPORTED_GUARANTEE_VERSIONS: &[u64] = &[GUARANTEE_CLAIMS_VERSION, 2];

/// Returns `true` if `version` is a known, supported guarantee claims version.
pub fn is_supported_guarantee_version(version: u64) -> bool {
    SUPPORTED_GUARANTEE_VERSIONS.contains(&version)
}

/// Returns `true` if the given version requires a trusted validation registry
/// (i.e. it is a validation-gated version, V2 or higher).
pub fn version_requires_validation_registry(version: u64) -> bool {
    version > GUARANTEE_CLAIMS_VERSION
}

#[cfg(test)]
mod tests;
