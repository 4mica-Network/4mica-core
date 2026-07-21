use alloy_sol_types::sol;

sol! {
    /// EIP-712 payload for a guarantee request with no validation requirement.
    /// Renaming this struct changes the EIP-712 type hash and invalidates existing signatures.
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
    }

    struct SolValidation {
        string validator;
        bytes32 subject;
        uint64 deadline;
        bytes params;
    }

    /// EIP-712 payload for a validation-gated guarantee request. Its type hash differs from
    /// [`SolGuaranteeRequestClaimsV1`], so the two can never be replayed as one another.
    struct SolValidatedGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
        SolValidation validation;
    }
}
