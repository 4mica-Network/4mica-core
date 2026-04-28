use alloy_sol_types::sol;

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
    }

    struct SolGuaranteeRequestClaimsV2 {
        address user;
        address recipient;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64 timestamp;
        address validationRegistryAddress;
        bytes32 validationRequestHash;
        uint256 validationChainId;
        address validatorAddress;
        uint256 validatorAgentId;
        uint8 minValidationScore;
        bytes32 validationSubjectHash;
        bytes32 jobHash;
        string requiredValidationTag;
    }
}
