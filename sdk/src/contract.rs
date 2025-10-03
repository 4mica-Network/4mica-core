use alloy::sol;

sol! {
    #[sol(rpc)]
    contract Core4Mica {
        // ========= Errors =========
        error AmountZero();
        error InsufficientAvailable();
        error TransferFailed();
        error GracePeriodNotElapsed();
        error NoWithdrawalRequested();
        error DirectTransferNotAllowed();
        error DoubleSpendingDetected();
        error TabNotYetOverdue();
        error TabExpired();
        error TabPreviouslyRemunerated();
        error TabAlreadyPaid();
        error InvalidSignature();
        error InvalidRecipient();
        error IllegalValue();

        // ========= Storage =========
        function remunerationGracePeriod() external view returns (uint256);
        function withdrawalGracePeriod() external view returns (uint256);
        function tabExpirationTime() external view returns (uint256);
        function synchronizationDelay() external view returns (uint256);

        /// TODO(#22): move key to registry
        function GUARANTEE_VERIFICATION_KEY() external view returns (
            bytes32 x1, bytes32 x2, bytes32 y1, bytes32 y2
        );

        // ========= Events =========
        event CollateralDeposited(address indexed user, uint256 amount);
        event RecipientRemunerated(uint256 indexed tab_id, uint256 amount);
        event CollateralWithdrawn(address indexed user, uint256 amount);
        event WithdrawalRequested(address indexed user, uint256 when, uint256 amount);
        event WithdrawalCanceled(address indexed user);
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
        event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
        event TabExpirationTimeUpdated(uint256 newExpirationTime);
        event SynchronizationDelayUpdated(uint256 newSynchronizationDelay);
        event VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32) newVerificationKey);

        // ========= Structs =========
        struct WithdrawalRequest {
            uint256 timestamp;
            uint256 amount;
        }

        struct PaymentStatus {
            uint256 paid;
            bool remunerated;
        }

        struct Guarantee {
            uint256 tab_id;
            uint256 tab_timestamp;
            address client;
            address recipient;
            uint256 req_id;
            uint256 amount;
        }

        // ========= Constructor =========
        /// @param manager Address of AccessManager
        /// @param verificationKey Initial BLS verification key
        constructor(address manager, (bytes32,bytes32,bytes32,bytes32) verificationKey);

        // ========= User flows =========
        function deposit() external payable;
        function requestWithdrawal(uint256 amount) external;
        function cancelWithdrawal() external;
        function finalizeWithdrawal() external;

        /// Remunerate a recipient based on a signed guarantee
        function remunerate(
            Guarantee calldata g,
            (bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) signature
        ) external;

        // ========= Admin / Manager =========
        function setRemunerationGracePeriod(uint256 _gracePeriod) external;
        function setWithdrawalGracePeriod(uint256 _gracePeriod) external;
        function setTabExpirationTime(uint256 _expirationTime) external;
        function setSynchronizationDelay(uint256 _synchronizationDelay) external;
        function setGuaranteeVerificationKey((bytes32,bytes32,bytes32,bytes32) verificationKey) external;
        function recordPayment(uint256 tab_id, uint256 amount) external;

        // ========= Views =========
        function getUser(address userAddr)
            external
            view
            returns (
                uint256 _collateral,
                uint256 withdrawal_request_timestamp,
                uint256 withdrawal_request_amount
            );

        function getPaymentStatus(uint256 tab_id)
            external
            view
            returns (uint256 paid, bool remunerated);

        function encodeGuarantee(Guarantee memory g) external pure returns (bytes memory);
        function verifyGuaranteeSignature(
            Guarantee memory g,
            (bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) signature
        ) external view returns (bool);
    }
}
