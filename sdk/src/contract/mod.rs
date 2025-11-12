use alloy::sol;

pub mod utils;

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
        error UnsupportedAsset(address asset);
        error InvalidAsset(address asset);
        error UnsupportedGuaranteeVersion(uint64 version);
        error InvalidGuaranteeDomain();

        // ========= Storage =========
        function remunerationGracePeriod() external view returns (uint256);
        function withdrawalGracePeriod() external view returns (uint256);
        function tabExpirationTime() external view returns (uint256);
        function synchronizationDelay() external view returns (uint256);
        function USDC() external view returns (address);
        function USDT() external view returns (address);

        /// TODO(#22): move key to registry
        function GUARANTEE_VERIFICATION_KEY() external view returns (
            bytes32 x1, bytes32 x2, bytes32 y1, bytes32 y2
        );

        // ========= Events =========
        event CollateralDeposited(address indexed user, address indexed asset, uint256 amount);
        event RecipientRemunerated(uint256 indexed tab_id, address indexed asset, uint256 amount);
        event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);
        event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);
        event WithdrawalCanceled(address indexed user, address indexed asset);
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
        event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
        event TabExpirationTimeUpdated(uint256 newExpirationTime);
        event SynchronizationDelayUpdated(uint256 newSynchronizationDelay);
        event VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32) newVerificationKey);
        event PaymentRecorded(uint256 indexed tab_id, address indexed asset, uint256 amount);

        // ========= Structs =========
        struct WithdrawalRequest {
            uint256 timestamp;
            uint256 amount;
        }

        struct PaymentStatus {
            uint256 paid;
            bool remunerated;
            address asset;
        }

        struct UserAssetInfo {
            address asset;
            uint256 collateral;
            uint256 withdrawalRequestTimestamp;
            uint256 withdrawalRequestAmount;
        }

        struct Guarantee {
            bytes32 domain;
            uint256 tab_id;
            uint256 req_id;
            address client;
            address recipient;
            uint256 amount;
            uint256 total_amount;
            address asset;
            uint64 timestamp;
            uint64 version;
        }

        struct G1Point {
            bytes32 x_a;
            bytes32 x_b;
            bytes32 y_a;
            bytes32 y_b;
        }

        struct G2Point {
            bytes32 x_c0_a;
            bytes32 x_c0_b;
            bytes32 x_c1_a;
            bytes32 x_c1_b;
            bytes32 y_c0_a;
            bytes32 y_c0_b;
            bytes32 y_c1_a;
            bytes32 y_c1_b;
        }

        // ========= Constructor =========
        /// @param manager Address of AccessManager
        /// @param verificationKey Initial BLS verification key
        /// @param usdc_ USDC token address
        /// @param usdt_ USDT token address
        constructor(address manager, (bytes32,bytes32,bytes32,bytes32) verificationKey, address usdc_, address usdt_);

        // ========= User flows =========
        function deposit() external payable;
        function depositStablecoin(address asset, uint256 amount) external;
        function requestWithdrawal(uint256 amount) external;
        function requestWithdrawal(address asset, uint256 amount) external;
        function cancelWithdrawal() external;
        function cancelWithdrawal(address asset) external;
        function finalizeWithdrawal() external;
        function finalizeWithdrawal(address asset) external;

        function payTabInERC20Token(
            uint256 tab_id,
            address asset,
            uint256 amount,
            address recipient
        ) external;

        /// Remunerate a recipient based on a signed guarantee
        function remunerate(
            bytes calldata guaranteeData,
            G2Point calldata signature
        ) external;

        // ========= Admin / Manager =========
        function setRemunerationGracePeriod(uint256 _gracePeriod) external;
        function setWithdrawalGracePeriod(uint256 _gracePeriod) external;
        function setTabExpirationTime(uint256 _expirationTime) external;
        function setSynchronizationDelay(uint256 _synchronizationDelay) external;
        function setGuaranteeVerificationKey((bytes32,bytes32,bytes32,bytes32) verificationKey) external;
        function setTimingParameters(uint256 _remunerationGracePeriod, uint256 _tabExpirationTime, uint256 _synchronizationDelay, uint256 _withdrawalGracePeriod) external;
        function configureGuaranteeVersion(uint64 version, (bytes32,bytes32,bytes32,bytes32) verificationKey, bytes32 domainSeparator, address decoder, bool enabled) external;
        function recordPayment(uint256 tab_id, address asset, uint256 amount) external;

        // ========= Views =========
        function getUserAllAssets(address userAddr)
            external
            view
            returns (UserAssetInfo[] memory);

        function getPaymentStatus(uint256 tab_id)
            external
            view
            returns (uint256 paid, bool remunerated, address asset);

        function getERC20Tokens() external view returns (address[] memory);

        function guaranteeDomainSeparator() external view returns (bytes32);
        function verifyAndDecodeGuarantee(
            bytes memory guarantee,
            G2Point memory signature
        ) external view returns (Guarantee memory);

        function collateral(address userAddr) external view returns (uint256);
        function collateral(address userAddr, address asset) external view returns (uint256);

        function getUser(address userAddr) external view returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        );
        function getUser(address userAddr, address asset) external view returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        );
    }
}

sol! {
    #[sol(rpc)]
    contract ERC20 {
        event Transfer(address indexed from, address indexed to, uint256 amount);
        event Approval(address indexed owner, address indexed spender, uint256 amount);

        constructor(string memory name_, string memory symbol_);

        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
    }
}
