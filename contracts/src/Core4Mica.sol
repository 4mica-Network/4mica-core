// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
contract Core4Mica is AccessManaged, ReentrancyGuard {
    using SafeERC20 for IERC20;

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

    // ========= Storage =========
    uint256 public remunerationGracePeriod = 14 days;
    uint256 public withdrawalGracePeriod = 22 days;
    uint256 public tabExpirationTime = 21 days;
    uint256 public synchronizationDelay = 6 hours;

    /// TODO(#22): move key to registry
    BLS.G1Point public GUARANTEE_VERIFICATION_KEY;
    bytes32 public guaranteeDomainSeparator;

    address public immutable USDC;
    address public immutable USDT;

    address internal constant ETH_ASSET = address(0);

    /// @notice The negated generator point in G1 (-G1), derived from EIP-2537's standard G1 generator.
    BLS.G1Point internal NEGATED_G1_GENERATOR =
        BLS.G1Point(
            bytes32(
                0x0000000000000000000000000000000017F1D3A73197D7942695638C4FA9AC0F
            ),
            bytes32(
                0xC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB
            ),
            bytes32(
                0x00000000000000000000000000000000114D1D6855D545A8AA7D76C8CF2E21F2
            ),
            bytes32(
                0x67816AEF1DB507C96655B9D5CAAC42364E6F38BA0ECB751BAD54DCD6B939C2CA
            )
        );

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

    mapping(address => mapping(address => uint256)) internal collateralBalances;
    mapping(address => mapping(address => WithdrawalRequest))
        public withdrawalRequests;
    mapping(uint256 => PaymentStatus) public payments;

    // ========= Events =========
    event CollateralDeposited(
        address indexed user,
        address indexed asset,
        uint256 amount
    );
    event RecipientRemunerated(
        uint256 indexed tab_id,
        address indexed asset,
        uint256 amount
    );
    event CollateralWithdrawn(
        address indexed user,
        address indexed asset,
        uint256 amount
    );
    event WithdrawalRequested(
        address indexed user,
        address indexed asset,
        uint256 when,
        uint256 amount
    );
    event WithdrawalCanceled(address indexed user, address indexed asset);
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
    event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
    event TabExpirationTimeUpdated(uint256 newExpirationTime);
    event SynchronizationDelayUpdated(uint256 newExpirationTime);
    event VerificationKeyUpdated(BLS.G1Point newVerificationKey);
    event PaymentRecorded(
        uint256 indexed tab_id,
        address indexed asset,
        uint256 amount
    );
    event TabPaid(
        uint256 indexed tab_id,
        address indexed asset,
        address indexed user,
        uint256 amount
    );

    // ========= Helper structs =========
    struct Guarantee {
        uint256 tab_id;
        uint256 tab_timestamp;
        address client;
        address recipient;
        uint256 req_id;
        uint256 amount;
        address asset;
    }

    // ========= Constructor =========
    constructor(
        address manager,
        BLS.G1Point memory verificationKey,
        address usdc_,
        address usdt_
    ) AccessManaged(manager) {
        if (usdc_ == address(0)) revert InvalidAsset(usdc_);
        if (usdt_ == address(0)) revert InvalidAsset(usdt_);
        if (usdc_ == usdt_) revert InvalidAsset(usdc_);

        USDC = usdc_;
        USDT = usdt_;
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        guaranteeDomainSeparator = keccak256(
            abi.encode("4MICA_CORE_GUARANTEE_V1", block.chainid, address(this))
        );
    }

    // ========= Modifiers =========
    modifier nonZero(uint256 amount) {
        if (amount == 0) revert AmountZero();
        _;
    }

    modifier validRecipient(address recipient) {
        if (recipient == address(0)) revert InvalidRecipient();
        _;
    }

    modifier supportedAsset(address asset) {
        if (!isSupportedAsset(asset)) revert UnsupportedAsset(asset);
        _;
    }

    modifier stablecoin(address asset) {
        if (!isStablecoin(asset)) revert UnsupportedAsset(asset);
        _;
    }

    // ========= Admin / Manager configuration =========
    function setRemunerationGracePeriod(
        uint256 _gracePeriod
    ) external restricted nonZero(_gracePeriod) {
        if (_gracePeriod >= tabExpirationTime) revert IllegalValue();
        remunerationGracePeriod = _gracePeriod;
        emit RemunerationGracePeriodUpdated(_gracePeriod);
    }

    function setWithdrawalGracePeriod(
        uint256 _gracePeriod
    ) external restricted nonZero(_gracePeriod) {
        if (synchronizationDelay + tabExpirationTime >= _gracePeriod)
            revert IllegalValue();
        withdrawalGracePeriod = _gracePeriod;
        emit WithdrawalGracePeriodUpdated(_gracePeriod);
    }

    function setTabExpirationTime(
        uint256 _expirationTime
    ) external restricted nonZero(_expirationTime) {
        if (
            synchronizationDelay + _expirationTime >= withdrawalGracePeriod ||
            remunerationGracePeriod >= _expirationTime
        ) revert IllegalValue();
        tabExpirationTime = _expirationTime;
        emit TabExpirationTimeUpdated(_expirationTime);
    }

    function setSynchronizationDelay(
        uint256 _synchronizationDelay
    ) external restricted nonZero(_synchronizationDelay) {
        if (_synchronizationDelay + tabExpirationTime >= withdrawalGracePeriod)
            revert IllegalValue();
        synchronizationDelay = _synchronizationDelay;
        emit SynchronizationDelayUpdated(_synchronizationDelay);
    }

    function setTimingParameters(
        uint256 _remunerationGracePeriod,
        uint256 _tabExpirationTime,
        uint256 _synchronizationDelay,
        uint256 _withdrawalGracePeriod
    ) external restricted {
        if (
            _remunerationGracePeriod == 0 ||
            _tabExpirationTime == 0 ||
            _synchronizationDelay == 0 ||
            _withdrawalGracePeriod == 0
        ) revert AmountZero();

        if (_remunerationGracePeriod >= _tabExpirationTime)
            revert IllegalValue();
        if (
            _synchronizationDelay + _tabExpirationTime >= _withdrawalGracePeriod
        ) revert IllegalValue();

        remunerationGracePeriod = _remunerationGracePeriod;
        tabExpirationTime = _tabExpirationTime;
        synchronizationDelay = _synchronizationDelay;
        withdrawalGracePeriod = _withdrawalGracePeriod;

        emit RemunerationGracePeriodUpdated(_remunerationGracePeriod);
        emit TabExpirationTimeUpdated(_tabExpirationTime);
        emit SynchronizationDelayUpdated(_synchronizationDelay);
        emit WithdrawalGracePeriodUpdated(_withdrawalGracePeriod);
    }

    function setGuaranteeVerificationKey(
        BLS.G1Point calldata verificationKey
    ) external restricted {
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        emit VerificationKeyUpdated(verificationKey);
    }

    // ========= User flows =========
    function deposit() external payable nonReentrant nonZero(msg.value) {
        collateralBalances[msg.sender][ETH_ASSET] += msg.value;
        emit CollateralDeposited(msg.sender, ETH_ASSET, msg.value);
    }

    function depositStablecoin(
        address asset,
        uint256 amount
    ) external nonReentrant stablecoin(asset) nonZero(amount) {
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        collateralBalances[msg.sender][asset] += amount;
        emit CollateralDeposited(msg.sender, asset, amount);
    }

    function requestWithdrawal(uint256 amount) external nonZero(amount) {
        requestWithdrawalInternal(msg.sender, ETH_ASSET, amount);
    }

    function requestWithdrawal(
        address asset,
        uint256 amount
    ) external supportedAsset(asset) nonZero(amount) {
        requestWithdrawalInternal(msg.sender, asset, amount);
    }

    function requestWithdrawalInternal(
        address user,
        address asset,
        uint256 amount
    ) internal {
        if (amount > collateralBalances[user][asset])
            revert InsufficientAvailable();

        withdrawalRequests[user][asset] = WithdrawalRequest(
            block.timestamp,
            amount
        );
        emit WithdrawalRequested(user, asset, block.timestamp, amount);
    }

    function cancelWithdrawal() external {
        cancelWithdrawalInternal(msg.sender, ETH_ASSET);
    }

    function cancelWithdrawal(address asset) external supportedAsset(asset) {
        cancelWithdrawalInternal(msg.sender, asset);
    }

    function cancelWithdrawalInternal(address user, address asset) internal {
        if (withdrawalRequests[user][asset].timestamp == 0)
            revert NoWithdrawalRequested();
        delete withdrawalRequests[user][asset];
        emit WithdrawalCanceled(user, asset);
    }

    function finalizeWithdrawal() external nonReentrant {
        finalizeWithdrawalInternal(msg.sender, ETH_ASSET);
    }

    function finalizeWithdrawal(
        address asset
    ) external nonReentrant supportedAsset(asset) {
        finalizeWithdrawalInternal(msg.sender, asset);
    }

    function finalizeWithdrawalInternal(address user, address asset) internal {
        WithdrawalRequest memory request = withdrawalRequests[user][asset];
        if (request.timestamp == 0) revert NoWithdrawalRequested();
        if (block.timestamp < request.timestamp + withdrawalGracePeriod)
            revert GracePeriodNotElapsed();

        /// The user's collateral may have been reduced since the withdrawal was requested.
        /// As such, take the minimum of the two, making sure we never overdraw the account.
        uint256 available = collateralBalances[user][asset];
        uint256 withdrawal_amount = Math.min(available, request.amount);

        collateralBalances[user][asset] = available - withdrawal_amount;
        delete withdrawalRequests[user][asset];

        if (asset == ETH_ASSET) {
            (bool ok, ) = payable(user).call{value: withdrawal_amount}("");
            if (!ok) revert TransferFailed();
        } else {
            IERC20(asset).safeTransfer(user, withdrawal_amount);
        }

        emit CollateralWithdrawn(user, asset, withdrawal_amount);
    }

    function payTabInERC20Token(
        uint256 tab_id,
        address asset,
        uint256 amount,
        address recipient
    )
        external
        nonReentrant
        stablecoin(asset)
        nonZero(amount)
        validRecipient(recipient)
    {
        IERC20(asset).safeTransferFrom(msg.sender, recipient, amount);
        emit TabPaid(tab_id, asset, msg.sender, amount);
    }

    /// TODO(#20): compress signature
    /// TODO(#21): permit batch verification
    function remunerate(
        Guarantee calldata g,
        BLS.G2Point calldata signature
    ) external nonReentrant nonZero(g.amount) validRecipient(g.recipient) {
        // Tab must be overdue
        if (block.timestamp < g.tab_timestamp + remunerationGracePeriod)
            revert TabNotYetOverdue();

        // Tab must not be expired
        if (g.tab_timestamp + tabExpirationTime < block.timestamp)
            revert TabExpired();

        address asset = requireSupportedAsset(g.asset);
        PaymentStatus storage status = payments[g.tab_id];

        // If payment doesn't exist yet (never been initialized), set the asset
        if (status.paid == 0 && !status.remunerated) {
            status.asset = asset;
        } else {
            // If payment already exists, verify the asset matches
            if (status.asset != asset) revert InvalidAsset(asset);
        }

        // Tab must not previously be remunerated
        if (status.remunerated) revert TabPreviouslyRemunerated();

        // Tab must not be paid
        if (status.paid >= g.amount) revert TabAlreadyPaid();

        // Verify signature
        if (!verifyGuaranteeSignature(g, signature)) revert InvalidSignature();

        // Client must have sufficient funds
        if (collateralBalances[g.client][asset] < g.amount)
            revert DoubleSpendingDetected();

        collateralBalances[g.client][asset] -= g.amount;
        status.remunerated = true;

        // Subtract the remunerated value from the withdrawal request
        // whenever the tab was opened BEFORE the withdrawal request
        // was synchronized.
        WithdrawalRequest storage wr = withdrawalRequests[g.client][asset];
        if (
            wr.timestamp != 0 &&
            g.tab_timestamp < wr.timestamp + synchronizationDelay
        ) {
            uint256 deduction = Math.min(wr.amount, g.amount);
            wr.amount -= deduction;
        }

        if (asset == ETH_ASSET) {
            (bool ok, ) = payable(g.recipient).call{value: g.amount}("");
            if (!ok) revert TransferFailed();
        } else {
            IERC20(asset).safeTransfer(g.recipient, g.amount);
        }

        emit RecipientRemunerated(g.tab_id, asset, g.amount);
    }

    // ========= Operator / Manager flows =========
    function recordPayment(
        uint256 tab_id,
        address asset,
        uint256 amount
    ) external restricted supportedAsset(asset) nonZero(amount) nonReentrant {
        PaymentStatus storage status = payments[tab_id];

        // If payment doesn't exist yet (never been initialized), set the asset
        if (status.paid == 0 && !status.remunerated) {
            status.asset = asset;
        } else {
            // If payment already exists, verify the asset matches
            if (status.asset != asset) revert InvalidAsset(asset);
        }

        status.paid += amount;
        emit PaymentRecorded(tab_id, asset, amount);
    }

    // ========= Views / Helpers =========
    function collateral(address userAddr) external view returns (uint256) {
        return collateralBalances[userAddr][ETH_ASSET];
    }

    function collateral(
        address userAddr,
        address asset
    ) external view supportedAsset(asset) returns (uint256) {
        return collateralBalances[userAddr][asset];
    }

    function getUserAllAssets(
        address userAddr
    ) external view returns (UserAssetInfo[] memory) {
        UserAssetInfo[] memory assetInfos = new UserAssetInfo[](3);

        address[3] memory assets = [ETH_ASSET, USDC, USDT];

        for (uint256 i = 0; i < 3; i++) {
            address asset = assets[i];
            WithdrawalRequest storage request = withdrawalRequests[userAddr][
                asset
            ];

            assetInfos[i] = UserAssetInfo({
                asset: asset,
                collateral: collateralBalances[userAddr][asset],
                withdrawalRequestTimestamp: request.timestamp,
                withdrawalRequestAmount: request.amount
            });
        }

        return assetInfos;
    }

    function getUser(
        address userAddr
    )
        external
        view
        returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        )
    {
        return getUser(userAddr, ETH_ASSET);
    }

    function getUser(
        address userAddr,
        address asset
    )
        public
        view
        supportedAsset(asset)
        returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        )
    {
        WithdrawalRequest storage request = withdrawalRequests[userAddr][asset];
        assetCollateral = collateralBalances[userAddr][asset];
        withdrawalRequestTimestamp = request.timestamp;
        withdrawalRequestAmount = request.amount;
    }

    function getPaymentStatus(
        uint256 tab_id
    ) external view returns (uint256 paid, bool remunerated, address asset) {
        PaymentStatus storage status = payments[tab_id];
        paid = status.paid;
        remunerated = status.remunerated;
        asset = status.asset;
    }

    function getERC20Tokens() external view returns (address[] memory) {
        address[] memory tokens = new address[](2);
        tokens[0] = USDC;
        tokens[1] = USDT;
        return tokens;
    }

    // === Signature verification ===
    function encodeGuarantee(
        Guarantee memory g
    ) public view returns (bytes memory) {
        return
            abi.encodePacked(
                guaranteeDomainSeparator,
                g.tab_id,
                g.req_id,
                g.client,
                g.recipient,
                g.amount,
                g.asset,
                g.tab_timestamp
            );
    }

    function verifyGuaranteeSignature(
        Guarantee memory guarantee,
        BLS.G2Point memory signature
    ) public view returns (bool) {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR;
        g1Points[1] = GUARANTEE_VERIFICATION_KEY;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = BLS.hashToG2(encodeGuarantee(guarantee));

        return BLS.pairing(g1Points, g2Points);
    }

    // ========= Fallbacks =========
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    fallback() external payable {
        revert DirectTransferNotAllowed();
    }

    function requireSupportedAsset(
        address asset
    ) internal view returns (address) {
        if (isSupportedAsset(asset)) return asset;
        revert UnsupportedAsset(asset);
    }

    function isSupportedAsset(address asset) internal view returns (bool) {
        return asset == ETH_ASSET || asset == USDC || asset == USDT;
    }

    function isStablecoin(address asset) internal view returns (bool) {
        return asset == USDC || asset == USDT;
    }
}
