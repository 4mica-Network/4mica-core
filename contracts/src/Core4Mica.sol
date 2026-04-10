// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {IAavePool} from "./interfaces/IAavePool.sol";
import {IPoolAddressesProvider} from "./interfaces/IPoolAddressesProvider.sol";
import {IAaveProtocolDataProvider} from "./interfaces/IAaveProtocolDataProvider.sol";
import {IAToken} from "./interfaces/IAToken.sol";
import {Core4MicaAccounting} from "./libraries/Core4MicaAccounting.sol";

struct Guarantee {
    bytes32 domain;
    uint256 tabId;
    uint256 reqId;
    address client;
    address recipient;
    uint256 amount;
    uint256 totalAmount;
    address asset;
    uint64 timestamp;
    uint64 version;
}

interface IGuaranteeDecoder {
    function decode(bytes calldata data) external view returns (Guarantee memory);
}

/// @title Core4Mica
/// @notice Manages user collateral, delayed withdrawals, and make-whole payouts.
contract Core4Mica is AccessManaged, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_YIELD_FEE_BPS = 5000;
    uint256 public constant RECONCILIATION_DUST_TOLERANCE_SCALED = 1;

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
    error MissingGuaranteeDecoder(uint64 version);
    error AaveNotConfigured();
    error FeeTooHigh();
    error TreasuryClaimExceedsAvailable();
    error UnsupportedTreasuryAsset(address asset);
    error StablecoinWithdrawShortfall(address asset, uint256 requested, uint256 actual);
    error AaveProviderReconfigurationBlocked();
    error UserScaledBalanceUnderflow(address asset, address user, uint256 deduction, uint256 balance);
    error ZeroAddress();
    error InvalidAToken(address asset, address aToken);
    error ReconciliationLoss(address asset, uint256 tracked, uint256 observed);
    error SurplusClaimExceedsAvailable();

    // ========= Storage =========
    uint256 public remunerationGracePeriod = 14 days;
    uint256 public withdrawalGracePeriod = 22 days;
    uint256 public tabExpirationTime = 21 days;
    uint256 public synchronizationDelay = 6 hours;

    // forge-lint: disable-next-line(mixed-case-variable)
    BLS.G1Point public GUARANTEE_VERIFICATION_KEY;
    bytes32 public guaranteeDomainSeparator;

    struct VersionConfig {
        BLS.G1Point verificationKey;
        bytes32 domainSeparator;
        address decoder;
        bool enabled;
    }

    mapping(uint64 => VersionConfig) private guaranteeVersions;
    uint64 public constant INITIAL_GUARANTEE_VERSION = 1;

    address internal constant ETH_ASSET = address(0);
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable usdc;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable usdt;

    mapping(address => bool) private stablecoinAssets;
    address[] private stablecoinAssetList;
    mapping(address => uint256) private stablecoinAssetIndexPlusOne;

    mapping(address => bool) public stablecoinDepositsEnabled;
    IPoolAddressesProvider public aaveAddressesProvider;
    uint256 public yieldFeeBps;
    mapping(address => address) internal stablecoinATokens;
    mapping(address => address) internal approvedPoolForAsset;
    mapping(address => mapping(address => uint256)) internal scaledStablecoinBalances;
    mapping(address => mapping(address => uint256)) internal stablecoinPrincipalBalances;
    mapping(address => uint256) internal protocolScaledStablecoinBalances;
    mapping(address => uint256) internal totalUserScaledStablecoinBalances;
    mapping(address => uint256) internal surplusScaledStablecoinBalances;
    mapping(address => uint256) internal ethCollateralBalances;

    /// @notice The negated generator point in G1 (-G1), derived from EIP-2537's standard G1 generator.
    BLS.G1Point internal negatedG1Generator = BLS.G1Point(
        bytes32(0x0000000000000000000000000000000017F1D3A73197D7942695638C4FA9AC0F),
        bytes32(0xC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB),
        bytes32(0x00000000000000000000000000000000114D1D6855D545A8AA7D76C8CF2E21F2),
        bytes32(0x67816AEF1DB507C96655B9D5CAAC42364E6F38BA0ECB751BAD54DCD6B939C2CA)
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

    mapping(address => mapping(address => WithdrawalRequest)) public withdrawalRequests;
    mapping(uint256 => PaymentStatus) public payments;

    // ========= Events =========
    event CollateralDeposited(address indexed user, address indexed asset, uint256 amount);
    event RecipientRemunerated(uint256 indexed tabId, address indexed asset, uint256 amount);
    event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);
    event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);
    event WithdrawalCanceled(address indexed user, address indexed asset);
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
    event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
    event TabExpirationTimeUpdated(uint256 newExpirationTime);
    event SynchronizationDelayUpdated(uint256 newExpirationTime);
    event VerificationKeyUpdated(BLS.G1Point newVerificationKey);
    event PaymentRecorded(uint256 indexed tabId, address indexed asset, uint256 amount);
    event TabPaid(
        uint256 indexed tabId, address indexed asset, address indexed user, address recipient, uint256 amount
    );
    event GuaranteeVersionUpdated(
        uint64 indexed version, BLS.G1Point verificationKey, bytes32 domainSeparator, address decoder, bool enabled
    );
    event StablecoinAssetUpdated(address indexed asset, bool enabled);
    event AaveConfigured(address indexed provider, address indexed pool);
    event YieldFeeBpsUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event StablecoinDepositsEnabledUpdated(address indexed asset, bool enabled);
    event ProtocolYieldClaimed(address indexed asset, address indexed to, uint256 amount);
    event SurplusATokensClaimed(address indexed asset, address indexed to, uint256 scaledAmount, uint256 nominalAmount);

    // ========= Constructor =========
    constructor(address manager, BLS.G1Point memory verificationKey, address usdc_, address usdt_)
        AccessManaged(manager)
    {
        if (usdc_ == address(0) || usdt_ == address(0)) revert ZeroAddress();
        if (usdc_ == usdt_) revert InvalidAsset(usdc_);

        usdc = usdc_;
        usdt = usdt_;
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        guaranteeDomainSeparator = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V1", block.chainid, address(this)));
        guaranteeVersions[INITIAL_GUARANTEE_VERSION] = VersionConfig({
            verificationKey: verificationKey,
            domainSeparator: guaranteeDomainSeparator,
            decoder: address(0),
            enabled: true
        });
        emit GuaranteeVersionUpdated(
            INITIAL_GUARANTEE_VERSION, verificationKey, guaranteeDomainSeparator, address(0), true
        );
    }

    // ========= Modifiers =========
    modifier nonZero(uint256 amount) {
        _requireNonZero(amount);
        _;
    }

    modifier validRecipient(address recipient) {
        _requireValidRecipient(recipient);
        _;
    }

    modifier supportedAsset(address asset) {
        _requireSupportedAsset(asset);
        _;
    }

    modifier stablecoin(address asset) {
        _requireStablecoin(asset);
        _;
    }

    function _requireNonZero(uint256 amount) internal pure {
        if (amount == 0) revert AmountZero();
    }

    function _requireValidRecipient(address recipient) internal pure {
        if (recipient == address(0)) revert InvalidRecipient();
    }

    function _requireSupportedAsset(address asset) internal view {
        if (!isSupportedAsset(asset)) revert UnsupportedAsset(asset);
    }

    function _requireStablecoin(address asset) internal view {
        if (!isStablecoin(asset)) revert UnsupportedAsset(asset);
    }

    // ========= Admin / Manager configuration =========
    function pause() external restricted {
        _pause();
    }

    function unpause() external restricted {
        _unpause();
    }

    function setRemunerationGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        if (_gracePeriod >= tabExpirationTime) revert IllegalValue();
        remunerationGracePeriod = _gracePeriod;
        emit RemunerationGracePeriodUpdated(_gracePeriod);
    }

    function setWithdrawalGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        if (synchronizationDelay + tabExpirationTime >= _gracePeriod) {
            revert IllegalValue();
        }
        withdrawalGracePeriod = _gracePeriod;
        emit WithdrawalGracePeriodUpdated(_gracePeriod);
    }

    function setTabExpirationTime(uint256 _expirationTime) external restricted nonZero(_expirationTime) {
        if (
            synchronizationDelay + _expirationTime >= withdrawalGracePeriod
                || remunerationGracePeriod >= _expirationTime
        ) revert IllegalValue();
        tabExpirationTime = _expirationTime;
        emit TabExpirationTimeUpdated(_expirationTime);
    }

    function setSynchronizationDelay(uint256 _synchronizationDelay)
        external
        restricted
        nonZero(_synchronizationDelay)
    {
        if (_synchronizationDelay + tabExpirationTime >= withdrawalGracePeriod) {
            revert IllegalValue();
        }
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
            _remunerationGracePeriod == 0 || _tabExpirationTime == 0 || _synchronizationDelay == 0
                || _withdrawalGracePeriod == 0
        ) revert AmountZero();

        if (_remunerationGracePeriod >= _tabExpirationTime) {
            revert IllegalValue();
        }
        if (_synchronizationDelay + _tabExpirationTime >= _withdrawalGracePeriod) revert IllegalValue();

        remunerationGracePeriod = _remunerationGracePeriod;
        tabExpirationTime = _tabExpirationTime;
        synchronizationDelay = _synchronizationDelay;
        withdrawalGracePeriod = _withdrawalGracePeriod;

        emit RemunerationGracePeriodUpdated(_remunerationGracePeriod);
        emit TabExpirationTimeUpdated(_tabExpirationTime);
        emit SynchronizationDelayUpdated(_synchronizationDelay);
        emit WithdrawalGracePeriodUpdated(_withdrawalGracePeriod);
    }

    function setGuaranteeVerificationKey(BLS.G1Point calldata verificationKey) external restricted {
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        VersionConfig storage config = guaranteeVersions[INITIAL_GUARANTEE_VERSION];
        config.verificationKey = verificationKey;
        emit VerificationKeyUpdated(verificationKey);
        emit GuaranteeVersionUpdated(
            INITIAL_GUARANTEE_VERSION, verificationKey, config.domainSeparator, config.decoder, config.enabled
        );
    }

    function configureGuaranteeVersion(
        uint64 version,
        BLS.G1Point calldata verificationKey,
        bytes32 domainSeparator,
        address decoder,
        bool enabled
    ) external restricted {
        if (version == 0) revert UnsupportedGuaranteeVersion(version);
        if (version == INITIAL_GUARANTEE_VERSION && decoder != address(0)) {
            revert UnsupportedGuaranteeVersion(version);
        }
        VersionConfig storage config = guaranteeVersions[version];
        address decoderToUse = decoder;
        if (version != INITIAL_GUARANTEE_VERSION && decoderToUse == address(0)) {
            if (enabled) revert MissingGuaranteeDecoder(version);
            decoderToUse = config.decoder;
        }
        bytes32 domainSeparatorToUse = domainSeparator;
        if (enabled && domainSeparatorToUse == bytes32(0)) {
            revert InvalidGuaranteeDomain();
        }
        if (!enabled && domainSeparatorToUse == bytes32(0)) {
            domainSeparatorToUse = config.domainSeparator;
        }

        config.verificationKey = verificationKey;
        config.domainSeparator = domainSeparatorToUse;
        config.decoder = decoderToUse;
        config.enabled = enabled;

        if (version == INITIAL_GUARANTEE_VERSION) {
            GUARANTEE_VERIFICATION_KEY = verificationKey;
            guaranteeDomainSeparator = domainSeparatorToUse;
        }

        emit GuaranteeVersionUpdated(version, verificationKey, domainSeparatorToUse, decoderToUse, enabled);
    }

    function setStablecoinAsset(address asset, bool enabled) external restricted {
        _setStablecoinAsset(asset, enabled);
    }

    function setStablecoinAssets(address[] calldata assets, bool enabled) external restricted {
        for (uint256 i = 0; i < assets.length; i++) {
            _setStablecoinAsset(assets[i], enabled);
        }
    }

    function configureAave(address poolAddressesProvider, address usdcAToken, address usdtAToken) external restricted {
        if (poolAddressesProvider == address(0) || usdcAToken == address(0) || usdtAToken == address(0)) {
            revert ZeroAddress();
        }
        if (_hasOpenStablecoinPositions()) revert AaveProviderReconfigurationBlocked();

        address usdcAsset = IAToken(usdcAToken).UNDERLYING_ASSET_ADDRESS();
        address usdtAsset = IAToken(usdtAToken).UNDERLYING_ASSET_ADDRESS();
        if (usdcAsset != usdc) revert InvalidAToken(usdc, usdcAToken);
        if (usdtAsset != usdt) revert InvalidAToken(usdt, usdtAToken);
        if (usdcAsset == usdtAsset) revert InvalidAsset(usdcAsset);

        IPoolAddressesProvider provider = IPoolAddressesProvider(poolAddressesProvider);
        address pool = provider.getPool();
        address dataProvider = provider.getPoolDataProvider();
        if (pool == address(0) || dataProvider == address(0)) revert ZeroAddress();

        (address configuredUsdcAToken,,) = IAaveProtocolDataProvider(dataProvider).getReserveTokensAddresses(usdc);
        (address configuredUsdtAToken,,) = IAaveProtocolDataProvider(dataProvider).getReserveTokensAddresses(usdt);
        if (configuredUsdcAToken != usdcAToken) revert InvalidAToken(usdc, usdcAToken);
        if (configuredUsdtAToken != usdtAToken) revert InvalidAToken(usdt, usdtAToken);

        aaveAddressesProvider = provider;
        stablecoinATokens[usdc] = usdcAToken;
        stablecoinATokens[usdt] = usdtAToken;
        approvedPoolForAsset[usdc] = address(0);
        approvedPoolForAsset[usdt] = address(0);
        emit AaveConfigured(poolAddressesProvider, pool);
    }

    function setYieldFeeBps(uint256 feeBps) external restricted {
        if (feeBps > MAX_YIELD_FEE_BPS) revert FeeTooHigh();
        uint256 oldFee = yieldFeeBps;
        yieldFeeBps = feeBps;
        emit YieldFeeBpsUpdated(oldFee, feeBps);
    }

    function setStablecoinDepositsEnabled(address asset, bool enabled) external restricted stablecoin(asset) {
        stablecoinDepositsEnabled[asset] = enabled;
        emit StablecoinDepositsEnabledUpdated(asset, enabled);
    }

    function claimProtocolYield(address asset, address to, uint256 amount)
        external
        restricted
        nonReentrant
        validRecipient(to)
        stablecoin(asset)
    {
        uint256 index = _currentIndex(asset);
        uint256 amountToClaim = amount;
        if (amount == type(uint256).max) {
            amountToClaim = _toUnderlyingRoundDown(protocolScaledStablecoinBalances[asset], index);
            if (amountToClaim == 0) revert AmountZero();
        } else if (amount == 0) {
            revert AmountZero();
        }

        uint256 claimable = _toUnderlyingRoundDown(protocolScaledStablecoinBalances[asset], index);
        if (amountToClaim > claimable) revert TreasuryClaimExceedsAvailable();

        address aToken = _requireAToken(asset);
        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        uint256 actualWithdrawn = _aavePool().withdraw(asset, amountToClaim, to);
        if (actualWithdrawn < amountToClaim) {
            revert StablecoinWithdrawShortfall(asset, amountToClaim, actualWithdrawn);
        }
        uint256 scaledAfter = IAToken(aToken).scaledBalanceOf(address(this));
        uint256 scaledBurn = scaledBefore - scaledAfter;
        protocolScaledStablecoinBalances[asset] -= scaledBurn;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        emit ProtocolYieldClaimed(asset, to, actualWithdrawn);
    }

    function claimSurplusATokens(address asset, address to, uint256 scaledAmount)
        external
        restricted
        nonReentrant
        validRecipient(to)
        stablecoin(asset)
        nonZero(scaledAmount)
    {
        if (scaledAmount > surplusScaledStablecoinBalances[asset]) revert SurplusClaimExceedsAvailable();
        address aToken = _requireAToken(asset);
        uint256 nominalAmount = _toUnderlyingRoundDown(scaledAmount, _currentIndex(asset));
        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        IERC20(aToken).safeTransfer(to, nominalAmount);
        uint256 scaledAfter = IAToken(aToken).scaledBalanceOf(address(this));
        uint256 actualScaledRemoved = scaledBefore - scaledAfter;
        if (actualScaledRemoved > surplusScaledStablecoinBalances[asset]) revert SurplusClaimExceedsAvailable();
        surplusScaledStablecoinBalances[asset] -= actualScaledRemoved;
        _checkReconciliation(asset);
        emit SurplusATokensClaimed(asset, to, actualScaledRemoved, nominalAmount);
    }

    function getGuaranteeVersionConfig(uint64 version)
        external
        view
        returns (BLS.G1Point memory verificationKey, bytes32 domainSeparator, address decoder, bool enabled)
    {
        VersionConfig storage config = guaranteeVersions[version];
        return (config.verificationKey, config.domainSeparator, config.decoder, config.enabled);
    }

    // ========= User flows =========
    function deposit() external payable nonReentrant nonZero(msg.value) whenNotPaused {
        ethCollateralBalances[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, ETH_ASSET, msg.value);
    }

    function depositStablecoin(address asset, uint256 amount)
        external
        nonReentrant
        stablecoin(asset)
        nonZero(amount)
        whenNotPaused
    {
        if (!stablecoinDepositsEnabled[asset]) revert IllegalValue();
        address aToken = _requireAToken(asset);

        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);

        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        _ensureDepositApproval(asset, amount);
        _aavePool().supply(asset, amount, address(this), 0);
        uint256 scaledAfter = IAToken(aToken).scaledBalanceOf(address(this));
        uint256 scaledCredit = scaledAfter - scaledBefore;

        scaledStablecoinBalances[msg.sender][asset] += scaledCredit;
        totalUserScaledStablecoinBalances[asset] += scaledCredit;
        stablecoinPrincipalBalances[msg.sender][asset] += amount;
        _syncSurplusScaledBalance(asset);
        emit CollateralDeposited(msg.sender, asset, amount);
    }

    function requestWithdrawal(uint256 amount) external nonZero(amount) whenNotPaused {
        requestWithdrawalInternal(msg.sender, ETH_ASSET, amount);
    }

    function requestWithdrawal(address asset, uint256 amount)
        external
        supportedAsset(asset)
        nonZero(amount)
        whenNotPaused
    {
        requestWithdrawalInternal(msg.sender, asset, amount);
    }

    function requestWithdrawalInternal(address user, address asset, uint256 amount) internal {
        if (amount > _availableBalance(user, asset)) {
            revert InsufficientAvailable();
        }

        withdrawalRequests[user][asset] = WithdrawalRequest({timestamp: block.timestamp, amount: amount});
        emit WithdrawalRequested(user, asset, block.timestamp, amount);
    }

    function cancelWithdrawal() external whenNotPaused {
        cancelWithdrawalInternal(msg.sender, ETH_ASSET);
    }

    function cancelWithdrawal(address asset) external supportedAsset(asset) whenNotPaused {
        cancelWithdrawalInternal(msg.sender, asset);
    }

    function cancelWithdrawalInternal(address user, address asset) internal {
        if (withdrawalRequests[user][asset].timestamp == 0) {
            revert NoWithdrawalRequested();
        }
        delete withdrawalRequests[user][asset];
        emit WithdrawalCanceled(user, asset);
    }

    function finalizeWithdrawal() external nonReentrant whenNotPaused {
        finalizeWithdrawalInternal(msg.sender, ETH_ASSET);
    }

    function finalizeWithdrawal(address asset) external nonReentrant supportedAsset(asset) whenNotPaused {
        finalizeWithdrawalInternal(msg.sender, asset);
    }

    function finalizeWithdrawalInternal(address user, address asset) internal {
        WithdrawalRequest memory request = withdrawalRequests[user][asset];
        if (request.timestamp == 0) revert NoWithdrawalRequested();
        if (block.timestamp < request.timestamp + withdrawalGracePeriod) {
            revert GracePeriodNotElapsed();
        }

        if (asset == ETH_ASSET) {
            _finalizeEthWithdrawal(user, request);
            return;
        }

        _finalizeStablecoinWithdrawal(user, asset, request);
    }

    function payTabInERC20Token(uint256 tabId, address asset, uint256 amount, address recipient)
        external
        nonReentrant
        stablecoin(asset)
        nonZero(amount)
        validRecipient(recipient)
        whenNotPaused
    {
        IERC20(asset).safeTransferFrom(msg.sender, recipient, amount);
        emit TabPaid(tabId, asset, msg.sender, recipient, amount);
    }

    function remunerate(bytes calldata guaranteeData, BLS.G2Point calldata signature) external nonReentrant {
        Guarantee memory g = verifyAndDecodeGuarantee(guaranteeData, signature);

        if (g.amount == 0) revert AmountZero();
        if (g.totalAmount == 0) revert AmountZero();
        if (g.recipient == address(0)) revert InvalidRecipient();

        if (block.timestamp < g.timestamp + remunerationGracePeriod) {
            revert TabNotYetOverdue();
        }
        if (g.timestamp + tabExpirationTime < block.timestamp) {
            revert TabExpired();
        }

        address asset = requireSupportedAsset(g.asset);
        PaymentStatus storage status = payments[g.tabId];

        if (status.paid == 0 && !status.remunerated) {
            status.asset = asset;
        } else if (status.asset != asset) {
            revert InvalidAsset(asset);
        }

        if (status.remunerated) revert TabPreviouslyRemunerated();
        if (status.paid >= g.totalAmount) revert TabAlreadyPaid();
        uint256 remaining = g.totalAmount - status.paid;

        if (asset == ETH_ASSET) {
            _remunerateEth(g, status, remaining);
            return;
        }

        _remunerateStablecoin(g, status, asset, remaining);
    }

    // ========= Operator / Manager flows =========
    function recordPayment(uint256 tabId, address asset, uint256 amount)
        external
        restricted
        supportedAsset(asset)
        nonZero(amount)
        nonReentrant
    {
        PaymentStatus storage status = payments[tabId];

        if (status.paid == 0 && !status.remunerated) {
            status.asset = asset;
        } else if (status.asset != asset) {
            revert InvalidAsset(asset);
        }

        status.paid += amount;
        emit PaymentRecorded(tabId, asset, amount);
    }

    // ========= Views / Helpers =========
    function collateral(address userAddr) external view returns (uint256) {
        return ethCollateralBalances[userAddr];
    }

    function collateral(address userAddr, address asset) external view supportedAsset(asset) returns (uint256) {
        if (asset == ETH_ASSET) return ethCollateralBalances[userAddr];
        return _userWithdrawableStablecoinBalance(userAddr, asset);
    }

    function getUserAllAssets(address userAddr) external view returns (UserAssetInfo[] memory) {
        uint256 stablecoinCount = stablecoinAssetList.length;
        UserAssetInfo[] memory assetInfos = new UserAssetInfo[](stablecoinCount + 1);

        WithdrawalRequest storage ethRequest = withdrawalRequests[userAddr][ETH_ASSET];
        assetInfos[0] = UserAssetInfo({
            asset: ETH_ASSET,
            collateral: ethCollateralBalances[userAddr],
            withdrawalRequestTimestamp: ethRequest.timestamp,
            withdrawalRequestAmount: ethRequest.amount
        });

        for (uint256 i = 0; i < stablecoinCount; i++) {
            address asset = stablecoinAssetList[i];
            WithdrawalRequest storage request = withdrawalRequests[userAddr][asset];

            assetInfos[i + 1] = UserAssetInfo({
                asset: asset,
                collateral: _userWithdrawableStablecoinBalance(userAddr, asset),
                withdrawalRequestTimestamp: request.timestamp,
                withdrawalRequestAmount: request.amount
            });
        }

        return assetInfos;
    }

    function getUser(address userAddr)
        external
        view
        returns (uint256 assetCollateral, uint256 withdrawalRequestTimestamp, uint256 withdrawalRequestAmount)
    {
        return getUser(userAddr, ETH_ASSET);
    }

    function getUser(address userAddr, address asset)
        public
        view
        supportedAsset(asset)
        returns (uint256 assetCollateral, uint256 withdrawalRequestTimestamp, uint256 withdrawalRequestAmount)
    {
        WithdrawalRequest storage request = withdrawalRequests[userAddr][asset];
        assetCollateral = asset == ETH_ASSET ? ethCollateralBalances[userAddr] : _userWithdrawableStablecoinBalance(userAddr, asset);
        withdrawalRequestTimestamp = request.timestamp;
        withdrawalRequestAmount = request.amount;
    }

    function getPaymentStatus(uint256 tabId) external view returns (uint256 paid, bool remunerated, address asset) {
        PaymentStatus storage status = payments[tabId];
        paid = status.paid;
        remunerated = status.remunerated;
        asset = status.asset;
    }

    function getERC20Tokens() external view returns (address[] memory) {
        uint256 len = stablecoinAssetList.length;
        address[] memory tokens = new address[](len);
        for (uint256 i = 0; i < len; i++) {
            tokens[i] = stablecoinAssetList[i];
        }
        return tokens;
    }

    function principalBalance(address user, address asset) external view stablecoin(asset) returns (uint256) {
        return stablecoinPrincipalBalances[user][asset];
    }

    function guaranteeCapacity(address user, address asset) external view stablecoin(asset) returns (uint256) {
        return stablecoinPrincipalBalances[user][asset];
    }

    function grossYield(address user, address asset) external view stablecoin(asset) returns (uint256) {
        return _grossYield(user, asset);
    }

    function protocolYieldShare(address user, address asset) external view stablecoin(asset) returns (uint256) {
        return _protocolShareFromGross(_grossYield(user, asset));
    }

    function userNetYield(address user, address asset) external view stablecoin(asset) returns (uint256) {
        return _userNetYield(user, asset);
    }

    function withdrawableBalance(address user, address asset) external view supportedAsset(asset) returns (uint256) {
        return _availableBalance(user, asset);
    }

    function totalUserScaledBalance(address asset) external view stablecoin(asset) returns (uint256) {
        return totalUserScaledStablecoinBalances[asset];
    }

    function protocolScaledBalance(address asset) external view stablecoin(asset) returns (uint256) {
        return protocolScaledStablecoinBalances[asset];
    }

    function surplusScaledBalance(address asset) external view stablecoin(asset) returns (uint256) {
        return surplusScaledStablecoinBalances[asset];
    }

    function contractScaledATokenBalance(address asset) external view stablecoin(asset) returns (uint256) {
        return _scaledATokenBalance(asset);
    }

    function reconciliationDustToleranceScaled() external pure returns (uint256) {
        return RECONCILIATION_DUST_TOLERANCE_SCALED;
    }

    function stablecoinAToken(address asset) external view returns (address) {
        return stablecoinATokens[asset];
    }

    function verifyAndDecodeGuarantee(bytes memory guarantee, BLS.G2Point memory signature)
        public
        view
        returns (Guarantee memory)
    {
        (uint64 version, bytes memory encodedGuarantee) = abi.decode(guarantee, (uint64, bytes));
        VersionConfig storage config = guaranteeVersions[version];
        if (!config.enabled) revert UnsupportedGuaranteeVersion(version);

        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = negatedG1Generator;
        g1Points[1] = config.verificationKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = BLS.hashToG2(guarantee);

        if (!BLS.pairing(g1Points, g2Points)) revert InvalidSignature();

        Guarantee memory g;
        if (version == INITIAL_GUARANTEE_VERSION && config.decoder == address(0)) {
            g = abi.decode(encodedGuarantee, (Guarantee));
        } else {
            if (config.decoder == address(0)) {
                revert MissingGuaranteeDecoder(version);
            }
            g = IGuaranteeDecoder(config.decoder).decode(encodedGuarantee);
        }

        if (g.domain != config.domainSeparator) {
            revert InvalidGuaranteeDomain();
        }
        return g;
    }

    // ========= Fallbacks =========
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    fallback() external payable {
        revert DirectTransferNotAllowed();
    }

    function requireSupportedAsset(address asset) internal view returns (address) {
        if (isSupportedAsset(asset)) return asset;
        revert UnsupportedAsset(asset);
    }

    function isSupportedAsset(address asset) internal view returns (bool) {
        return asset == ETH_ASSET || stablecoinAssets[asset];
    }

    function isStablecoin(address asset) internal view returns (bool) {
        return stablecoinAssets[asset];
    }

    function _setStablecoinAsset(address asset, bool enabled) internal {
        if (asset == ETH_ASSET) revert InvalidAsset(asset);
        if (enabled && asset != usdc && asset != usdt) revert InvalidAsset(asset);

        bool current = stablecoinAssets[asset];
        if (current == enabled) return;

        stablecoinAssets[asset] = enabled;
        if (enabled) {
            stablecoinAssetIndexPlusOne[asset] = stablecoinAssetList.length + 1;
            stablecoinAssetList.push(asset);
        } else {
            uint256 indexPlusOne = stablecoinAssetIndexPlusOne[asset];
            if (indexPlusOne != 0) {
                uint256 index = indexPlusOne - 1;
                uint256 lastIndex = stablecoinAssetList.length - 1;
                if (index != lastIndex) {
                    address movedAsset = stablecoinAssetList[lastIndex];
                    stablecoinAssetList[index] = movedAsset;
                    stablecoinAssetIndexPlusOne[movedAsset] = index + 1;
                }
                stablecoinAssetList.pop();
                delete stablecoinAssetIndexPlusOne[asset];
            }
        }

        emit StablecoinAssetUpdated(asset, enabled);
    }

    function _aavePool() internal view returns (IAavePool pool) {
        IPoolAddressesProvider provider = aaveAddressesProvider;
        if (address(provider) == address(0)) revert AaveNotConfigured();
        address poolAddress = provider.getPool();
        if (poolAddress == address(0)) revert AaveNotConfigured();
        pool = IAavePool(poolAddress);
    }

    function _requireAToken(address asset) internal view returns (address aToken) {
        aToken = stablecoinATokens[asset];
        if (aToken == address(0)) revert AaveNotConfigured();
    }

    function _currentIndex(address asset) internal view returns (uint256) {
        return _aavePool().getReserveNormalizedIncome(asset);
    }

    function _toUnderlyingRoundDown(uint256 scaled, uint256 index) internal pure returns (uint256) {
        return Core4MicaAccounting.toUnderlyingRoundDown(scaled, index);
    }

    function _toScaledRoundDown(uint256 amount, uint256 index) internal pure returns (uint256) {
        return Core4MicaAccounting.toScaledRoundDown(amount, index);
    }

    function _toScaledRoundUp(uint256 amount, uint256 index) internal pure returns (uint256) {
        return Core4MicaAccounting.toScaledRoundUp(amount, index);
    }

    function _actualStablecoinBalance(address user, address asset) internal view returns (uint256) {
        return _toUnderlyingRoundDown(scaledStablecoinBalances[user][asset], _currentIndex(asset));
    }

    function _grossYield(address user, address asset) internal view returns (uint256) {
        uint256 actualBalance = _actualStablecoinBalance(user, asset);
        uint256 principal = stablecoinPrincipalBalances[user][asset];
        return actualBalance > principal ? actualBalance - principal : 0;
    }

    function _protocolShareFromGross(uint256 gross) internal view returns (uint256) {
        return Core4MicaAccounting.protocolShareFromGross(gross, yieldFeeBps);
    }

    function _netYieldFromGross(uint256 gross) internal view returns (uint256) {
        return Core4MicaAccounting.netYieldFromGross(gross, yieldFeeBps);
    }

    function _userNetYield(address user, address asset) internal view returns (uint256) {
        return _netYieldFromGross(_grossYield(user, asset));
    }

    function _userWithdrawableStablecoinBalance(address user, address asset) internal view returns (uint256) {
        return stablecoinPrincipalBalances[user][asset] + _userNetYield(user, asset);
    }

    function _availableBalance(address user, address asset) internal view returns (uint256) {
        if (asset == ETH_ASSET) {
            return ethCollateralBalances[user];
        }
        return _userWithdrawableStablecoinBalance(user, asset);
    }

    function _scaledATokenBalance(address asset) internal view returns (uint256) {
        address aToken = stablecoinATokens[asset];
        if (aToken == address(0)) return 0;
        return IAToken(aToken).scaledBalanceOf(address(this));
    }

    function _trackedScaledBalanceWithoutSurplus(address asset) internal view returns (uint256) {
        return totalUserScaledStablecoinBalances[asset] + protocolScaledStablecoinBalances[asset];
    }

    function _syncSurplusScaledBalance(address asset) internal {
        uint256 observed = _scaledATokenBalance(asset);
        uint256 trackedWithoutSurplus = _trackedScaledBalanceWithoutSurplus(asset);
        if (observed >= trackedWithoutSurplus) {
            surplusScaledStablecoinBalances[asset] = observed - trackedWithoutSurplus;
            return;
        }
        if (trackedWithoutSurplus - observed > RECONCILIATION_DUST_TOLERANCE_SCALED) {
            revert ReconciliationLoss(asset, trackedWithoutSurplus, observed);
        }
        surplusScaledStablecoinBalances[asset] = 0;
    }

    function _checkReconciliation(address asset) internal view {
        uint256 observed = _scaledATokenBalance(asset);
        uint256 tracked = totalUserScaledStablecoinBalances[asset] + protocolScaledStablecoinBalances[asset]
            + surplusScaledStablecoinBalances[asset];

        if (observed > tracked) {
            if (observed - tracked > RECONCILIATION_DUST_TOLERANCE_SCALED) {
                revert ReconciliationLoss(asset, tracked, observed);
            }
        } else if (tracked > observed && tracked - observed > RECONCILIATION_DUST_TOLERANCE_SCALED) {
            revert ReconciliationLoss(asset, tracked, observed);
        }
    }

    function _ensureDepositApproval(address asset, uint256 amount) internal {
        IERC20 token = IERC20(asset);
        address pool = address(_aavePool());
        if (approvedPoolForAsset[asset] == pool && token.allowance(address(this), pool) >= amount) {
            return;
        }

        address oldPool = approvedPoolForAsset[asset];
        if (oldPool != address(0) && oldPool != pool) {
            token.forceApprove(oldPool, 0);
        }
        token.forceApprove(pool, type(uint256).max);
        approvedPoolForAsset[asset] = pool;
    }

    function _syncWithdrawalRequestAfterStablecoinBalanceChange(address user, address asset) internal {
        WithdrawalRequest storage wr = withdrawalRequests[user][asset];
        if (wr.timestamp == 0) return;
        uint256 available = _userWithdrawableStablecoinBalance(user, asset);
        if (wr.amount > available) {
            wr.amount = available;
            if (available == 0) {
                delete withdrawalRequests[user][asset];
            }
        }
    }

    function _hasOpenStablecoinPositions() internal view returns (bool) {
        return totalUserScaledStablecoinBalances[usdc] != 0 || totalUserScaledStablecoinBalances[usdt] != 0
            || protocolScaledStablecoinBalances[usdc] != 0 || protocolScaledStablecoinBalances[usdt] != 0
            || surplusScaledStablecoinBalances[usdc] != 0 || surplusScaledStablecoinBalances[usdt] != 0;
    }

    function _grossForNetYield(uint256 desiredNet) internal view returns (uint256) {
        return Core4MicaAccounting.grossForNetYield(desiredNet, yieldFeeBps);
    }

    function _finalizeEthWithdrawal(address user, WithdrawalRequest memory request) internal {
        uint256 available = ethCollateralBalances[user];
        uint256 ethWithdrawalAmount = Math.min(available, request.amount);
        ethCollateralBalances[user] = available - ethWithdrawalAmount;
        delete withdrawalRequests[user][ETH_ASSET];

        (bool ok,) = payable(user).call{value: ethWithdrawalAmount}("");
        if (!ok) revert TransferFailed();
        emit CollateralWithdrawn(user, ETH_ASSET, ethWithdrawalAmount);
    }

    function _finalizeStablecoinWithdrawal(address user, address asset, WithdrawalRequest memory request) internal {
        uint256 principal = stablecoinPrincipalBalances[user][asset];
        uint256 gross = _grossYield(user, asset);
        uint256 userNet = _netYieldFromGross(gross);
        uint256 userWithdrawableBalance = principal + userNet;
        uint256 withdrawalAmount = Math.min(request.amount, userWithdrawableBalance);
        uint256 principalConsumed = Math.min(withdrawalAmount, principal);
        uint256 userYieldWithdrawn = withdrawalAmount - principalConsumed;
        uint256 remainingUserNet = userNet - userYieldWithdrawn;
        uint256 remainingGross = _grossForNetYield(remainingUserNet);
        uint256 protocolFeeReallocatedUnderlying = gross - userYieldWithdrawn - remainingGross;
        uint256 protocolScaledCredit = _toScaledRoundDown(protocolFeeReallocatedUnderlying, _currentIndex(asset));

        (uint256 scaledBurn, uint256 actualWithdrawn) = _withdrawStablecoinAndMeasureScaledBurn(asset, withdrawalAmount, user);
        if (actualWithdrawn < withdrawalAmount) {
            revert StablecoinWithdrawShortfall(asset, withdrawalAmount, actualWithdrawn);
        }

        uint256 userScaledDeduction = scaledBurn + protocolScaledCredit;
        uint256 userScaledBalance = scaledStablecoinBalances[user][asset];
        if (userScaledDeduction > userScaledBalance) {
            revert UserScaledBalanceUnderflow(asset, user, userScaledDeduction, userScaledBalance);
        }

        stablecoinPrincipalBalances[user][asset] = principal - principalConsumed;
        scaledStablecoinBalances[user][asset] = userScaledBalance - userScaledDeduction;
        totalUserScaledStablecoinBalances[asset] -= userScaledDeduction;
        protocolScaledStablecoinBalances[asset] += protocolScaledCredit;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        delete withdrawalRequests[user][asset];
        emit CollateralWithdrawn(user, asset, withdrawalAmount);
    }

    function _remunerateEth(Guarantee memory g, PaymentStatus storage status, uint256 remaining) internal {
        if (ethCollateralBalances[g.client] < remaining) revert DoubleSpendingDetected();
        ethCollateralBalances[g.client] -= remaining;
        status.remunerated = true;

        WithdrawalRequest storage ethRequest = withdrawalRequests[g.client][ETH_ASSET];
        if (ethRequest.timestamp != 0 && g.timestamp < ethRequest.timestamp + synchronizationDelay) {
            uint256 deduction = Math.min(ethRequest.amount, remaining);
            ethRequest.amount -= deduction;
        }

        (bool ok,) = payable(g.recipient).call{value: remaining}("");
        if (!ok) revert TransferFailed();
        emit RecipientRemunerated(g.tabId, ETH_ASSET, remaining);
    }

    function _remunerateStablecoin(Guarantee memory g, PaymentStatus storage status, address asset, uint256 remaining)
        internal
    {
        uint256 principal = stablecoinPrincipalBalances[g.client][asset];
        if (remaining > principal) revert DoubleSpendingDetected();

        (uint256 scaledBurn, uint256 actualWithdrawn) = _withdrawStablecoinAndMeasureScaledBurn(asset, remaining, g.recipient);
        if (actualWithdrawn < remaining) {
            revert StablecoinWithdrawShortfall(asset, remaining, actualWithdrawn);
        }

        uint256 userScaledBalance = scaledStablecoinBalances[g.client][asset];
        if (scaledBurn > userScaledBalance) {
            revert UserScaledBalanceUnderflow(asset, g.client, scaledBurn, userScaledBalance);
        }

        stablecoinPrincipalBalances[g.client][asset] = principal - remaining;
        scaledStablecoinBalances[g.client][asset] = userScaledBalance - scaledBurn;
        totalUserScaledStablecoinBalances[asset] -= scaledBurn;
        status.remunerated = true;

        WithdrawalRequest storage stablecoinRequest = withdrawalRequests[g.client][asset];
        if (stablecoinRequest.timestamp != 0 && g.timestamp < stablecoinRequest.timestamp + synchronizationDelay) {
            uint256 deduction = Math.min(stablecoinRequest.amount, remaining);
            stablecoinRequest.amount -= deduction;
        }

        _syncWithdrawalRequestAfterStablecoinBalanceChange(g.client, asset);
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        emit RecipientRemunerated(g.tabId, asset, remaining);
    }

    function _withdrawStablecoinAndMeasureScaledBurn(address asset, uint256 amount, address recipient)
        internal
        returns (uint256 scaledBurn, uint256 actualWithdrawn)
    {
        address aToken = _requireAToken(asset);
        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        actualWithdrawn = _aavePool().withdraw(asset, amount, recipient);
        uint256 scaledAfter = IAToken(aToken).scaledBalanceOf(address(this));
        scaledBurn = scaledBefore - scaledAfter;
    }
}
