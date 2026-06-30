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
    error GracePeriodBelowMinimum(uint256 provided, uint256 minimum);
    error MinGracePeriodExceedsGrace(uint256 minimum, uint256 gracePeriod);
    error NoWithdrawalRequested();
    error DirectTransferNotAllowed();
    error InvalidSignature();
    error InvalidRecipient();
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
    error EscrowScaledUnderflow(address asset, uint256 requested, uint256 available);
    error ZeroAddress();
    error InvalidAToken(address asset, address aToken);
    error ReconciliationLoss(address asset, uint256 tracked, uint256 observed);
    error SurplusClaimExceedsAvailable();
    error ValueMismatch(uint256 expected, uint256 actual);

    // ========= Storage =========
    /// @notice Delay between `requestWithdrawal` and `finalizeWithdrawal`.
    /// @dev This is the window the operator has to seize a defaulting user's collateral
    /// before it can leave. The operator is responsible for keeping it long enough
    /// to cover the off-chain settlement cycle's worst-case time-to-finality
    /// plus its seizure margin.
    uint256 public withdrawalGracePeriod = 22 days;

    /// @notice On-chain floor for `withdrawalGracePeriod`; `setWithdrawalGracePeriod` cannot go
    /// below it. Deployments should set this to at least the worst-case cycle time-to-finality
    /// plus seizure margin so a governance action can never shorten the seizure window below
    /// what settlement needs. Defaults to 0 (no floor) until configured.
    uint256 public minWithdrawalGracePeriod;

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
    mapping(address => bool) private stablecoinAssets;
    address[] private stablecoinAssetList;
    mapping(address => uint256) private stablecoinAssetIndexPlusOne;

    IPoolAddressesProvider public aaveAddressesProvider;
    uint256 public yieldFeeBps;
    mapping(address => address) internal stablecoinATokens;
    mapping(address => address) internal approvedPoolForAsset;
    mapping(address => mapping(address => uint256)) internal scaledStablecoinBalances;
    mapping(address => mapping(address => uint256)) internal stablecoinPrincipalBalances;
    mapping(address => uint256) internal protocolScaledStablecoinBalances;
    mapping(address => uint256) internal totalUserScaledStablecoinBalances;
    mapping(address => uint256) internal surplusScaledStablecoinBalances;
    /// Scaled aToken balance seized from defaulters (or paid in) and held for settlement,
    /// owned by the ClearingHouse. Held in scaled form so settlement never depends on
    /// instantaneous Aave liquidity; converted to underlying lazily at
    /// creditor cash-out. Backed by this contract's aToken position, so it is part of the
    /// reconciliation total alongside user, protocol, and surplus balances.
    mapping(address => uint256) internal escrowScaledStablecoinBalances;
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
        // Grace period in effect when the request was made, snapshotted so a later
        // setWithdrawalGracePeriod reduction cannot retroactively shorten in-flight requests.
        uint256 gracePeriod;
    }

    struct UserAssetInfo {
        address asset;
        uint256 collateral;
        uint256 withdrawalRequestTimestamp;
        uint256 withdrawalRequestAmount;
    }

    mapping(address => mapping(address => WithdrawalRequest)) public withdrawalRequests;

    // ========= Events =========
    event CollateralDeposited(address indexed user, address indexed asset, uint256 amount);
    event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);
    event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);
    event WithdrawalCanceled(address indexed user, address indexed asset);
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
    event MinWithdrawalGracePeriodUpdated(uint256 newMinGracePeriod);
    event VerificationKeyUpdated(BLS.G1Point newVerificationKey);
    event GuaranteeVersionUpdated(
        uint64 indexed version, BLS.G1Point verificationKey, bytes32 domainSeparator, address decoder, bool enabled
    );
    event StablecoinAssetUpdated(address indexed asset, bool enabled);
    event AaveConfigured(address indexed provider, address indexed pool);
    event YieldFeeBpsUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event ProtocolYieldClaimed(address indexed asset, address indexed to, uint256 amount);
    event SurplusATokensClaimed(address indexed asset, address indexed to, uint256 scaledAmount, uint256 nominalAmount);
    /// Seized debtor collateral during settlement. For stablecoins `scaledToEscrow` is the scaled aToken
    /// amount moved into the settlement escrow; for ETH it is 0.
    event CollateralSeized(address indexed debtor, address indexed asset, uint256 amount, uint256 scaledToEscrow);
    /// Escrowed stablecoin collateral re-attributed to a creditor (no Aave round trip).
    event EscrowCredited(address indexed creditor, address indexed asset, uint256 amount, uint256 scaledFromEscrow);
    /// Escrowed stablecoin collateral converted to underlying via Aave and paid out.
    event EscrowWithdrawn(address indexed asset, address indexed recipient, uint256 amount, uint256 scaledBurned);
    /// Debtor's paid-in stablecoin supplied to Aave and held in the settlement escrow.
    event EscrowDeposited(address indexed asset, address indexed from, uint256 amount, uint256 scaledCredited);

    // ========= Constructor =========
    constructor(
        address manager,
        BLS.G1Point memory verificationKey,
        address[] memory stablecoins_,
        uint256 minGracePeriod_
    ) AccessManaged(manager) {
        if (stablecoins_.length == 0) revert AmountZero();
        // Set the withdrawal-grace floor atomically at deploy so it can never be left at 0 by a
        // forgotten setter call. May be 0 only for explicit opt-out (e.g. tests); production
        // deploys pass a non-zero value (enforced by the deploy script). Must not exceed the
        // initial grace period so withdrawalGracePeriod >= minWithdrawalGracePeriod always holds.
        if (minGracePeriod_ > withdrawalGracePeriod) {
            revert MinGracePeriodExceedsGrace(minGracePeriod_, withdrawalGracePeriod);
        }
        minWithdrawalGracePeriod = minGracePeriod_;
        emit MinWithdrawalGracePeriodUpdated(minGracePeriod_);
        for (uint256 i = 0; i < stablecoins_.length; i++) {
            _addStablecoinAsset(stablecoins_[i]);
        }
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

    function setWithdrawalGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        if (_gracePeriod < minWithdrawalGracePeriod) {
            revert GracePeriodBelowMinimum(_gracePeriod, minWithdrawalGracePeriod);
        }
        withdrawalGracePeriod = _gracePeriod;
        emit WithdrawalGracePeriodUpdated(_gracePeriod);
    }

    /// Set the on-chain floor for `withdrawalGracePeriod`. Cannot exceed the current grace period
    /// (raise the grace first), keeping `withdrawalGracePeriod >= minWithdrawalGracePeriod` always.
    function setMinWithdrawalGracePeriod(uint256 _minGracePeriod) external restricted {
        if (_minGracePeriod > withdrawalGracePeriod) {
            revert MinGracePeriodExceedsGrace(_minGracePeriod, withdrawalGracePeriod);
        }
        minWithdrawalGracePeriod = _minGracePeriod;
        emit MinWithdrawalGracePeriodUpdated(_minGracePeriod);
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

    function configureAave(address poolAddressesProvider, address[] calldata aTokens) external restricted {
        if (poolAddressesProvider == address(0)) {
            revert ZeroAddress();
        }
        if (aTokens.length != stablecoinAssetList.length || aTokens.length == 0) revert InvalidAsset(address(0));
        if (_hasOpenStablecoinPositions()) revert AaveProviderReconfigurationBlocked();

        IPoolAddressesProvider provider = IPoolAddressesProvider(poolAddressesProvider);
        address pool = provider.getPool();
        address dataProvider = provider.getPoolDataProvider();
        if (pool == address(0) || dataProvider == address(0)) revert ZeroAddress();

        aaveAddressesProvider = provider;
        for (uint256 i = 0; i < stablecoinAssetList.length; i++) {
            address asset = stablecoinAssetList[i];
            address aToken = aTokens[i];
            _validateAToken(dataProvider, asset, aToken);

            stablecoinATokens[asset] = aToken;
            approvedPoolForAsset[asset] = address(0);
        }
        emit AaveConfigured(poolAddressesProvider, pool);
    }

    function addStablecoinAsset(address asset, address aToken) external restricted {
        _requireNewStablecoinAsset(asset);

        IPoolAddressesProvider provider = aaveAddressesProvider;
        if (address(provider) == address(0)) revert AaveNotConfigured();

        address dataProvider = provider.getPoolDataProvider();
        if (provider.getPool() == address(0) || dataProvider == address(0)) revert AaveNotConfigured();

        _validateAToken(dataProvider, asset, aToken);
        _addStablecoinAsset(asset);
        stablecoinATokens[asset] = aToken;
        approvedPoolForAsset[asset] = address(0);
    }

    function setYieldFeeBps(uint256 feeBps) external restricted {
        if (feeBps > MAX_YIELD_FEE_BPS) revert FeeTooHigh();
        uint256 oldFee = yieldFeeBps;
        yieldFeeBps = feeBps;
        emit YieldFeeBpsUpdated(oldFee, feeBps);
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
        _creditUserStablecoin(msg.sender, asset, amount, msg.sender);
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

        withdrawalRequests[user][asset] =
            WithdrawalRequest({timestamp: block.timestamp, amount: amount, gracePeriod: withdrawalGracePeriod});
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
        // Use the grace period snapshotted at request time, not the current global value, so a
        // reduction applies only to new requests and never shortens an in-flight one.
        if (block.timestamp < request.timestamp + request.gracePeriod) {
            revert GracePeriodNotElapsed();
        }

        if (asset == ETH_ASSET) {
            _finalizeEthWithdrawal(user, request);
            return;
        }

        _finalizeStablecoinWithdrawal(user, asset, request);
    }

    // ========= Settlement (ClearingHouse) =========
    /// Seize `amount` of a defaulting debtor's collateral. For ETH the underlying is routed
    /// to the caller; for stablecoins the seized scaled position is moved into the settlement
    /// escrow (no Aave withdrawal) and converted to underlying lazily at cash-out.
    /// Restricted to the ClearingHouse via the AccessManager. Reverts if the debtor's
    /// withdrawable balance is insufficient so a batch caller can skip the entry.
    /// Returns the underlying-equivalent seized.
    function seizeCollateral(address debtor, address asset, uint256 amount)
        external
        restricted
        nonReentrant
        whenNotPaused
        supportedAsset(asset)
        nonZero(amount)
        returns (uint256 seized)
    {
        if (asset == ETH_ASSET) {
            if (amount > ethCollateralBalances[debtor]) revert InsufficientAvailable();
            _seizeEth(debtor, amount);
            seized = amount;
        } else {
            if (amount > _userWithdrawableStablecoinBalance(debtor, asset)) revert InsufficientAvailable();
            // Re-attribute the debtor's scaled position into escrow rather than withdrawing
            // underlying from Aave, so the seizure cannot revert on Aave illiquidity.
            // Conversion to underlying happens lazily at creditor cash-out. The stablecoin path
            // emits CollateralSeized itself (it has the scaled-to-escrow amount).
            seized = _seizeStablecoinToEscrow(debtor, asset, amount, false);
        }
    }

    /// Seize up to `amount` of a defaulting debtor's collateral, recovering whatever is
    /// available without reverting on a shortfall. Lets settlement always resolve an
    /// under-collateralised debtor so the cycle can reach a terminal state rather than wedging.
    /// Returns the underlying-equivalent actually seized (possibly < `amount`, or zero).
    /// Restricted to the ClearingHouse.
    function seizeUpTo(address debtor, address asset, uint256 amount)
        external
        restricted
        nonReentrant
        whenNotPaused
        supportedAsset(asset)
        returns (uint256 seized)
    {
        if (asset == ETH_ASSET) {
            uint256 take = Math.min(amount, ethCollateralBalances[debtor]);
            if (take == 0) return 0;
            _seizeEth(debtor, take);
            seized = take;
        } else {
            uint256 take = Math.min(amount, _userWithdrawableStablecoinBalance(debtor, asset));
            if (take == 0) return 0;
            // Stablecoin path emits CollateralSeized itself.
            seized = _seizeStablecoinToEscrow(debtor, asset, take, true);
        }
    }

    /// @dev Debit `amount` of `debtor`'s ETH collateral and forward it to the caller (the
    /// ClearingHouse). Caller must ensure `amount <= ethCollateralBalances[debtor]`. Shared by
    /// `seizeCollateral` (revert-on-shortfall) and `seizeUpTo` (clamp-to-available).
    function _seizeEth(address debtor, uint256 amount) internal {
        ethCollateralBalances[debtor] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit CollateralSeized(debtor, ETH_ASSET, amount, 0);
    }

    /// Credit `amount` of `asset` to a creditor's collateral, funded by the caller
    /// Restricted to the ClearingHouse via the AccessManager. For ETH the caller must
    /// forward `amount` as `msg.value`; for stablecoins the caller must have approved this
    /// contract to pull `amount` of the underlying.
    function creditCollateral(address creditor, address asset, uint256 amount)
        external
        payable
        restricted
        nonReentrant
        whenNotPaused
        supportedAsset(asset)
        validRecipient(creditor)
        nonZero(amount)
    {
        if (asset == ETH_ASSET) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
            ethCollateralBalances[creditor] += amount;
        } else {
            if (msg.value != 0) revert ValueMismatch(0, msg.value);
            _creditUserStablecoin(creditor, asset, amount, msg.sender);
        }
    }

    /// Credit `amount` (underlying-equivalent) of seized/escrowed stablecoin collateral to a
    /// creditor by re-attributing scaled aTokens from the settlement escrow, with no Aave
    /// interaction. Used to make creditors whole in collateral form without a withdraw/supply
    /// round trip. Restricted to the ClearingHouse.
    function creditFromEscrowScaled(address creditor, address asset, uint256 amount)
        external
        restricted
        nonReentrant
        whenNotPaused
        stablecoin(asset)
        validRecipient(creditor)
        nonZero(amount)
    {
        uint256 scaledAmount = _toScaledRoundDown(amount, _currentIndex(asset));
        uint256 escrowScaled = escrowScaledStablecoinBalances[asset];
        if (scaledAmount > escrowScaled) revert EscrowScaledUnderflow(asset, scaledAmount, escrowScaled);

        // Mirror deposit accounting: principal records the credited amount, scaled is the
        // round-down equivalent, so the creditor's position is identical to a fresh deposit.
        escrowScaledStablecoinBalances[asset] = escrowScaled - scaledAmount;
        scaledStablecoinBalances[creditor][asset] += scaledAmount;
        totalUserScaledStablecoinBalances[asset] += scaledAmount;
        stablecoinPrincipalBalances[creditor][asset] += amount;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        emit EscrowCredited(creditor, asset, amount, scaledAmount);
    }

    /// Convert up to `amount` of escrowed stablecoin collateral to underlying via Aave and
    /// send it to `recipient`. Partial-fill tolerant: returns the amount actually withdrawn
    /// (which may be less than `amount` if Aave liquidity is short). Never reverts on an Aave
    /// liquidity shortfall, so an individual cash-out can be retried without wedging the cycle
    /// (it can still revert on an escrow underflow or reconciliation failure). Restricted to the
    /// ClearingHouse.
    function withdrawFromEscrow(address asset, uint256 amount, address recipient)
        external
        restricted
        nonReentrant
        whenNotPaused
        stablecoin(asset)
        validRecipient(recipient)
        nonZero(amount)
        returns (uint256 actualWithdrawn)
    {
        address aToken = _requireAToken(asset);
        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        actualWithdrawn = _aavePool().withdraw(asset, amount, recipient);
        uint256 scaledBurn = scaledBefore - IAToken(aToken).scaledBalanceOf(address(this));

        uint256 escrowScaled = escrowScaledStablecoinBalances[asset];
        if (scaledBurn > escrowScaled) revert EscrowScaledUnderflow(asset, scaledBurn, escrowScaled);
        escrowScaledStablecoinBalances[asset] = escrowScaled - scaledBurn;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        emit EscrowWithdrawn(asset, recipient, actualWithdrawn, scaledBurn);
    }

    /// Pull `amount` of `asset` from the caller, supply it into Aave, and hold it in the
    /// settlement escrow as scaled aTokens. Used to route debtors' paid-in funds into the
    /// same escrow as seized collateral, so the entire settlement pool is liquidity-free
    /// scaled value. Restricted to the ClearingHouse.
    function depositToEscrow(address asset, uint256 amount)
        external
        restricted
        nonReentrant
        whenNotPaused
        stablecoin(asset)
        nonZero(amount)
    {
        address aToken = _requireAToken(asset);
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);

        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        _ensureDepositApproval(asset, amount);
        _aavePool().supply(asset, amount, address(this), 0);
        uint256 scaledCredit = IAToken(aToken).scaledBalanceOf(address(this)) - scaledBefore;

        escrowScaledStablecoinBalances[asset] += scaledCredit;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
        emit EscrowDeposited(asset, msg.sender, amount, scaledCredit);
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
        assetCollateral =
            asset == ETH_ASSET ? ethCollateralBalances[userAddr] : _userWithdrawableStablecoinBalance(userAddr, asset);
        withdrawalRequestTimestamp = request.timestamp;
        withdrawalRequestAmount = request.amount;
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

    function escrowScaledBalance(address asset) external view stablecoin(asset) returns (uint256) {
        return escrowScaledStablecoinBalances[asset];
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

    function isSupportedAsset(address asset) internal view returns (bool) {
        return asset == ETH_ASSET || stablecoinAssets[asset];
    }

    function isStablecoin(address asset) internal view returns (bool) {
        return stablecoinAssets[asset];
    }

    function _requireNewStablecoinAsset(address asset) internal view {
        if (asset == ETH_ASSET) revert InvalidAsset(asset);
        if (asset == address(0)) revert ZeroAddress();
        if (stablecoinAssets[asset]) revert InvalidAsset(asset);
    }

    function _addStablecoinAsset(address asset) internal {
        _requireNewStablecoinAsset(asset);

        stablecoinAssets[asset] = true;
        stablecoinAssetIndexPlusOne[asset] = stablecoinAssetList.length + 1;
        stablecoinAssetList.push(asset);
        emit StablecoinAssetUpdated(asset, true);
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
        if (address(aaveAddressesProvider) == address(0) || stablecoinATokens[asset] == address(0)) {
            return Core4MicaAccounting.RAY;
        }

        address poolAddress = aaveAddressesProvider.getPool();
        if (poolAddress == address(0)) {
            return Core4MicaAccounting.RAY;
        }

        return IAavePool(poolAddress).getReserveNormalizedIncome(asset);
    }

    function _validateAToken(address dataProvider, address asset, address aToken) internal view {
        if (aToken == address(0)) revert ZeroAddress();

        address underlyingAsset = IAToken(aToken).UNDERLYING_ASSET_ADDRESS();
        if (underlyingAsset != asset) revert InvalidAToken(asset, aToken);

        (address configuredAToken,,) = IAaveProtocolDataProvider(dataProvider).getReserveTokensAddresses(asset);
        if (configuredAToken != aToken) revert InvalidAToken(asset, aToken);
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
        return totalUserScaledStablecoinBalances[asset] + protocolScaledStablecoinBalances[asset]
            + escrowScaledStablecoinBalances[asset];
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
            + escrowScaledStablecoinBalances[asset] + surplusScaledStablecoinBalances[asset];

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

    function _hasOpenStablecoinPositions() internal view returns (bool) {
        uint256 len = stablecoinAssetList.length;
        for (uint256 i = 0; i < len; i++) {
            address asset = stablecoinAssetList[i];
            if (
                totalUserScaledStablecoinBalances[asset] != 0 || protocolScaledStablecoinBalances[asset] != 0
                    || escrowScaledStablecoinBalances[asset] != 0 || surplusScaledStablecoinBalances[asset] != 0
            ) {
                return true;
            }
        }
        return false;
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
        uint256 withdrawalAmount = Math.min(request.amount, _userWithdrawableStablecoinBalance(user, asset));
        _debitUserStablecoin(user, asset, withdrawalAmount, user);
        delete withdrawalRequests[user][asset];
        emit CollateralWithdrawn(user, asset, withdrawalAmount);
    }

    /// Debits `amount` of `user`'s withdrawable stablecoin balance, routing the
    /// underlying to `recipient`, and keeps the scaled / principal / protocol-fee
    /// accounting and reconciliation invariants consistent. `amount` must not exceed
    /// the user's withdrawable balance. Returns the underlying actually withdrawn.
    /// @dev Shared accounting for both stablecoin debit paths (user withdrawal and seizure):
    /// for a debit of `amount` underlying, returns how much principal it consumes and the scaled
    /// protocol-fee slice to reallocate from the user to the protocol pool. View-only — no state
    /// writes, no Aave interaction. Keeps the 4MCA-H03 fee math in one place so a fix can never
    /// land in only one caller.
    function _planStablecoinDebit(address user, address asset, uint256 amount, uint256 index)
        internal
        view
        returns (uint256 principalConsumed, uint256 protocolScaledCredit)
    {
        uint256 gross = _grossYield(user, asset);
        uint256 userNet = _netYieldFromGross(gross);
        principalConsumed = Math.min(amount, stablecoinPrincipalBalances[user][asset]);
        uint256 userYieldWithdrawn = amount - principalConsumed;
        uint256 remainingGross = _grossForNetYield(userNet - userYieldWithdrawn);
        uint256 grossAfterUserWithdrawal = gross - userYieldWithdrawn;
        // Saturating subtraction: _grossForNetYield returns the smallest preimage, so
        // remainingGross can never exceed grossAfterUserWithdrawal; the clamp guards a rounding
        // edge so the call can never underflow and revert a seizure or partial withdrawal. Any
        // under-charge is at most one unit, in the user's favour (4MCA-H03).
        uint256 protocolFeeReallocatedUnderlying =
            grossAfterUserWithdrawal > remainingGross ? grossAfterUserWithdrawal - remainingGross : 0;
        protocolScaledCredit = _toScaledRoundDown(protocolFeeReallocatedUnderlying, index);
    }

    /// @dev Applies the user-side burn shared by both debit paths: removes `principalConsumed`
    /// principal and `userScaledDeduction` scaled aTokens from the user, reverting on a scaled
    /// underflow. The caller routes the seized/withdrawn scaled value and credits the protocol fee.
    function _applyUserStablecoinDeduction(
        address user,
        address asset,
        uint256 principalConsumed,
        uint256 userScaledDeduction
    ) internal {
        uint256 userScaledBalance = scaledStablecoinBalances[user][asset];
        if (userScaledDeduction > userScaledBalance) {
            revert UserScaledBalanceUnderflow(asset, user, userScaledDeduction, userScaledBalance);
        }
        stablecoinPrincipalBalances[user][asset] -= principalConsumed;
        scaledStablecoinBalances[user][asset] = userScaledBalance - userScaledDeduction;
        totalUserScaledStablecoinBalances[asset] -= userScaledDeduction;
    }

    function _debitUserStablecoin(address user, address asset, uint256 amount, address recipient)
        internal
        returns (uint256 withdrawalAmount)
    {
        withdrawalAmount = amount;
        uint256 index = _currentIndex(asset);
        (uint256 principalConsumed, uint256 protocolScaledCredit) =
            _planStablecoinDebit(user, asset, withdrawalAmount, index);

        (uint256 scaledBurn, uint256 actualWithdrawn) =
            _withdrawStablecoinAndMeasureScaledBurn(asset, withdrawalAmount, recipient);
        if (actualWithdrawn < withdrawalAmount) {
            revert StablecoinWithdrawShortfall(asset, withdrawalAmount, actualWithdrawn);
        }

        _applyUserStablecoinDeduction(user, asset, principalConsumed, scaledBurn + protocolScaledCredit);
        protocolScaledStablecoinBalances[asset] += protocolScaledCredit;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);
    }

    /// Seizes `amount` of `user`'s withdrawable stablecoin balance into the settlement
    /// escrow, mirroring [`_debitUserStablecoin`]'s scaled / principal / protocol-fee
    /// accounting (via [`_planStablecoinDebit`]) but WITHOUT touching Aave: the seized value is
    /// re-attributed as scaled aTokens to the escrow rather than withdrawn to underlying, so a
    /// seizure never depends on instantaneous Aave liquidity. `amount` must not exceed the user's
    /// withdrawable balance. Returns the underlying-equivalent seized into escrow.
    function _seizeStablecoinToEscrow(address user, address asset, uint256 amount, bool bestEffort)
        internal
        returns (uint256 seizedUnderlying)
    {
        uint256 index = _currentIndex(asset);
        (uint256 principalConsumed, uint256 protocolScaledCredit) = _planStablecoinDebit(user, asset, amount, index);

        // Round the seized scaled amount UP, matching the burn Aave would perform on a real
        // withdrawal, so the escrow holds at least `amount` of underlying value.
        uint256 scaledSeized = _toScaledRoundUp(amount, index);
        seizedUnderlying = amount;

        // A scaled position can back up to ~1 base unit less than its recorded principal: Aave mints
        // scaled by rounding `amount / index` DOWN at deposit, while principal is stored at face
        // value and the withdrawable bound floors net yield at 0 rather than below principal. In that
        // dust edge `scaledSeized` (rounded UP) exceeds the user's scaled balance, so the deduction
        // would underflow and revert. On the best-effort path (`seizeUpTo`) a revert would leave the
        // debtor unresolved and wedge the whole cycle, so instead seize the entire position and
        // report what it truly backs; the <=1-unit remainder is borne by creditors via the terminal
        // Shortfall state. The strict path (`seizeCollateral`) keeps its revert-on-shortfall contract.
        if (bestEffort) {
            uint256 userScaled = scaledStablecoinBalances[user][asset];
            if (scaledSeized + protocolScaledCredit > userScaled) {
                scaledSeized = userScaled;
                protocolScaledCredit = 0; // no yield to skim when the position backs < principal
                principalConsumed = stablecoinPrincipalBalances[user][asset];
                seizedUnderlying = _toUnderlyingRoundDown(scaledSeized, index);
            }
        }

        _applyUserStablecoinDeduction(user, asset, principalConsumed, scaledSeized + protocolScaledCredit);
        escrowScaledStablecoinBalances[asset] += scaledSeized;
        protocolScaledStablecoinBalances[asset] += protocolScaledCredit;
        _syncSurplusScaledBalance(asset);
        _checkReconciliation(asset);

        emit CollateralSeized(user, asset, seizedUnderlying, scaledSeized);
    }

    /// Supplies `amount` of `asset` (pulled from `from`) into Aave and credits it to
    /// `user`'s collateral, mirroring [`depositStablecoin`] accounting.
    function _creditUserStablecoin(address user, address asset, uint256 amount, address from) internal {
        address aToken = _requireAToken(asset);
        IERC20(asset).safeTransferFrom(from, address(this), amount);

        uint256 scaledBefore = IAToken(aToken).scaledBalanceOf(address(this));
        _ensureDepositApproval(asset, amount);
        _aavePool().supply(asset, amount, address(this), 0);
        uint256 scaledAfter = IAToken(aToken).scaledBalanceOf(address(this));
        uint256 scaledCredit = scaledAfter - scaledBefore;

        scaledStablecoinBalances[user][asset] += scaledCredit;
        totalUserScaledStablecoinBalances[asset] += scaledCredit;
        stablecoinPrincipalBalances[user][asset] += amount;
        _syncSurplusScaledBalance(asset);
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
