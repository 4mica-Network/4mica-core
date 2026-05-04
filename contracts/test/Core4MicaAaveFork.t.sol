// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";
import {Core4Mica, Guarantee} from "../src/Core4Mica.sol";
import {IPoolAddressesProvider} from "../src/interfaces/IPoolAddressesProvider.sol";
import {IAaveProtocolDataProvider} from "../src/interfaces/IAaveProtocolDataProvider.sol";
import {IAToken} from "../src/interfaces/IAToken.sol";

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
}

contract Core4MicaAaveForkTest is Test {
    using SafeERC20 for IERC20;

    uint64 internal constant GOVERNANCE_ROLE = 1;

    address internal constant USER1 = address(0x111);
    address internal constant USER2 = address(0x222);

    bytes32 internal constant TEST_PRIVATE_KEY =
        bytes32(0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3);

    string internal forkRpcUrl;
    address internal providerAddress;
    address[2] internal stablecoins;
    address[2] internal aTokens;
    bool internal forkConfigured;

    AccessManager internal manager;
    Core4Mica internal core4Mica;
    BLS.G1Point internal testPublicKey;

    modifier onlyIfForkConfigured() {
        if (!forkConfigured) return;
        _;
    }

    function setUp() public {
        forkRpcUrl = vm.envOr("AAVE_FORK_RPC_URL", string(""));
        providerAddress = vm.envOr("AAVE_FORK_PROVIDER", address(0));
        stablecoins[0] = vm.envOr("AAVE_FORK_STABLECOIN_0", address(0));
        stablecoins[1] = vm.envOr("AAVE_FORK_STABLECOIN_1", address(0));
        aTokens[0] = vm.envOr("AAVE_FORK_STABLECOIN_ATOKEN_0", address(0));
        aTokens[1] = vm.envOr("AAVE_FORK_STABLECOIN_ATOKEN_1", address(0));

        forkConfigured = bytes(forkRpcUrl).length != 0 && providerAddress != address(0) && stablecoins[0] != address(0)
            && stablecoins[1] != address(0) && aTokens[0] != address(0) && aTokens[1] != address(0);
        if (!forkConfigured) {
            return;
        }

        vm.createSelectFork(forkRpcUrl);

        manager = new AccessManager(address(this));
        testPublicKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);

        address[] memory supportedStablecoins = new address[](2);
        supportedStablecoins[0] = stablecoins[0];
        supportedStablecoins[1] = stablecoins[1];
        core4Mica = new Core4Mica(address(manager), testPublicKey, supportedStablecoins);

        _grantGovernance(Core4Mica.configureAave.selector);
        _grantGovernance(Core4Mica.setYieldFeeBps.selector);
        _grantGovernance(Core4Mica.claimProtocolYield.selector);
        _grantGovernance(Core4Mica.claimSurplusATokens.selector);
        _grantGovernance(Core4Mica.setTimingParameters.selector);

        address[] memory configuredATokens = new address[](2);
        configuredATokens[0] = aTokens[0];
        configuredATokens[1] = aTokens[1];
        core4Mica.configureAave(providerAddress, configuredATokens);

        core4Mica.setTimingParameters(1 hours, 2 hours, 1 hours, 4 hours);

        _fundAndApprove(USER1, stablecoins[0], _depositAmount(stablecoins[0]) * 3);
        _fundAndApprove(USER1, stablecoins[1], _depositAmount(stablecoins[1]) * 3);
    }

    function testFork_ConfigureAave_UsesLiveProviderAndReserveMembership() public onlyIfForkConfigured {
        IPoolAddressesProvider provider = IPoolAddressesProvider(providerAddress);
        address livePool = provider.getPool();
        address liveDataProvider = provider.getPoolDataProvider();

        assertEq(address(core4Mica.aaveAddressesProvider()), providerAddress);
        assertTrue(livePool != address(0));
        assertTrue(liveDataProvider != address(0));

        for (uint256 i = 0; i < stablecoins.length; i++) {
            assertEq(core4Mica.stablecoinAToken(stablecoins[i]), aTokens[i]);
            assertEq(IAToken(aTokens[i]).UNDERLYING_ASSET_ADDRESS(), stablecoins[i]);
            (address configuredAToken,,) =
                IAaveProtocolDataProvider(liveDataProvider).getReserveTokensAddresses(stablecoins[i]);
            assertEq(configuredAToken, aTokens[i]);
        }
    }

    function testFork_DepositAndFinalizeWithdrawal_UsesRealAavePool() public onlyIfForkConfigured {
        uint256 depositAmount = _depositAmount(stablecoins[0]);
        uint256 userBalanceBefore = IERC20(stablecoins[0]).balanceOf(USER1);

        vm.prank(USER1);
        core4Mica.depositStablecoin(stablecoins[0], depositAmount);

        assertEq(core4Mica.principalBalance(USER1, stablecoins[0]), depositAmount);
        assertGt(core4Mica.totalUserScaledBalance(stablecoins[0]), 0);
        assertGt(core4Mica.contractScaledATokenBalance(stablecoins[0]), 0);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(stablecoins[0], depositAmount);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(stablecoins[0]);

        assertEq(core4Mica.principalBalance(USER1, stablecoins[0]), 0);
        assertEq(core4Mica.totalUserScaledBalance(stablecoins[0]), 0);
        assertGe(IERC20(stablecoins[0]).balanceOf(USER1), userBalanceBefore);
    }

    function testFork_Remunerate_WithdrawsUnderlyingFromRealAavePool() public onlyIfForkConfigured {
        uint256 depositAmount = _depositAmount(stablecoins[0]);
        uint256 remuneratedAmount = depositAmount / 2;

        vm.prank(USER1);
        core4Mica.depositStablecoin(stablecoins[0], depositAmount);

        uint256 tabTimestamp = block.timestamp;
        Guarantee memory g = _guarantee(0xABCD, tabTimestamp, USER1, USER2, 1, remuneratedAmount, stablecoins[0]);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 1);

        uint256 recipientBalanceBefore = IERC20(stablecoins[0]).balanceOf(USER2);
        vm.prank(USER2);
        core4Mica.remunerate(_encodeGuaranteeWithVersion(g), signature);

        assertEq(IERC20(stablecoins[0]).balanceOf(USER2), recipientBalanceBefore + remuneratedAmount);
        assertEq(core4Mica.principalBalance(USER1, stablecoins[0]), depositAmount - remuneratedAmount);
    }

    function testFork_ClaimProtocolYield_AfterLiveIndexAccrual() public onlyIfForkConfigured {
        uint256 depositAmount = _largeDepositAmount(stablecoins[0]);

        vm.prank(USER1);
        core4Mica.depositStablecoin(stablecoins[0], depositAmount);

        core4Mica.setYieldFeeBps(2_000);

        // On a fork, normalized income can advance with time against the live reserve parameters.
        vm.warp(block.timestamp + 30 days);

        uint256 withdrawable = core4Mica.withdrawableBalance(USER1, stablecoins[0]);
        if (withdrawable <= depositAmount) {
            return;
        }

        vm.prank(USER1);
        core4Mica.requestWithdrawal(stablecoins[0], withdrawable);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(stablecoins[0]);

        uint256 protocolScaled = core4Mica.protocolScaledBalance(stablecoins[0]);
        if (protocolScaled == 0) {
            return;
        }

        uint256 treasuryBalanceBefore = IERC20(stablecoins[0]).balanceOf(USER2);
        core4Mica.claimProtocolYield(stablecoins[0], USER2, type(uint256).max);

        assertGt(IERC20(stablecoins[0]).balanceOf(USER2), treasuryBalanceBefore);
        assertEq(core4Mica.protocolScaledBalance(stablecoins[0]), 0);
    }

    function testFork_RepeatedPartialWithdrawals_ReconcileWithinDustTolerance() public onlyIfForkConfigured {
        address asset = stablecoins[0];
        uint256 depositAmount = _largeDepositAmount(asset);

        vm.prank(USER1);
        core4Mica.depositStablecoin(asset, depositAmount);

        core4Mica.setYieldFeeBps(2_000);
        _assertScaledReconciliationWithinTolerance(asset);

        vm.warp(block.timestamp + 30 days);

        uint256 firstWithdraw = depositAmount / 2;
        vm.prank(USER1);
        core4Mica.requestWithdrawal(asset, firstWithdraw);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(asset);
        _assertScaledReconciliationWithinTolerance(asset);

        vm.warp(block.timestamp + 30 days);

        uint256 secondWithdraw = core4Mica.withdrawableBalance(USER1, asset) / 2;
        if (secondWithdraw == 0) {
            return;
        }

        vm.prank(USER1);
        core4Mica.requestWithdrawal(asset, secondWithdraw);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(asset);
        _assertScaledReconciliationWithinTolerance(asset);
    }

    function testFork_RemunerationWithdrawalAndTreasuryClaim_ReconcileWithinDustTolerance()
        public
        onlyIfForkConfigured
    {
        address asset = stablecoins[0];
        uint256 depositAmount = _largeDepositAmount(asset);
        uint256 remuneratedAmount = depositAmount / 4;

        vm.prank(USER1);
        core4Mica.depositStablecoin(asset, depositAmount);

        core4Mica.setYieldFeeBps(2_000);
        _assertScaledReconciliationWithinTolerance(asset);

        vm.warp(block.timestamp + 30 days);

        uint256 tabTimestamp = block.timestamp;
        Guarantee memory g = _guarantee(0xDCBA, tabTimestamp, USER1, USER2, 2, remuneratedAmount, asset);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 1);
        vm.prank(USER2);
        core4Mica.remunerate(_encodeGuaranteeWithVersion(g), signature);
        _assertScaledReconciliationWithinTolerance(asset);

        vm.warp(block.timestamp + 30 days);

        uint256 withdrawable = core4Mica.withdrawableBalance(USER1, asset);
        if (withdrawable == 0) {
            return;
        }

        vm.prank(USER1);
        core4Mica.requestWithdrawal(asset, withdrawable);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(asset);
        _assertScaledReconciliationWithinTolerance(asset);

        uint256 protocolScaled = core4Mica.protocolScaledBalance(asset);
        if (protocolScaled == 0) {
            return;
        }

        core4Mica.claimProtocolYield(asset, USER2, type(uint256).max);
        _assertScaledReconciliationWithinTolerance(asset);
    }

    function _grantGovernance(bytes4 selector) internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = selector;
        manager.setTargetFunctionRole(address(core4Mica), selectors, GOVERNANCE_ROLE);
        manager.grantRole(GOVERNANCE_ROLE, address(this), 0);
    }

    function _fundAndApprove(address user, address asset, uint256 amount) internal {
        deal(asset, user, amount, true);
        vm.startPrank(user);
        IERC20(asset).approve(address(core4Mica), type(uint256).max);
        vm.stopPrank();
    }

    function _depositAmount(address asset) internal view returns (uint256) {
        uint8 decimals = IERC20Metadata(asset).decimals();
        return 10 ** decimals;
    }

    function _largeDepositAmount(address asset) internal view returns (uint256) {
        uint8 decimals = IERC20Metadata(asset).decimals();
        return 1_000 * (10 ** decimals);
    }

    function _assertScaledReconciliationWithinTolerance(address asset) internal view {
        uint256 observed = core4Mica.contractScaledATokenBalance(asset);
        uint256 tracked = core4Mica.totalUserScaledBalance(asset) + core4Mica.protocolScaledBalance(asset)
            + core4Mica.surplusScaledBalance(asset);
        uint256 tolerance = core4Mica.reconciliationDustToleranceScaled();
        uint256 gap = observed >= tracked ? observed - tracked : tracked - observed;
        assertLe(gap, tolerance, "scaled reconciliation drift exceeded tolerance");
    }

    function _encodeGuaranteeWithVersion(Guarantee memory g) internal pure returns (bytes memory) {
        return BlsHelper.encodeGuaranteeWithVersion(g);
    }

    function _guarantee(
        uint256 tabId,
        uint256 tabTimestamp,
        address client,
        address recipient,
        uint256 reqId,
        uint256 amount,
        address asset
    ) internal view returns (Guarantee memory) {
        return Guarantee({
            domain: core4Mica.guaranteeDomainSeparator(),
            tabId: tabId,
            reqId: reqId,
            client: client,
            recipient: recipient,
            amount: amount,
            totalAmount: amount,
            asset: asset,
            // forge-lint: disable-next-line(unsafe-typecast)
            timestamp: uint64(tabTimestamp),
            version: 1
        });
    }
}
