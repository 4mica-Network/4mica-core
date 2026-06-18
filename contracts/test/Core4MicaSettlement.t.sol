// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";

error EnforcedPause();

/// Tests for the ClearingHouse-only collateral seize/credit settlement hooks.
contract Core4MicaSettlementTest is Core4MicaTestBase {
    uint256 internal constant DEPOSIT = 100e6;

    function setUp() public override {
        super.setUp();
        // Grant the settlement hooks to OPERATOR, which stands in for the ClearingHouse.
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = Core4Mica.seizeCollateral.selector;
        selectors[1] = Core4Mica.creditCollateral.selector;
        for (uint256 i = 0; i < selectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(selectors[i]), OPERATOR_ROLE);
        }
    }

    function _assertReconciled(address asset) internal view {
        uint256 observed = core4Mica.contractScaledATokenBalance(asset);
        uint256 tracked = core4Mica.totalUserScaledBalance(asset) + core4Mica.protocolScaledBalance(asset)
            + core4Mica.surplusScaledBalance(asset);
        uint256 tolerance = core4Mica.reconciliationDustToleranceScaled();
        uint256 diff = observed > tracked ? observed - tracked : tracked - observed;
        assertLe(diff, tolerance, "reconciliation drift");
    }

    // ===================== seize =====================

    function test_SeizeEthCollateral() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 3 ether}();

        uint256 operatorBefore = OPERATOR.balance;
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, ETH_ASSET, 2 ether);

        assertEq(seized, 2 ether);
        assertEq(core4Mica.collateral(USER1), 1 ether);
        assertEq(OPERATOR.balance, operatorBefore + 2 ether);
    }

    function test_SeizeStablecoinCollateral() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        uint256 operatorBefore = usdc.balanceOf(OPERATOR);
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, address(usdc), 40e6);

        assertEq(seized, 40e6);
        assertEq(usdc.balanceOf(OPERATOR), operatorBefore + 40e6);
        assertEq(core4Mica.collateral(USER1, address(usdc)), DEPOSIT - 40e6);
        _assertReconciled(address(usdc));
    }

    function test_SeizeRevertsWhenInsufficient() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.prank(OPERATOR);
        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.seizeCollateral(USER1, ETH_ASSET, 2 ether);
    }

    function test_SeizeOnlyCallableByGrantedRole() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.prank(USER2);
        vm.expectRevert(accessUnauthorizedError(USER2));
        core4Mica.seizeCollateral(USER1, ETH_ASSET, 1 ether);
    }

    // ===================== credit =====================

    function test_CreditEthCollateral() public {
        vm.deal(OPERATOR, 5 ether);

        vm.prank(OPERATOR);
        core4Mica.creditCollateral{value: 2 ether}(USER2, ETH_ASSET, 2 ether);

        assertEq(core4Mica.collateral(USER2), 2 ether);
    }

    function test_CreditEthRequiresExactValue() public {
        vm.deal(OPERATOR, 5 ether);

        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ValueMismatch.selector, 2 ether, 1 ether));
        core4Mica.creditCollateral{value: 1 ether}(USER2, ETH_ASSET, 2 ether);
    }

    function test_CreditStablecoinCollateral() public {
        usdc.mint(OPERATOR, DEPOSIT);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), DEPOSIT);
        core4Mica.creditCollateral(USER2, address(usdc), DEPOSIT);
        vm.stopPrank();

        assertEq(core4Mica.collateral(USER2, address(usdc)), DEPOSIT);
        _assertReconciled(address(usdc));
    }

    function test_CreditStablecoinRejectsEthValue() public {
        usdc.mint(OPERATOR, DEPOSIT);
        vm.deal(OPERATOR, 1 ether);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), DEPOSIT);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ValueMismatch.selector, 0, 1 ether));
        core4Mica.creditCollateral{value: 1 ether}(USER2, address(usdc), DEPOSIT);
        vm.stopPrank();
    }

    // ===================== round trip =====================

    function test_SeizeThenCreditPreservesReconciliation() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        // Seize from USER1 into OPERATOR, then credit it back to USER2's collateral.
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, address(usdc), 60e6);

        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), seized);
        core4Mica.creditCollateral(USER2, address(usdc), seized);
        vm.stopPrank();

        assertEq(core4Mica.collateral(USER1, address(usdc)), DEPOSIT - 60e6);
        assertEq(core4Mica.collateral(USER2, address(usdc)), 60e6);
        _assertReconciled(address(usdc));
    }

    // ===================== pause =====================

    /// The settlement hooks move collateral, so they must freeze while paused
    /// like every other collateral mutation, and resume once unpaused.
    function test_PauseBlocksSeizeAndCredit_AndUnpauseRestoresFlow() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 3 ether}();

        core4Mica.pause();

        vm.prank(OPERATOR);
        vm.expectRevert(EnforcedPause.selector);
        core4Mica.seizeCollateral(USER1, ETH_ASSET, 2 ether);

        vm.deal(OPERATOR, 2 ether);
        vm.prank(OPERATOR);
        vm.expectRevert(EnforcedPause.selector);
        core4Mica.creditCollateral{value: 2 ether}(USER2, ETH_ASSET, 2 ether);

        core4Mica.unpause();

        // Both hooks work again once unpaused.
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, ETH_ASSET, 2 ether);
        assertEq(seized, 2 ether);

        vm.prank(OPERATOR);
        core4Mica.creditCollateral{value: 2 ether}(USER2, ETH_ASSET, 2 ether);
        assertEq(core4Mica.collateral(USER2), 2 ether);
    }
}
