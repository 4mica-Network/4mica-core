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
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = Core4Mica.seizeCollateral.selector;
        selectors[1] = Core4Mica.creditCollateral.selector;
        selectors[2] = Core4Mica.creditFromEscrowScaled.selector;
        selectors[3] = Core4Mica.withdrawFromEscrow.selector;
        selectors[4] = Core4Mica.depositToEscrow.selector;
        for (uint256 i = 0; i < selectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(selectors[i]), OPERATOR_ROLE);
        }
    }

    function _assertReconciled(address asset) internal view {
        uint256 observed = core4Mica.contractScaledATokenBalance(asset);
        uint256 tracked = core4Mica.totalUserScaledBalance(asset) + core4Mica.protocolScaledBalance(asset)
            + core4Mica.escrowScaledBalance(asset) + core4Mica.surplusScaledBalance(asset);
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
        uint256 escrowBefore = core4Mica.escrowScaledBalance(address(usdc));
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, address(usdc), 40e6);

        assertEq(seized, 40e6);
        // The seizure re-attributes the scaled position into escrow;
        // no underlying is withdrawn from Aave, so the caller receives nothing.
        assertEq(usdc.balanceOf(OPERATOR), operatorBefore);
        assertGt(core4Mica.escrowScaledBalance(address(usdc)), escrowBefore);
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

        // Seize from USER1 into escrow (no underlying leaves the vault).
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeCollateral(USER1, address(usdc), 60e6);
        assertEq(seized, 60e6);
        assertEq(core4Mica.collateral(USER1, address(usdc)), DEPOSIT - 60e6);
        assertGt(core4Mica.escrowScaledBalance(address(usdc)), 0);

        // Independently credit USER2 from a fresh deposit; escrow plus user balances reconcile.
        // (The escrow -> creditor round trip lands with the credit-from-escrow primitive.)
        usdc.mint(OPERATOR, 60e6);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), 60e6);
        core4Mica.creditCollateral(USER2, address(usdc), 60e6);
        vm.stopPrank();

        assertEq(core4Mica.collateral(USER2, address(usdc)), 60e6);
        _assertReconciled(address(usdc));
    }

    // ===================== escrow consumption =====================

    function test_SeizeThenCreditFromEscrow() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        vm.prank(OPERATOR);
        core4Mica.seizeCollateral(USER1, address(usdc), 60e6);
        uint256 escrowAfterSeize = core4Mica.escrowScaledBalance(address(usdc));
        assertGt(escrowAfterSeize, 0);

        // Make USER2 whole in collateral form straight from escrow — no Aave interaction.
        vm.prank(OPERATOR);
        core4Mica.creditFromEscrowScaled(USER2, address(usdc), 60e6);

        assertEq(core4Mica.collateral(USER2, address(usdc)), 60e6);
        assertEq(core4Mica.collateral(USER1, address(usdc)), DEPOSIT - 60e6);
        assertLt(core4Mica.escrowScaledBalance(address(usdc)), escrowAfterSeize);
        _assertReconciled(address(usdc));
    }

    function test_SeizeThenWithdrawFromEscrow() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        vm.prank(OPERATOR);
        core4Mica.seizeCollateral(USER1, address(usdc), 60e6);

        uint256 recipientBefore = usdc.balanceOf(USER2);
        vm.prank(OPERATOR);
        uint256 got = core4Mica.withdrawFromEscrow(address(usdc), 60e6, USER2);

        assertEq(got, 60e6);
        assertEq(usdc.balanceOf(USER2), recipientBefore + 60e6);
        assertEq(core4Mica.escrowScaledBalance(address(usdc)), 0);
        _assertReconciled(address(usdc));
    }

    function test_WithdrawFromEscrow_PartialFillOnLiquidityShortfall() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        vm.prank(OPERATOR);
        core4Mica.seizeCollateral(USER1, address(usdc), 60e6);
        uint256 escrowBefore = core4Mica.escrowScaledBalance(address(usdc));

        // Aave can only return 40 of the requested 60; the call must not revert.
        mockPool.setWithdrawShortfall(address(usdc), 20e6);

        uint256 recipientBefore = usdc.balanceOf(USER2);
        vm.prank(OPERATOR);
        uint256 got = core4Mica.withdrawFromEscrow(address(usdc), 60e6, USER2);

        assertEq(got, 40e6);
        assertEq(usdc.balanceOf(USER2), recipientBefore + 40e6);
        // Only the converted portion's scaled balance is burned; the rest stays in escrow.
        assertEq(core4Mica.escrowScaledBalance(address(usdc)), escrowBefore - 40e6);
        _assertReconciled(address(usdc));
    }

    function test_DepositToEscrowThenCreditOut_FullRoundTrip() public {
        usdc.mint(OPERATOR, DEPOSIT);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), DEPOSIT);
        core4Mica.depositToEscrow(address(usdc), DEPOSIT);
        vm.stopPrank();

        assertGt(core4Mica.escrowScaledBalance(address(usdc)), 0);
        _assertReconciled(address(usdc));

        // Fund a creditor entirely from the paid-in escrow, no Aave withdrawal.
        vm.prank(OPERATOR);
        core4Mica.creditFromEscrowScaled(USER2, address(usdc), DEPOSIT);

        assertEq(core4Mica.collateral(USER2, address(usdc)), DEPOSIT);
        assertEq(core4Mica.escrowScaledBalance(address(usdc)), 0);
        _assertReconciled(address(usdc));
    }

    /// A credit too small to be worth one scaled unit rounds down to zero scaled, which would give
    /// the creditor face-value principal with no scaled backing — the same hazard as a dust deposit.
    function test_CreditFromEscrowScaled_RevertZeroScaledCredit() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);
        vm.prank(OPERATOR);
        core4Mica.seizeCollateral(USER1, address(usdc), 60e6);

        // Advance the liquidity index above RAY so a 1-wei credit rounds down to 0 scaled.
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ZeroCollateralCredit.selector, address(usdc), 1));
        core4Mica.creditFromEscrowScaled(USER2, address(usdc), 1);
    }

    /// Boundary: the smallest credit that maps to exactly one scaled unit still succeeds.
    function test_CreditFromEscrowScaled_MinScaledCreditSucceeds() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);
        vm.prank(OPERATOR);
        core4Mica.seizeCollateral(USER1, address(usdc), 60e6);

        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(OPERATOR);
        core4Mica.creditFromEscrowScaled(USER2, address(usdc), 2); // mulDiv(2, RAY, 2*RAY) = 1 scaled
        assertEq(core4Mica.collateral(USER2, address(usdc)), 2, "min credit applied");
    }

    /// A dust escrow deposit mints no scaled aTokens, so the pulled tokens would be handed to Aave
    /// while the escrow grows by nothing.
    function test_DepositToEscrow_RevertZeroScaledCredit() public {
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        usdc.mint(OPERATOR, 1);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), 1);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ZeroCollateralCredit.selector, address(usdc), 1));
        core4Mica.depositToEscrow(address(usdc), 1);
        vm.stopPrank();
    }

    /// Boundary: the smallest escrow deposit that mints exactly one scaled unit still succeeds.
    function test_DepositToEscrow_MinScaledCreditSucceeds() public {
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        usdc.mint(OPERATOR, 2);
        vm.startPrank(OPERATOR);
        usdc.approve(address(core4Mica), 2);
        core4Mica.depositToEscrow(address(usdc), 2); // mulDiv(2, RAY, 2*RAY) = 1 scaled
        vm.stopPrank();

        assertEq(core4Mica.escrowScaledBalance(address(usdc)), 1, "min escrow deposit credited");
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
