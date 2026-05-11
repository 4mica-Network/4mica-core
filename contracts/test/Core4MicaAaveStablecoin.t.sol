// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica, Guarantee} from "../src/Core4Mica.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

contract Core4MicaAaveStablecoinTest is Core4MicaTestBase {
    function test_StablecoinViewsReflectAaveYieldSplit() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 1_000 ether);
        assertEq(core4Mica.grossYield(USER1, address(usdc)), 1_000 ether);
        assertEq(core4Mica.protocolYieldShare(USER1, address(usdc)), 200 ether);
        assertEq(core4Mica.userNetYield(USER1, address(usdc)), 800 ether);
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 1_800 ether);
        assertEq(core4Mica.collateral(USER1, address(usdc)), 1_800 ether);
    }

    function test_FinalizeWithdrawal_CrystallizesProtocolYield() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 1_800 ether);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(usdc.balanceOf(USER1), 1_000_800 ether);
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0);
        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 100 ether);
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 0);

        uint256 poolBalanceBefore = usdc.balanceOf(address(mockPool));
        core4Mica.claimProtocolYield(address(usdc), USER2, type(uint256).max);
        assertEq(usdc.balanceOf(USER2), 200 ether);
        assertEq(usdc.balanceOf(address(mockPool)), poolBalanceBefore - 200 ether);
        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 0);
    }

    function test_Remuneration_ClampsPendingStablecoinWithdrawalToRemainingWithdrawable() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 1_500 ether);
        (, uint256 requestTimestamp,) = core4Mica.getUser(USER1, address(usdc));

        uint256 tabTimestamp = requestTimestamp + core4Mica.synchronizationDelay() + 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);
        Guarantee memory g = _guarantee(0xABCD, tabTimestamp, USER1, USER2, 9, 500 ether, address(usdc));
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        vm.prank(USER2);
        core4Mica.remunerate(_encodeGuaranteeWithVersion(g), signature);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) =
            core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, 1_300 ether);
        assertGt(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 1_300 ether);
        assertEq(usdc.balanceOf(USER2), 500 ether);
    }

    function test_TinyYieldRoundingDoesNotCreateProtocolClaim() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1);

        core4Mica.setYieldFeeBps(5_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 1);
        assertEq(core4Mica.grossYield(USER1, address(usdc)), 1);
        assertEq(core4Mica.protocolYieldShare(USER1, address(usdc)), 0);
        assertEq(core4Mica.userNetYield(USER1, address(usdc)), 1);
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 2);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 2);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(usdc.balanceOf(USER1), 1_000_000 ether - 1 + 2);
        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 0);
    }

    function test_ClaimProtocolYield_RevertAmountZeroWithoutCrystallizedYield() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.claimProtocolYield(address(usdc), USER2, type(uint256).max);
    }

    function test_ClaimSurplusATokens_AfterReconciliationTransfersATokens() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        uint256 trackedScaled = mockUsdcAToken.scaledBalanceOf(address(core4Mica));
        vm.prank(address(mockPool));
        mockUsdcAToken.setScaledBalance(address(core4Mica), trackedScaled + 50 ether);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 1 wei);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(core4Mica.surplusScaledBalance(address(usdc)), 50 ether);

        uint256 recipientATokenBefore = mockUsdcAToken.balanceOf(USER2);
        core4Mica.claimSurplusATokens(address(usdc), USER2, 10 ether);

        assertEq(mockUsdcAToken.balanceOf(USER2), recipientATokenBefore + 10 ether);
        assertEq(core4Mica.surplusScaledBalance(address(usdc)), 40 ether);
    }

    function test_RepeatedPartialWithdrawalsAcrossIndexChangesPreserveAccounting() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 1.5e27);

        uint256 userBalanceBefore = usdc.balanceOf(USER1);
        uint256 firstWithdraw = 700 ether;

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), firstWithdraw);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(usdc.balanceOf(USER1), userBalanceBefore + firstWithdraw);
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 700 ether);

        mockPool.setNormalizedIncome(address(usdc), 2e27);

        uint256 secondWithdraw = core4Mica.withdrawableBalance(USER1, address(usdc));
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), secondWithdraw);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 0);
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0);
        assertGt(core4Mica.protocolScaledBalance(address(usdc)), 0);
    }

    function test_ClaimProtocolYield_PartialThenMaxClaim() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        core4Mica.setYieldFeeBps(2_000);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 1_800 ether);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 100 ether);

        core4Mica.claimProtocolYield(address(usdc), USER2, 50 ether);
        assertEq(usdc.balanceOf(USER2), 50 ether);
        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 75 ether);

        core4Mica.claimProtocolYield(address(usdc), USER2, type(uint256).max);
        assertEq(usdc.balanceOf(USER2), 200 ether);
        assertEq(core4Mica.protocolScaledBalance(address(usdc)), 0);
    }

    function test_ClaimSurplusATokens_AfterIndexChangeUsesCurrentNominalValue() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        uint256 trackedScaled = mockUsdcAToken.scaledBalanceOf(address(core4Mica));
        vm.prank(address(mockPool));
        mockUsdcAToken.setScaledBalance(address(core4Mica), trackedScaled + 50 ether);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 1 wei);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        mockPool.setNormalizedIncome(address(usdc), 2e27);

        uint256 recipientATokenBefore = mockUsdcAToken.balanceOf(USER2);
        core4Mica.claimSurplusATokens(address(usdc), USER2, 10 ether);

        assertEq(mockUsdcAToken.balanceOf(USER2), recipientATokenBefore + 20 ether);
        assertEq(core4Mica.surplusScaledBalance(address(usdc)), 40 ether);
    }
}
