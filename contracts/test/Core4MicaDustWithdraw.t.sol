// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";

/// Regression for the user-withdrawal dust edge, the withdrawal-path analogue of the seizure clamp
/// in `Core4MicaSeizeDust.t.sol`. A scaled aToken position can back up to ~1 base unit less than its
/// recorded principal (Aave floors the scaled mint at deposit while `withdrawableBalance`
/// optimistically reports the full principal). Finalizing a withdrawal of that full reported balance
/// must drain the position and pay out what it truly redeems, rather than reverting on a scaled
/// underflow and stranding the user's own funds.
contract Core4MicaDustWithdrawTest is Core4MicaTestBase {
    uint256 internal constant DEPOSIT = 100e6;
    // index 3.0: 100e6 mints scaled floor(100e6/3) = 33_333_333, backing floor(33_333_333*3) = 99_999_999.
    uint256 internal constant DUST_INDEX = 3e27;
    uint256 internal constant DUST_BACKED = 99_999_999;

    function _depositDust() internal {
        // Seed pool liquidity so Aave itself never short-fills, isolating the scaled-accounting edge.
        usdc.mint(USER2, 1_000_000 ether);
        vm.prank(USER2);
        usdc.approve(address(core4Mica), type(uint256).max);
        vm.prank(USER2);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        mockPool.setNormalizedIncome(address(usdc), DUST_INDEX);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);
    }

    /// The reported withdrawable stays at the (optimistic) face-value principal, as the seizure path
    /// relies on: this is unchanged by the withdrawal fix.
    function test_Withdrawable_StillReportsFullPrincipal() public {
        _depositDust();
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), DEPOSIT, "principal is face value");
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), DEPOSIT, "withdrawable reports full principal");
    }

    /// Finalizing a withdrawal of the full reported balance no longer reverts: it drains the whole
    /// position, pays out what it truly redeems (principal - 1), and zeroes the ledger.
    function test_WithdrawFullBalance_DustPosition_DrainsInsteadOfReverting() public {
        _depositDust();

        uint256 stated = core4Mica.withdrawableBalance(USER1, address(usdc));
        assertEq(stated, DEPOSIT, "stated is the optimistic principal");

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), stated);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        uint256 before = usdc.balanceOf(USER1);
        // The event must report the clamped payout, not the optimistic request it was derived from.
        vm.expectEmit(true, true, false, true, address(core4Mica));
        emit Core4Mica.CollateralWithdrawn(USER1, address(usdc), DUST_BACKED);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        // Received the true backed value, and the position is fully drained on both ledgers.
        assertEq(usdc.balanceOf(USER1) - before, DUST_BACKED, "paid out what the position backs");
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0, "principal zeroed");
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 0, "position drained");
    }

    /// Property: finalizing the full reported withdrawable never reverts and always drains the debtor,
    /// for any deposit size and reserve index.
    function testFuzz_FinalizeFullWithdrawal_NeverReverts(uint256 depositAmt, uint256 indexNum) public {
        depositAmt = bound(depositAmt, 1e6, 1_000_000e6);
        uint256 index = bound(indexNum, 1e27, 5e27);

        // Pool liquidity from a second depositor at the same index.
        usdc.mint(USER2, 2_000_000e6);
        vm.prank(USER2);
        usdc.approve(address(core4Mica), type(uint256).max);
        mockPool.setNormalizedIncome(address(usdc), index);
        vm.prank(USER2);
        core4Mica.depositStablecoin(address(usdc), 1_000_000e6);

        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), depositAmt);

        uint256 stated = core4Mica.withdrawableBalance(USER1, address(usdc));
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), stated);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0, "principal zeroed");
    }

    /// Positive accrued yield is unaffected: a full withdrawal still pays principal + net yield.
    function test_WithdrawWithYield_Unchanged() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        uint256 stated = core4Mica.withdrawableBalance(USER1, address(usdc));
        assertEq(stated, 2_000 ether, "principal + yield");

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), stated);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        uint256 before = usdc.balanceOf(USER1);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));
        assertEq(usdc.balanceOf(USER1) - before, 2_000 ether, "paid principal + yield in full");
    }
}
