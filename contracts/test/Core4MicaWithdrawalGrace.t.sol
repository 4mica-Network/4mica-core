// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";

/// Tests for the withdrawal seizure-window invariant: the grace period is snapshotted into each
/// request so reductions are not retroactive, and an on-chain floor bounds how low it can be set.
contract Core4MicaWithdrawalGraceTest is Core4MicaTestBase {
    function _depositAndRequestEth(uint256 deposit, uint256 withdraw) internal {
        vm.prank(USER1);
        core4Mica.deposit{value: deposit}();
        vm.prank(USER1);
        core4Mica.requestWithdrawal(withdraw);
    }

    // ===================== snapshot (no retroactive reduction) =====================

    function test_GraceReductionDoesNotShortenInflightRequest() public {
        uint256 requestedAt = block.timestamp;
        _depositAndRequestEth(3 ether, 1 ether); // snapshots the default 22-day grace

        // Governance later shortens the global grace.
        core4Mica.setWithdrawalGracePeriod(1 days);

        // Past the NEW grace but before the snapshotted one: must still be locked.
        vm.warp(requestedAt + 1 days + 1);
        vm.prank(USER1);
        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawal();

        // Once the original snapshotted window elapses, it finalizes.
        vm.warp(requestedAt + 22 days);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral,,) = core4Mica.getUser(USER1, ETH_ASSET);
        assertEq(collateral, 2 ether);
    }

    function test_NewRequestUsesReducedGrace() public {
        core4Mica.setWithdrawalGracePeriod(1 days);

        uint256 requestedAt = block.timestamp;
        _depositAndRequestEth(3 ether, 1 ether); // snapshots the reduced 1-day grace

        vm.warp(requestedAt + 1 days + 1);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral,,) = core4Mica.getUser(USER1, ETH_ASSET);
        assertEq(collateral, 2 ether);
    }

    function test_GraceIncreaseDoesNotExtendInflightRequest() public {
        uint256 requestedAt = block.timestamp;
        _depositAndRequestEth(3 ether, 1 ether); // snapshots 22 days

        // Increasing the global grace must not retroactively extend the in-flight request.
        core4Mica.setWithdrawalGracePeriod(100 days);

        vm.warp(requestedAt + 22 days);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral,,) = core4Mica.getUser(USER1, ETH_ASSET);
        assertEq(collateral, 2 ether);
    }

    // ===================== minimum grace bound =====================

    function test_SetGraceBelowMinimumReverts() public {
        core4Mica.setMinWithdrawalGracePeriod(5 days);

        vm.expectRevert(abi.encodeWithSelector(Core4Mica.GracePeriodBelowMinimum.selector, 1 days, 5 days));
        core4Mica.setWithdrawalGracePeriod(1 days);

        // At or above the floor is accepted.
        core4Mica.setWithdrawalGracePeriod(5 days);
        assertEq(core4Mica.withdrawalGracePeriod(), 5 days);
    }

    function test_SetMinAboveCurrentGraceReverts() public {
        // Default grace is 22 days; a floor above it would leave grace below the floor.
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.MinGracePeriodExceedsGrace.selector, 30 days, 22 days));
        core4Mica.setMinWithdrawalGracePeriod(30 days);

        // Raise the grace first, then the floor can follow.
        core4Mica.setWithdrawalGracePeriod(30 days);
        core4Mica.setMinWithdrawalGracePeriod(30 days);
        assertEq(core4Mica.minWithdrawalGracePeriod(), 30 days);
    }

    function test_MinGraceFloorOnlyCallableByGovernance() public {
        vm.prank(USER2);
        vm.expectRevert(accessUnauthorizedError(USER2));
        core4Mica.setMinWithdrawalGracePeriod(1 days);
    }
}
