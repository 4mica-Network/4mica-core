// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";

contract Core4MicaTest is Test {
    Core4Mica core4Mica;
    AccessManager manager;
    address user1 = address(0x111);
    address user2 = address(0x222);
    uint256 minDeposit = 1e15; // 0.001 ETH

    uint64 public constant USER_ROLE = 3;
    uint64 public constant OPERATOR_ROLE = 9;

    function setUp() public {
        manager = new AccessManager(address(this));
        core4Mica = new Core4Mica(address(manager));
        // Assign all necessary function roles to USER_ROLE (no delay)
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.addDeposit.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.requestWithdrawal.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.cancelWithdrawal.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.finalizeWithdrawal.selector),
            USER_ROLE
        );
        // grant user1 the USER_ROLE immediately (0 delay)
        manager.grantRole(USER_ROLE, user1, 0);

        // grant test contract (us) the OPERATOR_ROLE so we can lockCollateral/makeWhole
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.makeWhole.selector),
            OPERATOR_ROLE
        );
        manager.grantRole(OPERATOR_ROLE, address(this), 0);
    }

    // helper

    function _asSingletonArray(
        bytes4 selector
    ) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    // === Admin Config ===

    function test_SetGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.GracePeriodUpdated(newGrace);
        core4Mica.setGracePeriod(newGrace);

        assertEq(core4Mica.gracePeriod(), newGrace);
    }

    function test_SetGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setGracePeriod(0);
    }

    // === Deposit ===

    function test_AddDeposit() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.UserRegistered(user1, minDeposit);

        core4Mica.addDeposit{value: minDeposit}();

        (
            uint256 totalCollateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(user1);
        assertEq(totalCollateral, minDeposit, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");

        assertEq(
            address(core4Mica).balance,
            minDeposit,
            "Contract balance mismatch"
        );

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralDeposited(user1, minDeposit);
        core4Mica.addDeposit{value: minDeposit}();
    }

    // === Request Withdrawal ===

    function test_RequestWithdrawal() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.WithdrawalRequested(user1, block.timestamp);

        core4Mica.requestWithdrawal(minDeposit);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, minDeposit);
    }

    // === Request Withdrawal: Failure cases ===

    function test_RequestWithdrawal_Revert_AmountZero() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestWithdrawal(0);
    }

    function test_RequestWithdrawal_Revert_TooMuch() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestWithdrawal(minDeposit * 2);
    }

    function test_RequestWithdrawal_Revert_NotRegistered() public {
        // user1 never registered
        vm.prank(user1);
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.requestWithdrawal(minDeposit);
    }

    // === Cancel Withdrawal ===

    function test_CancelWithdrawal() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();
        core4Mica.requestWithdrawal(minDeposit);

        vm.expectEmit(false, false, false, true);
        emit Core4Mica.WithdrawalCanceled(user1);

        core4Mica.cancelWithdrawal();
        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    // === Cancel Withdrawal: Failure cases ===

    function test_CancelWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.cancelWithdrawal();
    }

    // === Finalize Withdrawal ===

    function test_FinalizeWithdrawal_FullAmount() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();
        core4Mica.requestWithdrawal(minDeposit);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, minDeposit);

        assertEq(user1.balance, 1.998 ether);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 1.999 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_NotFullAmount() public {
        vm.deal(user1, 0.005 ether);
        vm.deal(user2, 0 ether);

        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 5}();
        core4Mica.requestWithdrawal(minDeposit * 4);
        vm.stopPrank();

        core4Mica.makeWhole(user1, user2, minDeposit * 3);
        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, minDeposit * 4);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, minDeposit * 2);

        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0.002 ether);

        (collateral, withdrawalTimestamp, withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_CollateralGone() public {
        vm.deal(user1, 0.004 ether);
        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 4}();
        core4Mica.requestWithdrawal(minDeposit * 2);
        vm.stopPrank();

        core4Mica.makeWhole(user1, user2, minDeposit * 4);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    // === Finalize Withdrawal: Failure cases ===

    function test_FinalizeWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 4}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.finalizeWithdrawal();
    }

    function test_FinalizeWithdrawal_Revert_GracePeriodNotElapsed() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 4}();
        core4Mica.requestWithdrawal(minDeposit * 2);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawal();
    }

    // === MakeWhole ===
    function test_MakeWholePayout() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        uint256 beforeBal = user2.balance;

        core4Mica.makeWhole(user1, user2, minDeposit);

        uint256 afterBal = user2.balance;
        assertEq(afterBal - beforeBal, minDeposit);

        (uint256 collateral,, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
    }

    // === MakeWhole: Failure cases ===

    function test_RevertMakeWhole_AmountZero() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.makeWhole(user1, user2, 0);
    }

    function test_RevertMakeWhole_InvalidRecipient() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.TransferFailed.selector);
        core4Mica.makeWhole(user1, address(0), minDeposit);
    }

    function test_RevertMakeWhole_UserNotRegistered() public {
        // user1 never registered
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.makeWhole(user1, user2, minDeposit);
    }
}
