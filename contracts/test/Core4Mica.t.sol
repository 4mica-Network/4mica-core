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
        core4Mica.setMinCollateralAmount(minDeposit);
        // Assign all necessary function roles to USER_ROLE (no delay)
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.addDeposit.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.withdrawCollateral.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.requestDeregistration.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.cancelDeregistration.selector),
            USER_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.finalizeDeregistration.selector),
            USER_ROLE
        );
        // grant user1 the USER_ROLE immediately (0 delay)
        manager.grantRole(USER_ROLE, user1, 0);

        // grant test contract (us) the OPERATOR_ROLE so we can lockCollateral/makeWhole
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.lockCollateral.selector),
            OPERATOR_ROLE
        );
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
    function test_SetMinCollateralAmount() public {
        // happy path
        uint256 newMin = 5e15;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.MinDepositUpdated(newMin);
        core4Mica.setMinCollateralAmount(newMin);

        assertEq(core4Mica.minCollateralAmount(), newMin);
    }

    function test_RevertSetMinCollateralAmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setMinCollateralAmount(0);
    }

    function test_SetGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.GracePeriodUpdated(newGrace);
        core4Mica.setGracePeriod(newGrace);

        assertEq(core4Mica.gracePeriod(), newGrace);
    }

    function test_RevertSetGracePeriodZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setGracePeriod(0);
    }

    // === Registration ===
    function test_AddDeposit() public {
        // Give user1 some ETH
        vm.deal(user1, 1 ether);

        // Simulate user1 calling the function
        vm.startPrank(user1);

        // Expect the UserRegistered event with exact parameters
        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralDeposited(user1, minDeposit);
        vm.expectEmit(true, false, false, true);
        emit Core4Mica.UserRegistered(user1, minDeposit);

        // Call registerUser with the minimum deposit
        core4Mica.addDeposit{value: minDeposit}();

        // Verify user data after deposit
        (
            uint256 totalCollateral,
            uint256 lockedCollateral,
            uint256 availableCollateral,
            uint256 deregTimestamp
        ) = core4Mica.getUser(user1);

        assertEq(totalCollateral, minDeposit, "Total collateral mismatch");
        assertEq(lockedCollateral, 0, "Locked collateral should be 0");
        assertEq(
            availableCollateral,
            minDeposit,
            "Available collateral mismatch"
        );
        assertEq(deregTimestamp, 0, "Deregistration timestamp should be 0");

        // Check contract balance increased correctly
        assertEq(
            address(core4Mica).balance,
            minDeposit,
            "Contract balance mismatch"
        );

        // Check that a second deposit succeeds
        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralDeposited(user1, minDeposit);
        core4Mica.addDeposit{value: minDeposit}();

        vm.stopPrank();
    }

    function test_RevertRegisterInsufficientFunds() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(Core4Mica.InsufficientFunds.selector);
        core4Mica.addDeposit{value: 1}();
    }

    // === Deposits / Withdrawals ===
    function test_AddDepositAndWithdraw() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();

        (uint256 collateral, , uint256 available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(available, minDeposit * 2);

        core4Mica.withdrawCollateral(minDeposit);
        (collateral, , available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(available, minDeposit);
    }

    function test_RevertWithdrawTooMuch() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.prank(user1);
        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.withdrawCollateral(minDeposit * 2);
    }

    // === Withdraw Collateral: Failure cases ===
    function test_RevertWithdrawCollateral_AmountZero() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.prank(user1);
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.withdrawCollateral(0);
    }

    function test_RevertWithdrawCollateral_NotRegistered() public {
        // user1 never registered
        vm.prank(user1);
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.withdrawCollateral(minDeposit);
    }

    function test_RevertWithdrawCollateral_InsufficientAvailable() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.addDeposit{value: minDeposit * 2}();
        vm.stopPrank();

        // lock part of the collateral so available < total
        core4Mica.lockCollateral(user1, minDeposit * 2);

        vm.prank(user1);
        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.withdrawCollateral(minDeposit);
    }

    // === Locking Collateral ===
    function test_ManagerCanLockCollateral() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        core4Mica.lockCollateral(user1, minDeposit);

        (, , uint256 available, ) = core4Mica.getUser(user1);
        (, uint256 locked, , ) = core4Mica.getUser(user1);

        assertEq(locked, minDeposit);
        assertEq(available, minDeposit * 2);
    }

    function test_RevertLockCollateral_NotRegistered() public {
        // user1 has no registration
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.lockCollateral(user1, minDeposit);
    }

    function test_RevertLockCollateral_AmountZero() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.lockCollateral(user1, 0);
    }

    function test_RevertLockCollateral_InsufficientAvailable() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        // Try to lock more than user1's collateral
        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.lockCollateral(user1, minDeposit * 2);
    }

    // === Deregistration ===
    function test_RequestAndFinalizeDeregistration() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        vm.prank(user1);
        core4Mica.finalizeDeregistration();

        (uint256 collateral, , , ) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
    }

    function test_RevertFinalizeBeforeGrace() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        vm.prank(user1);
        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeDeregistration();
    }

    // === Deregistration: Failure cases ===
    function test_RevertRequestDeregistration_NotRegistered() public {
        // user1 never registered
        vm.prank(user1);
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.requestDeregistration();
    }

    function test_RevertCancelDeregistration_NoRequest() public {
        vm.startPrank(user1);
        vm.expectRevert(Core4Mica.NoDeregistrationRequested.selector);
        core4Mica.cancelDeregistration();
        vm.stopPrank();
    }

    // === MakeWhole ===
    function test_MakeWholePayout() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);

        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();
        core4Mica.lockCollateral(user1, minDeposit);

        uint256 beforeBal = user2.balance;

        core4Mica.makeWhole(user1, user2, minDeposit);

        uint256 afterBal = user2.balance;
        assertEq(afterBal - beforeBal, minDeposit);

        (uint256 collateral, uint256 locked, uint256 available, ) = core4Mica
            .getUser(user1);

        assertEq(locked, 0);
        assertEq(collateral, minDeposit * 2);
        assertEq(available, minDeposit * 2);
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
        core4Mica.lockCollateral(user1, minDeposit);

        vm.expectRevert(Core4Mica.TransferFailed.selector);
        core4Mica.makeWhole(user1, address(0), minDeposit);
    }

    function test_RevertMakeWhole_UserNotRegistered() public {
        // user1 never registered
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.makeWhole(user1, user2, minDeposit);
    }

    function test_RevertMakeWhole_DoubleSpendDetected() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit}();

        // lock less than we will try to pay out
        core4Mica.lockCollateral(user1, minDeposit);

        vm.expectRevert(Core4Mica.DoubleSpendDetected.selector);
        core4Mica.makeWhole(user1, user2, minDeposit * 2);
    }

    // === Locking Collateral while deregistration is pending ===

    function test_RevertLockCollateral_WhenDeregistrationRequested_Immediately()
        public
    {
        vm.deal(user1, 3 ether);

        // user registers and deposits
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        // user requests deregistration
        vm.prank(user1);
        core4Mica.requestDeregistration();

        // operator tries to lock -> should revert
        vm.expectRevert(Core4Mica.DeregistrationPending.selector);
        core4Mica.lockCollateral(user1, minDeposit);
    }

    function test_RevertLockCollateral_WhenDeregistrationRequested_AfterGraceElapsed()
        public
    {
        vm.deal(user1, 3 ether);

        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        // Even after grace period elapses (but before finalize), lock should still revert
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        vm.expectRevert(Core4Mica.DeregistrationPending.selector);
        core4Mica.lockCollateral(user1, minDeposit);
    }

    function test_LockCollateral_AfterCancelDeregistration() public {
        vm.deal(user1, 3 ether);

        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        // user cancels; lock should now succeed
        vm.prank(user1);
        core4Mica.cancelDeregistration();

        core4Mica.lockCollateral(user1, minDeposit);

        (, uint256 lockedAfter, uint256 availableAfter, ) = core4Mica.getUser(
            user1
        );
        assertEq(
            lockedAfter,
            minDeposit,
            "Locked should reflect post-cancel lock"
        );
        assertEq(
            availableAfter,
            minDeposit * 2,
            "Available should decrease after lock"
        );
    }

    function test_RevertLockCollateral_AfterFinalizeDeregistration_NotRegistered()
        public
    {
        vm.deal(user1, 3 ether);

        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 3}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        // Let grace pass and finalize (must have zero locked to finalize)
        vm.warp(block.timestamp + core4Mica.gracePeriod());
        vm.prank(user1);
        core4Mica.finalizeDeregistration();

        // After finalize, user is no longer registered; locking should revert with NotRegistered
        vm.expectRevert(Core4Mica.NotRegistered.selector);
        core4Mica.lockCollateral(user1, minDeposit);
    }

    function test_RequestThenLockBeforeRequestAllowed_ButAfterRequestReverts()
        public
    {
        vm.deal(user1, 5 ether);

        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 5}();

        // Operator can lock before any deregistration request
        core4Mica.lockCollateral(user1, minDeposit);

        // User requests deregistration
        vm.prank(user1);
        core4Mica.requestDeregistration();

        // Further locks must be blocked
        vm.expectRevert(Core4Mica.DeregistrationPending.selector);
        core4Mica.lockCollateral(user1, minDeposit);

        // Sanity: existing lock remains, balances unchanged by failed lock
        (uint256 total, uint256 locked, uint256 available, ) = core4Mica
            .getUser(user1);
        assertEq(total, minDeposit * 5, "Total collateral should be unchanged");
        assertEq(locked, minDeposit, "Locked should be unchanged");
        assertEq(
            available,
            (minDeposit * 5) - minDeposit,
            "Available should be unchanged"
        );
    }

    function test_RequestDeregistration_DoesNotBlockWithdrawOrMakeWholeFromExistingLock()
        public
    {
        // Behavior expectation:
        // - Requesting deregistration blocks *new* locks.
        // - It should NOT interfere with paying out (makeWhole) against already-locked collateral.

        vm.deal(user1, 4 ether);
        vm.deal(user2, 0);

        // Register and pre-lock some collateral
        vm.prank(user1);
        core4Mica.addDeposit{value: minDeposit * 4}();
        core4Mica.lockCollateral(user1, minDeposit * 2);

        // User requests deregistration (blocks further locks but does not unblock/affect existing locks)
        vm.prank(user1);
        core4Mica.requestDeregistration();

        // New lock attempts must revert
        vm.expectRevert(Core4Mica.DeregistrationPending.selector);
        core4Mica.lockCollateral(user1, minDeposit);

        // But operator can still makeWhole using the already-locked amount
        uint256 before = user2.balance;
        core4Mica.makeWhole(user1, user2, minDeposit * 2);
        uint256 after_ = user2.balance;
        assertEq(
            after_ - before,
            minDeposit * 2,
            "Recipient didn't receive payout"
        );

        (uint256 total, uint256 locked, uint256 available, ) = core4Mica
            .getUser(user1);
        assertEq(locked, 0, "Locked should be reduced by payout");
        assertEq(total, minDeposit * 2, "Total should be reduced by payout");
        assertEq(available, minDeposit * 2, "Available tracks total - locked");
    }
}
