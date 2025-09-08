// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IAccessManaged} from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";

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
        bytes4[] memory userSelectors = new bytes4[](6);
        userSelectors[0] = Core4Mica.deposit.selector;
        userSelectors[1] = Core4Mica.requestUnlock.selector;
        userSelectors[2] = Core4Mica.cancelUnlock.selector;
        userSelectors[3] = Core4Mica.unlock.selector;
        userSelectors[4] = Core4Mica.withdraw.selector;
        userSelectors[5] = Core4Mica.remunerate.selector;
        for (uint256 i = 0; i < userSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica),
                _asSingletonArray(userSelectors[i]),
                USER_ROLE
            );
        }
        // grant user1 the USER_ROLE immediately (0 delay)
        manager.grantRole(USER_ROLE, user1, 0);

        // grant test contract (us) the OPERATOR_ROLE so we can record Payments
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.recordPayment.selector),
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

    function test_SetUnlockGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.UnlockGracePeriodUpdated(newGrace);
        core4Mica.setUnlockGracePeriod(newGrace);

        assertEq(core4Mica.unlockGracePeriod(), newGrace);
    }

    function test_SetUnlockGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setUnlockGracePeriod(0);
    }

    function test_SetUnlockGracePeriod_Revert_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setUnlockGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.RemunerationGracePeriodUpdated(newGrace);
        core4Mica.setRemunerationGracePeriod(newGrace);

        assertEq(core4Mica.remunerationGracePeriod(), newGrace);
    }

    function test_SetRemunerationGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setRemunerationGracePeriod(0);
    }

    function test_SetRemunerationGracePeriod_Revert_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetTabExpirationTime() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.TabExpirationTimeUpdated(newGrace);
        core4Mica.setTabExpirationTime(newGrace);

        assertEq(core4Mica.tabExpirationTime(), newGrace);
    }

    function test_SetTabExpirationTime_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTabExpirationTime(0);
    }

    function test_SetTabExpirationTime_Revert_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setTabExpirationTime(2 days);
    }

    // === Deposit ===

    function test_Deposit() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.BalanceDeposited(user1, minDeposit);

        core4Mica.deposit{value: minDeposit}();

        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit, "Available balance mismatch");
        assertEq(locked, 0, "Locked balance mismatch");
        assertEq(unlockTimestamp, 0, "Unlock timestamp should be 0");
        assertEq(unlockAmount, 0, "Unlock amount should be 0");
    }

    // === Lock ===

    function test_Lock() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();


        vm.expectEmit(true, false, false, true);
        emit Core4Mica.LockedBalance(user1, minDeposit * 2);

        core4Mica.lock(minDeposit * 2);

        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit);
        assertEq(locked, minDeposit * 2);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    // === Lock: Failure cases ===

    function test_Lock_Revert_AmountZero() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.lock(0);
    }

    function test_Lock_Revert_InsufficientAvailable() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.lock(minDeposit * 4);
    }

    // === Request Unlock ===

    function test_RequestUnlock() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();
        core4Mica.lock(minDeposit * 2);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.UnlockRequested(user1, block.timestamp);

        core4Mica.requestUnlock(minDeposit);

        (
            uint256 available,
            uint256 locked,
            uint256 unlockalTimestamp,
            uint256 unlockalAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit);
        assertEq(locked, minDeposit * 2);
        assertEq(unlockalTimestamp, block.timestamp);
        assertEq(unlockalAmount, minDeposit);
    }

    // === Request Unlock: Failure cases ===

    function test_RequestUnlock_Revert_AmountZero() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 2}();
        core4Mica.lock(minDeposit);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestUnlock(0);
    }

    function test_RequestUnlock_Revert_TooMuch() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 5}();
        core4Mica.lock(minDeposit);

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestUnlock(minDeposit * 2);
    }

    // === Cancel Withdrawal ===

    function test_CancelUnlock() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();
        core4Mica.lock(minDeposit * 2);
        core4Mica.requestUnlock(minDeposit);

        vm.expectEmit(false, false, false, true);
        emit Core4Mica.UnlockCanceled(user1);

        core4Mica.cancelUnlock();
        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit);
        assertEq(locked, minDeposit * 2);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    // === Cancel Unlock: Failure cases ===

    function test_CancelUnlock_Revert_NoUnlockRequested() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();
        core4Mica.lock(minDeposit * 2);

        vm.expectRevert(Core4Mica.NoUnlockRequested.selector);
        core4Mica.cancelUnlock();
    }

    // === Unlock ===

    function test_Unlock_FullAmount() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 3}();
        core4Mica.lock(minDeposit * 2);
        core4Mica.requestUnlock(minDeposit);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.unlockGracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.UnlockedBalance(user1, minDeposit);

        core4Mica.unlock();

        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit * 2);
        assertEq(locked, minDeposit);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    function test_Unlock_NotFullAmount() public {
        vm.deal(user1, 0.009 ether);
        vm.deal(user2, 0 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 9}();
        core4Mica.lock(minDeposit * 5);

        uint256 tab_timestamp = 1;
        uint256 unlock_timestamp = 1;
        core4Mica.requestUnlock(minDeposit * 4);
        vm.stopPrank();

        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, minDeposit * 3);
        core4Mica.remunerate(g, 0x0);
        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit * 4);
        assertEq(locked, minDeposit * 2);
        assertEq(unlockTimestamp, unlock_timestamp);
        assertEq(unlockAmount, minDeposit * 4);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.unlockGracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.UnlockedBalance(user1, minDeposit * 2);

        vm.prank(user1);
        core4Mica.unlock();

        (available, locked, unlockTimestamp, unlockAmount) = core4Mica.getUser(user1);
        assertEq(available, minDeposit * 6);
        assertEq(locked, 0);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    function test_Unlock_CollateralGone() public {
        vm.deal(user1, 0.006 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 6}();
        core4Mica.lock(minDeposit * 4);

        // user promised something to recipient as part of tab
        uint256 tab_timestamp = 1;

        // user requests unlock
        core4Mica.requestUnlock(minDeposit * 2);
        vm.stopPrank();

        // fast forward > remuneration period
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        // user did not pay their promise, so
        // recipient comes to collect remuneration
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, minDeposit * 4);
        core4Mica.remunerate(g, 0x0);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.unlockGracePeriod());

        // user gets nothing because their balance was used during remuneration
        vm.prank(user1);
        core4Mica.unlock();

        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, minDeposit * 2);
        assertEq(locked, 0);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    // === Unlock: Failure cases ===

    function test_Unlock_Revert_NoUnlockRequested() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 6}();
        core4Mica.lock(minDeposit * 4);

        vm.expectRevert(Core4Mica.NoUnlockRequested.selector);
        core4Mica.unlock();
    }

    function test_Unlock_Revert_GracePeriodNotElapsed() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 6}();
        core4Mica.lock(minDeposit * 4);
        core4Mica.requestUnlock(minDeposit * 2);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.unlock();
    }

    // === Withdraw ===

    function test_Withdraw() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.lock(1 ether);

        assertEq(user1.balance, 0 ether);
        core4Mica.withdraw(0.75 ether);
        assertEq(user1.balance, 0.75 ether);

        (
            uint256 available,
            uint256 locked,
            uint256 unlockTimestamp,
            uint256 unlockAmount
        ) = core4Mica.getUser(user1);
        assertEq(available, 0.25 ether);
        assertEq(locked, 1 ether);
        assertEq(unlockTimestamp, 0);
        assertEq(unlockAmount, 0);
    }

    // === Withdraw: Failure cases ===

    function test_Withdraw_Revert_AmountZero() public {
        vm.deal(user1, 3 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.lock(1 ether);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.withdraw(0);
    }

    function test_Withdraw_Revert_InsufficientAvailable() public {
        vm.deal(user1, 3 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.lock(1 ether);

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.withdraw(1.25 ether);
    }

    // === Record payment ===

    function test_RecordPayment() public {
        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 0);
        assertFalse(remunerated);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.RecordedPayment(0x1234, 1 ether);

        core4Mica.recordPayment(0x1234, 1 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.RecordedPayment(0x1234, 2 ether);

        core4Mica.recordPayment(0x1234, 2 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 3 ether);
        assertFalse(remunerated);
    }

    // === Record payment: failure cases ===

    function test_RecordPayment_Revert_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.recordPayment(0x1234, 0);
    }

    function test_RecordPayment_Revert_AmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.recordPayment(0x1234, 0);
    }

    // === Remuneration ===

    function test_Remunerate() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);
        vm.prank(user1);
        core4Mica.deposit{value: 2 ether}();
        vm.prank(user1);
        core4Mica.lock(1 ether);

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;
        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, req_id, 0.5 ether);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);

        assertEq(user2.balance, 0.5 ether);
        (, uint256 locked,, ) = core4Mica.getUser(user1);
        assertEq(locked, 0.5 ether);
    }

    function test_Remunerate_PartiallyPaidTab() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);
        vm.prank(user1);
        core4Mica.deposit{value: 2 ether}();
        vm.prank(user1);
        core4Mica.lock(1 ether);

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;

        // core contract is informed that user1 paid user2 half of the tab
        core4Mica.recordPayment(tab_id, 0.25 ether);

        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, req_id, 0.5 ether);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);

        // check: user2 is still remunerated for the full amount
        assertEq(user2.balance, 0.5 ether);
        (, uint256 locked,, ) = core4Mica.getUser(user1);
        assertEq(locked, 0.5 ether);
    }

    // === Remunerate: Failure cases ===

    function test_Remunerate_Revert_AmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_InvalidRecipient() public {
        vm.expectRevert(Core4Mica.TransferFailed.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, address(0), 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_NotYetOverdue() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.TabNotYetOverdue.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_TabExpired() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.tabExpirationTime() + 5);

        vm.expectRevert(Core4Mica.TabExpired.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_PreviouslyRemunerated() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 2 ether}();
        vm.prank(user1);
        core4Mica.lock(1 ether);

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        core4Mica.remunerate(g, 0x0);

        vm.expectRevert(Core4Mica.TabPreviouslyRemunerated.selector);

        // second remuneration attempt on the same tab
        g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 37, 0.75 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_TabAlreadyPaid() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        core4Mica.recordPayment(tab_id, 0.6 ether);

        vm.expectRevert(Core4Mica.TabAlreadyPaid.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }

    function test_Remunerate_Revert_InvalidSignature() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x1);
    }

    function test_Remunerate_Revert_DoubleSpending() public {
        vm.deal(user1, 3 ether);

        // user1 deposits fewer than the later remuneration claim
        vm.prank(user1);
        core4Mica.deposit{value: 0.25 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, 0x0);
    }
}
