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
    address operator = address(0x333);
    uint256 minDeposit = 1e15; // 0.001 ETH

    uint64 public constant OPERATOR_ROLE = 9;

    bytes32[3] public VALID_SIGNATURE = [bytes32(0), bytes32(0), bytes32(0)];
    bytes32[3] public INVALID_SIGNATURE = [bytes32(uint256(1)), bytes32(0), bytes32(0)];

    function setUp() public {
        manager = new AccessManager(address(this));
        core4Mica = new Core4Mica(address(manager));

        // grant operator the OPERATOR_ROLE so we can record Payments
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.recordPayment.selector),
            OPERATOR_ROLE
        );
        manager.grantRole(OPERATOR_ROLE, address(operator), 0);
    }

    // helper

    function _asSingletonArray(
        bytes4 selector
    ) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    // === Admin Config ===

    function test_SetWithdrawalGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.WithdrawalGracePeriodUpdated(newGrace);
        core4Mica.setWithdrawalGracePeriod(newGrace);

        assertEq(core4Mica.withdrawalGracePeriod(), newGrace);
    }

    function test_SetWithdrawalGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setWithdrawalGracePeriod(0);
    }

    function test_SetWithdrawalGracePeriod_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(operator))
        );
        core4Mica.setWithdrawalGracePeriod(2 days);
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

    function test_SetRemunerationGracePeriod_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(operator))
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

    function test_SetTabExpirationTime_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(user1))
        );
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(operator))
        );
        core4Mica.setTabExpirationTime(2 days);
    }

    // === Deposit ===

    function test_Deposit() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralDeposited(user1, minDeposit);

        core4Mica.deposit{value: minDeposit}();

        (
            uint256 totalCollateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(user1);
        assertEq(totalCollateral, minDeposit, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    function test_Deposit_MultipleDepositsAccumulate() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit}();
        core4Mica.deposit{value: minDeposit}();
        core4Mica.deposit{value: minDeposit * 3}();

        (
            uint256 totalCollateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(user1);
        assertEq(totalCollateral, minDeposit * 5, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    // === Request Withdrawal ===

    function test_RequestWithdrawal() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 2}();

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.WithdrawalRequested(user1, block.timestamp, minDeposit);

        core4Mica.requestWithdrawal(minDeposit);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, minDeposit);
    }

    function test_RequestWithdrawal_OverwritesPrevious() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 5}();

        core4Mica.requestWithdrawal(minDeposit);

        vm.warp(block.timestamp + 2500);

        core4Mica.requestWithdrawal(minDeposit * 3);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 5);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, minDeposit * 3);
    }

    // === Request Withdrawal: Failure cases ===

    function test_RequestWithdrawal_Revert_AmountZero() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestWithdrawal(0);
    }

    function test_RequestWithdrawal_Revert_TooMuch() public {
        vm.deal(user1, 1 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit}();

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestWithdrawal(minDeposit * 2);
    }

    // === Cancel Withdrawal ===

    function test_CancelWithdrawal() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 2}();
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
        core4Mica.deposit{value: minDeposit * 2}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.cancelWithdrawal();
    }

    // === Finalize Withdrawal ===

    function test_FinalizeWithdrawal_FullAmount() public {
        vm.deal(user1, 2 ether);

        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 2}();
        core4Mica.requestWithdrawal(minDeposit);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

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

        vm.prank(user1);
        core4Mica.deposit{value: minDeposit * 5}();

        uint256 tab_timestamp = 1;
        uint256 withdrawal_timestamp = 1;
        vm.prank(user1);
        core4Mica.requestWithdrawal(minDeposit * 4);

        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, minDeposit * 3);
        core4Mica.remunerate(g, VALID_SIGNATURE);
        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(withdrawalTimestamp, withdrawal_timestamp);
        assertEq(withdrawalAmount, minDeposit);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, minDeposit);

        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, minDeposit);

        (collateral, withdrawalTimestamp, withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_CollateralGone() public {
        vm.deal(user1, 0.004 ether);
        vm.prank(user1);
        core4Mica.deposit{value: minDeposit * 4}();

        // user promised something to recipient as part of tab
        uint256 tab_timestamp = 1;

        // user requests withdrawal
        vm.prank(user1);
        core4Mica.requestWithdrawal(minDeposit * 2);

        // fast forward > remuneration period
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        // user did not pay their promise, so
        // recipient comes to collect remuneration
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, minDeposit * 4);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.withdrawalGracePeriod());

        // user gets nothing because their balance was used during remuneration
        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_FullCollateral() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.prank(user1);
        core4Mica.requestWithdrawal(1 ether);

        // Fast-forward past withdrawalGracePeriod
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        // Expect event
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, 1 ether);

        vm.prank(user1);
        core4Mica.finalizeWithdrawal();

        (uint256 collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0, "Collateral not deleted");
        assertEq(address(user1).balance, 1 ether, "User did not receive full collateral");
    }

    // === Finalize Withdrawal: Failure cases ===

    function test_FinalizeWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 4}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.finalizeWithdrawal();
    }

    function test_FinalizeWithdrawal_Revert_GracePeriodNotElapsed() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.deposit{value: minDeposit * 4}();
        core4Mica.requestWithdrawal(minDeposit * 2);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawal();
    }

    // === Record payment ===

    function test_RecordPayment() public {
        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 0);
        assertFalse(remunerated);

        vm.prank(operator);
        core4Mica.recordPayment(0x1234, 1 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);

        vm.prank(operator);
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
        vm.prank(operator);
        core4Mica.recordPayment(0x1234, 0);
    }

    // === Remuneration ===

    function test_Remunerate() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;
        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, 0.5 ether);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        assertEq(user2.balance, 0.5 ether);
        (uint256 collateral,, ) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);

        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(tab_id);
        assertEq(paid, 0);
        assertEq(remunerated, true);
    }

    function test_Remunerate_PartiallyPaidTab() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;

        // core contract is informed that user1 paid user2 half of the tab
        vm.prank(operator);
        core4Mica.recordPayment(tab_id, 0.25 ether);

        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, 0.5 ether);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        // check: user2 is still remunerated for the full amount
        assertEq(user2.balance, 0.5 ether);
        (uint256 collateral,, ) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);
    }

    function test_Remunerate_GuaranteeIssuedBeforeWithdrawalRequestSynchronization() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // One day later, user requests a withdrawal
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        // Less than synchronizationDelay time later, a guarantee is issued.
        vm.warp(vm.getBlockTimestamp() + core4Mica.synchronizationDelay() - 1);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 0.5 ether);

        // user does not pay their tab; 15 days later recipient requests remuneration
        vm.warp(vm.getBlockTimestamp() + 15 days);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        // because the guarantee was issued less than synchronizationDelay after the withdrawal request, the amount
        // is deducted from the request amount
        (uint256 collateral,, uint256 withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);
        assertEq(withdrawal_amount, 0.25 ether);

        // Then a couple days later, user can withdraw the remainder
        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0.25 ether);
        (collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0.25 ether);
    }

    function test_Remunerate_GuaranteeIssuedAfterWithdrawalRequestSynchronization() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // One day later, user requests a withdrawal
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        // More than synchronizationDelay time later, a guarantee is issued.
        // The amount must be less than or equal to the total collateral minus the withdrawal amount.
        // This should be guaranteed by the guarantee issuing party.
        vm.warp(vm.getBlockTimestamp() + core4Mica.synchronizationDelay() + 1);
        uint256 amount = 0.24 ether;
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, amount);
        (uint256 collateral,, uint256 withdrawal_amount) = core4Mica.getUser(user1);
        assertLe(amount, collateral - withdrawal_amount);

        // user does not pay their tab; 15 days later recipient requests remuneration
        vm.warp(vm.getBlockTimestamp() + 15 days);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
        assertEq(user2.balance, 0.24 ether);

        // because the guarantee was issued more than synchronizationDelay after the withdrawal request, the amount
        // is NOT deducted from the request amount
        (collateral,, withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.76 ether);
        assertEq(withdrawal_amount, 0.75 ether);

        // Then a couple days later, user can withdraw the full amount
        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0.75 ether);
        (collateral,, withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.01 ether);
    }

    // === Remunerate: Failure cases ===

    function test_Remunerate_Revert_AmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_InvalidRecipient() public {
        vm.expectRevert(Core4Mica.InvalidRecipient.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, address(0), 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_NotYetOverdue() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.TabNotYetOverdue.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_TabExpired() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.tabExpirationTime() + 5);

        vm.expectRevert(Core4Mica.TabExpired.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_PreviouslyRemunerated() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        vm.expectRevert(Core4Mica.TabPreviouslyRemunerated.selector);

        // second remuneration attempt on the same tab
        g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 37, 0.75 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_TabAlreadyPaid() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        vm.prank(operator);
        core4Mica.recordPayment(tab_id, 0.6 ether);

        vm.expectRevert(Core4Mica.TabAlreadyPaid.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    function test_Remunerate_Revert_InvalidSignature() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, INVALID_SIGNATURE);
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
        core4Mica.remunerate(g, VALID_SIGNATURE);
    }

    // === Double spend prevention tests ===

    function test_DoubleSpend_IllegalGuarantee() public {
        vm.deal(user1, 1 ether);

        // User deposits collateral
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // Later, user requests withdrawal
        vm.warp(vm.getBlockTimestamp() + 5 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        (uint256 initial_collateral, uint256 withdrawal_timestamp, uint256 withdrawal_amount) = core4Mica.getUser(user1);

        // Quite some time after the withdrawal request, a guarantee is signed.
        uint256 delay = 2 days;
        vm.warp(vm.getBlockTimestamp() + delay);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 0.5 ether);

        // The user does not pay this.
        // Also, the recipient (user2) has not requested remuneration yet.
        vm.warp(vm.getBlockTimestamp() + 20 days);

        // Now user withdraws their funds, equal to all funds initially requested be released.
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0.25 ether);
        assertEq(user1.balance, 0.75 ether);

        // some time later, recipient decides to remunerate after all
        vm.warp(vm.getBlockTimestamp() + 6 hours);
        vm.prank(user2);

        // However, this remuneration cannot take place, since insufficient user funds are available.
        // Hence, there is double spending taking place here.
        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        core4Mica.remunerate(g, VALID_SIGNATURE);

        // This double spend took place because
        // 1. a guarantee was issued for a tab that started more than synchronizationDelay after
        //    the withdrawal request came in, and
        assertGt(g.tab_timestamp, withdrawal_timestamp + core4Mica.synchronizationDelay());
        // 2. because the guarantee's amount exceeded the amount of collateral that would be left after the withdrawal
        assertGt(g.amount, initial_collateral - withdrawal_amount);
        // Hence, the guarantee was illegally issued.
    }

    // === Fallback and Receive revert ===

    function test_Receive_Reverts_TransferFailed() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        (bool ok, bytes memory mem) = address(core4Mica).call{value: 0.25 ether}("");
        assert(!ok);
        assertEq(mem, abi.encodeWithSelector(Core4Mica.DirectTransferNotAllowed.selector));
    }

    function test_Fallback_Reverts_TransferFailed() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        (bool ok, bytes memory mem) = address(core4Mica).call{value: 0.25 ether}(abi.encodeWithSignature("nonExistentFunction()"));
        assert(!ok);
    }
}
