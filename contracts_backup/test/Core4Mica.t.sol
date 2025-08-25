// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/Core4Mica.sol";

contract Core4MicaTest is Test {
    Core4Mica core4Mica;
    address manager;
    address user1 = address(0x111);
    address user2 = address(0x222);

    uint256 minDeposit = 1e15; // 0.001 ETH

    function setUp() public {
        manager = address(this); // test contract acts as manager
        core4Mica = new Core4Mica(manager);

        // Set smaller deposit for testing
        core4Mica.setMinDepositAmount(minDeposit);
    }

    // === Registration ===
    function testRegisterUser() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        (uint256 collateral, , uint256 available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(available, minDeposit);
    }

    function testFailRegisterInsufficientFunds() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: 1}(); // should revert
    }

    function testFailDoubleRegister() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.registerUser{value: minDeposit}();
        core4Mica.registerUser{value: minDeposit}(); // should revert
    }

    // === Deposits / Withdrawals ===
    function testAddDepositAndWithdraw() public {
        vm.deal(user1, 2 ether);
        vm.startPrank(user1);
        core4Mica.registerUser{value: minDeposit}();
        core4Mica.addDeposit{value: minDeposit}();

        (uint256 collateral, , uint256 available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit * 2);
        assertEq(available, minDeposit * 2);

        core4Mica.withdrawCollateral(minDeposit);
        (collateral, , available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(available, minDeposit);
    }

    function testFailWithdrawTooMuch() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.prank(user1);
        core4Mica.withdrawCollateral(minDeposit * 2); // should revert
    }

    // === Locking Collateral ===
    function testManagerCanLockCollateral() public {
        vm.deal(user1, 3 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit * 3}();

        core4Mica.lockCollateral(user1, minDeposit);

        (, , uint256 available, ) = core4Mica.getUser(user1);
        (, uint256 locked, , ) = core4Mica.getUser(user1);

        assertEq(locked, minDeposit);
        assertEq(available, minDeposit * 2);
    }

    // === Deregistration ===
    function testRequestAndFinalizeDeregistration() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.gracePeriod());

        vm.prank(user1);
        core4Mica.finalizeDeregistration();

        (uint256 collateral, , , ) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
    }

    function testFailFinalizeBeforeGrace() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        vm.prank(user1);
        core4Mica.finalizeDeregistration(); // should revert
    }

    // === MakeWhole ===
    function testMakeWholePayout() public {
        vm.deal(user1, 3 ether);
        vm.deal(user2, 0);

        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit * 3}();

        core4Mica.lockCollateral(user1, minDeposit);

        uint256 beforeBal = user2.balance;

        core4Mica.makeWhole(user1, user2, minDeposit);

        uint256 afterBal = user2.balance;
        assertEq(afterBal - beforeBal, minDeposit);

        (, uint256 locked, , ) = core4Mica.getUser(user1);
        (uint256 collateral, , , ) = core4Mica.getUser(user1);

        assertEq(locked, 0);
        assertEq(collateral, minDeposit * 2);
    }
}
