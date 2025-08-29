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
            _asSingletonArray(Core4Mica.registerUser.selector),
            USER_ROLE
        );
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

    // === Registration ===
    function testRegisterUser() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        (uint256 collateral, , uint256 available, ) = core4Mica.getUser(user1);
        assertEq(collateral, minDeposit);
        assertEq(available, minDeposit);
    }

    function test_RevertRegisterInsufficientFunds() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(); // expect revert
        core4Mica.registerUser{value: 1}();
    }

    function test_RevertDoubleRegister() public {
        vm.deal(user1, 1 ether);
        vm.startPrank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.expectRevert(); // expect revert
        core4Mica.registerUser{value: minDeposit}();
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

    function test_RevertWithdrawTooMuch() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.prank(user1);
        vm.expectRevert()
        core4Mica.withdrawCollateral(minDeposit * 2);
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

    function test_RevertFinalizeBeforeGrace() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        core4Mica.registerUser{value: minDeposit}();

        vm.prank(user1);
        core4Mica.requestDeregistration();

        vm.prank(user1);
        vm.expectRevert(); // expect revert
        core4Mica.finalizeDeregistration();
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
