// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaDepositsTest is Core4MicaTestBase {
    function test_Deposit() public {
        vm.startPrank(USER1);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(USER1, ETH_ASSET, 1 ether);

        core4Mica.deposit{value: 1 ether}();

        (
            uint256 collateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 1 ether, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    function test_Deposit_MultipleDepositsAccumulate() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 3 ether}();

        (
            uint256 collateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 5 ether, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    function test_DepositStablecoin() public {
        uint256 amount = 1_000 ether;
        uint256 starting = usdc.balanceOf(USER1);

        vm.prank(USER1);
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(USER1, address(usdc), amount);
        core4Mica.depositStablecoin(address(usdc), amount);

        (
            uint256 collateral,
            uint256 withdrawTimestamp,
            uint256 withdrawAmount
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, amount);
        assertEq(withdrawTimestamp, 0);
        assertEq(withdrawAmount, 0);
        assertEq(usdc.balanceOf(USER1), starting - amount);
        assertEq(usdc.balanceOf(address(core4Mica)), amount);
    }

    function test_Deposit_RevertZeroEther() public {
        vm.prank(USER1);
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.deposit{value: 0}();
    }

    function test_CollateralViewStablecoin() public {
        uint256 amount = 2_500 ether;
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), amount);

        uint256 ethCollateral = core4Mica.collateral(USER1);
        uint256 stableCollateral = core4Mica.collateral(USER1, address(usdc));
        assertEq(ethCollateral, 0);
        assertEq(stableCollateral, amount);
    }

    function test_DepositStablecoin_RevertUnsupportedAsset() public {
        MockERC20 fake = new MockERC20("Fake", "FAKE");
        fake.mint(USER1, 100 ether);
        vm.prank(USER1);
        fake.approve(address(core4Mica), type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(fake)
            )
        );
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(fake), 10 ether);
    }

    function test_DepositStablecoin_RevertAmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 0);
    }
}
