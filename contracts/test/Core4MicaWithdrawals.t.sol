// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaWithdrawalsTest is Core4MicaTestBase {
    function test_RequestWithdrawal() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalRequested(
            USER1,
            ETH_ASSET,
            block.timestamp,
            1 ether
        );

        core4Mica.requestWithdrawal(1 ether);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 2 ether);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, 1 ether);
    }

    function test_RequestWithdrawal_WithExplicitEthAsset() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 3 ether}();

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalRequested(
            USER1,
            ETH_ASSET,
            block.timestamp,
            2 ether
        );
        core4Mica.requestWithdrawal(ETH_ASSET, 2 ether);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 3 ether);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, 2 ether);
    }

    function test_RequestWithdrawal_OverwritesPrevious() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 5 ether}();

        core4Mica.requestWithdrawal(1 ether);

        vm.warp(block.timestamp + 2500);

        core4Mica.requestWithdrawal(3 ether);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 5 ether);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, 3 ether);
    }

    function test_RequestWithdrawal_Stablecoin() public {
        uint256 depositAmount = 5_000 ether;
        uint256 withdrawAmount = 2_000 ether;
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), depositAmount);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalRequested(
            USER1,
            address(usdc),
            block.timestamp,
            withdrawAmount
        );
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), withdrawAmount);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 pendingAmount
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, depositAmount);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(pendingAmount, withdrawAmount);

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(
            USER1,
            address(usdc),
            withdrawAmount
        );
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));

        (
            uint256 collateralPost,
            uint256 withdrawalTimestampPost,
            uint256 pendingAmountPost
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateralPost, depositAmount - withdrawAmount);
        assertEq(withdrawalTimestampPost, 0);
        assertEq(pendingAmountPost, 0);
    }

    function test_RequestWithdrawal_Stablecoin_USDT() public {
        uint256 depositAmount = 4_000 ether;
        uint256 withdrawAmount = 1_500 ether;
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdt), depositAmount);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalRequested(
            USER1,
            address(usdt),
            block.timestamp,
            withdrawAmount
        );
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdt), withdrawAmount);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 pendingAmount
        ) = core4Mica.getUser(USER1, address(usdt));
        assertEq(collateral, depositAmount);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(pendingAmount, withdrawAmount);

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(
            USER1,
            address(usdt),
            withdrawAmount
        );
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdt));

        (
            uint256 collateralPost,
            uint256 withdrawalTimestampPost,
            uint256 pendingAmountPost
        ) = core4Mica.getUser(USER1, address(usdt));
        assertEq(collateralPost, depositAmount - withdrawAmount);
        assertEq(withdrawalTimestampPost, 0);
        assertEq(pendingAmountPost, 0);
    }

    function test_RequestWithdrawal_Stablecoin_RevertUnsupportedAsset() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(0x999)
            )
        );
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(0x999), 1);
    }

    function test_RequestWithdrawal_Stablecoin_RevertTooMuch() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 100 ether);

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 200 ether);
    }

    function test_RequestWithdrawal_Revert_AmountZero() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestWithdrawal(0);
    }

    function test_RequestWithdrawal_Revert_TooMuch() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestWithdrawal(2 ether);
    }

    function test_CancelWithdrawal() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.requestWithdrawal(1 ether);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalCanceled(USER1, ETH_ASSET);

        core4Mica.cancelWithdrawal();
        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 2 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_CancelWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.cancelWithdrawal();
    }

    function test_CancelWithdrawal_Stablecoin() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 100 ether);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 40 ether);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.WithdrawalCanceled(USER1, address(usdc));

        vm.prank(USER1);
        core4Mica.cancelWithdrawal(address(usdc));

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 pendingAmount
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, 100 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(pendingAmount, 0);
    }

    function test_CancelWithdrawal_Stablecoin_RevertNoRequest() public {
        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        vm.prank(USER1);
        core4Mica.cancelWithdrawal(address(usdc));
    }

    function test_FinalizeWithdrawal_FullAmount() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.requestWithdrawal(1 ether);

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(USER1, ETH_ASSET, 1 ether);

        assertEq(USER1.balance, 3 ether);
        core4Mica.finalizeWithdrawal();
        assertEq(USER1.balance, 4 ether);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 1 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_NotFullAmount() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 5 ether}();

        uint256 tabTimestamp = 1;
        uint256 withdrawalTimestamp = 1;
        vm.prank(USER1);
        core4Mica.requestWithdrawal(4 ether);

        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);
        Guarantee memory g = _ethGuarantee(
            0x1234,
            tabTimestamp,
            USER1,
            USER2,
            17,
            3 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        core4Mica.remunerate(guaranteeData, signature);
        (
            uint256 collateral,
            uint256 storedTimestamp,
            uint256 storedAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 2 ether);
        assertEq(storedTimestamp, withdrawalTimestamp);
        assertEq(storedAmount, 1 ether);

        vm.warp(tabTimestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(USER1, ETH_ASSET, 1 ether);

        assertEq(USER1.balance, 0 ether);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        assertEq(USER1.balance, 1 ether);

        (collateral, storedTimestamp, storedAmount) = core4Mica.getUser(USER1);
        assertEq(collateral, 1 ether);
        assertEq(storedTimestamp, 0);
        assertEq(storedAmount, 0);
    }

    function test_FinalizeWithdrawal_CollateralGone() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 5 ether}();

        uint256 tabTimestamp = 1;

        vm.prank(USER1);
        core4Mica.requestWithdrawal(2 ether);

        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Guarantee memory g = _ethGuarantee(
            0x1234,
            tabTimestamp,
            USER1,
            USER2,
            17,
            5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        core4Mica.remunerate(guaranteeData, signature);

        vm.warp(tabTimestamp + core4Mica.withdrawalGracePeriod());

        assertEq(USER1.balance, 0 ether);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        assertEq(USER1.balance, 0 ether);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_FullCollateral() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.prank(USER1);
        core4Mica.requestWithdrawal(1 ether);

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(USER1, ETH_ASSET, 1 ether);

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();

        (uint256 collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0);
        assertEq(USER1.balance, 5 ether);
    }

    function test_FinalizeWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.finalizeWithdrawal();
    }

    function test_FinalizeWithdrawal_Revert_GracePeriodNotElapsed() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 4 ether}();
        core4Mica.requestWithdrawal(2 ether);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawal();
    }

    function test_FinalizeWithdrawal_Stablecoin_Revert_NoWithdrawalRequested()
        public
    {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 100 ether);

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));
    }

    function test_FinalizeWithdrawal_Stablecoin_Revert_GracePeriodNotElapsed()
        public
    {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 100 ether);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 25 ether);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(usdc));
    }

    function test_FinalizeWithdrawal_Revert_UnsupportedAsset() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(0x999)
            )
        );
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal(address(0x999));
    }

    function test_MultipleAssetWithdrawalsRemainIndependent() public {
        vm.deal(USER1, 10 ether);
        vm.startPrank(USER1);
        core4Mica.deposit{value: 6 ether}();
        core4Mica.depositStablecoin(address(usdc), 600 ether);
        vm.stopPrank();

        vm.prank(USER1);
        core4Mica.requestWithdrawal(4 ether);
        vm.warp(block.timestamp + 1);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 250 ether);

        (
            uint256 ethCollateral,
            uint256 ethTimestamp,
            uint256 ethAmount
        ) = core4Mica.getUser(USER1);
        (
            uint256 usdcCollateral,
            uint256 usdcTimestamp,
            uint256 usdcAmount
        ) = core4Mica.getUser(USER1, address(usdc));

        assertEq(ethCollateral, 6 ether);
        assertEq(usdcCollateral, 600 ether);
        assertGt(ethTimestamp, 0);
        assertGt(usdcTimestamp, 0);
        assertEq(ethAmount, 4 ether);
        assertEq(usdcAmount, 250 ether);
        assertTrue(usdcTimestamp >= ethTimestamp);
    }
}
