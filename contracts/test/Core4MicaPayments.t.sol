// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaPaymentsTest is Core4MicaTestBase {
    function test_RecordPayment() public {
        (uint256 paid, bool remunerated, address asset) = core4Mica
            .getPaymentStatus(0x1234);
        assertEq(paid, 0);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(0x1234, ETH_ASSET, 1 ether);

        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, ETH_ASSET, 1 ether);

        (paid, remunerated, asset) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(0x1234, ETH_ASSET, 2 ether);

        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, ETH_ASSET, 2 ether);

        (paid, remunerated, asset) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 3 ether);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);
    }

    function test_RecordPayment_Stablecoin() public {
        uint256 tabId = 0x5678;
        (uint256 paid, bool remunerated, address asset) = core4Mica
            .getPaymentStatus(tabId);
        assertEq(paid, 0);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(tabId, address(usdc), 500 ether);
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, address(usdc), 500 ether);

        (paid, remunerated, asset) = core4Mica.getPaymentStatus(tabId);
        assertEq(paid, 500 ether);
        assertFalse(remunerated);
        assertEq(asset, address(usdc));
    }

    function test_RecordPayment_Stablecoin_USDT() public {
        uint256 tabId = 0x6789;
        (uint256 paid, bool remunerated, address asset) = core4Mica
            .getPaymentStatus(tabId);
        assertEq(paid, 0);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(tabId, address(usdt), 750 ether);
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, address(usdt), 750 ether);

        (paid, remunerated, asset) = core4Mica.getPaymentStatus(tabId);
        assertEq(paid, 750 ether);
        assertFalse(remunerated);
        assertEq(asset, address(usdt));
    }

    function test_RecordPayment_Revert_DifferentAsset() public {
        uint256 tabId = 0xABCD;

        // Record first payment with ETH
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, ETH_ASSET, 1 ether);

        (uint256 paid, bool remunerated, address asset) = core4Mica
            .getPaymentStatus(tabId);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);

        // Try to record second payment with USDC - should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.InvalidAsset.selector,
                address(usdc)
            )
        );
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, address(usdc), 100 ether);

        // Verify state hasn't changed
        (paid, remunerated, asset) = core4Mica.getPaymentStatus(tabId);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);
        assertEq(asset, ETH_ASSET);
    }

    function test_RecordPayment_Revert_Unauthorized() public {
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.recordPayment(0x1234, ETH_ASSET, 0);
    }

    function test_RecordPayment_Revert_AmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, ETH_ASSET, 0);
    }

    function test_RecordPayment_Stablecoin_RevertUnsupportedAsset() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(0x777)
            )
        );
        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, address(0x777), 1 ether);
    }

    function test_PayTabInERC20Token_Success() public {
        uint256 tabId = 0xBEEF;
        address recipient = address(0x999);
        uint256 amount = 100 ether;

        // Setup: mint and approve USDC for OPERATOR
        usdc.mint(OPERATOR, 1_000 ether);
        vm.prank(OPERATOR);
        usdc.approve(address(core4Mica), type(uint256).max);

        uint256 operatorBalanceBefore = usdc.balanceOf(OPERATOR);
        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);

        // Expect events
        vm.expectEmit(true, true, true, true);
        emit Core4Mica.TabPaid(tabId, address(usdc), OPERATOR, recipient, amount);

        // Pay tab in USDC
        vm.prank(OPERATOR);
        core4Mica.payTabInERC20Token(tabId, address(usdc), amount, recipient);

        // Verify balances changed correctly
        assertEq(usdc.balanceOf(OPERATOR), operatorBalanceBefore - amount);
        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + amount);
    }

    function test_PayTabInERC20Token_Success_USDT() public {
        uint256 tabId = 0xCAFE;
        address recipient = address(0x888);
        uint256 amount = 250 ether;

        usdt.mint(OPERATOR, 1_000 ether);
        vm.prank(OPERATOR);
        usdt.approve(address(core4Mica), type(uint256).max);

        uint256 operatorBalanceBefore = usdt.balanceOf(OPERATOR);
        uint256 recipientBalanceBefore = usdt.balanceOf(recipient);

        vm.expectEmit(true, true, true, true);
        emit Core4Mica.TabPaid(tabId, address(usdt), OPERATOR, recipient, amount);

        vm.prank(OPERATOR);
        core4Mica.payTabInERC20Token(tabId, address(usdt), amount, recipient);

        assertEq(usdt.balanceOf(OPERATOR), operatorBalanceBefore - amount);
        assertEq(usdt.balanceOf(recipient), recipientBalanceBefore + amount);
    }

    function test_PayTabInERC20Token_RevertUnsupportedAsset() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(0x123)
            )
        );
        vm.prank(OPERATOR);
        core4Mica.payTabInERC20Token(0xBEEF, address(0x123), 1 ether, USER1);
    }

    function test_PayTabInERC20Token_RevertAmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(OPERATOR);
        core4Mica.payTabInERC20Token(0xBEEF, address(usdc), 0, USER1);
    }

    function test_PayTabInERC20Token_RevertInvalidRecipient() public {
        vm.expectRevert(Core4Mica.InvalidRecipient.selector);
        vm.prank(OPERATOR);
        core4Mica.payTabInERC20Token(0xBEEF, address(usdc), 1 ether, address(0));
    }
}
