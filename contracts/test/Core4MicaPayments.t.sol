// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaPaymentsTest is Core4MicaTestBase {
    function test_RecordPayment() public {
        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 0);
        assertFalse(remunerated);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(0x1234, ETH_ASSET, 1 ether);

        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, ETH_ASSET, 1 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(0x1234, ETH_ASSET, 2 ether);

        vm.prank(OPERATOR);
        core4Mica.recordPayment(0x1234, ETH_ASSET, 2 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 3 ether);
        assertFalse(remunerated);
    }

    function test_RecordPayment_Stablecoin() public {
        uint256 tabId = 0x5678;
        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(
            tabId,
            address(usdc)
        );
        assertEq(paid, 0);
        assertFalse(remunerated);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.PaymentRecorded(tabId, address(usdc), 500 ether);
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, address(usdc), 500 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(
            tabId,
            address(usdc)
        );
        assertEq(paid, 500 ether);
        assertFalse(remunerated);
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

}
