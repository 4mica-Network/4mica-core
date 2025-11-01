// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaRemunerationTest is Core4MicaTestBase {
    function test_Remunerate() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x1234;
        uint256 reqId = 17;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            tabId,
            tabTimestamp,
            USER1,
            USER2,
            reqId,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tabId, ETH_ASSET, 0.5 ether);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        assertEq(USER2.balance, 0.5 ether);
        (uint256 collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.5 ether);

        (uint256 paid, bool remunerated, address asset) = core4Mica
            .getPaymentStatus(tabId);
        assertEq(paid, 0);
        assertTrue(remunerated);
        assertEq(asset, ETH_ASSET);
    }

    function test_Remunerate_PartiallyPaidTab() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x1234;
        uint256 reqId = 17;

        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, ETH_ASSET, 0.25 ether);

        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            tabId,
            tabTimestamp,
            USER1,
            USER2,
            reqId,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tabId, ETH_ASSET, 0.5 ether);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        assertEq(USER2.balance, 0.5 ether);
        (uint256 collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.5 ether);
    }

    function test_Remunerate_Stablecoin() public {
        uint256 depositAmount = 5_000 ether;
        uint256 remunerationAmount = 1_500 ether;
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), depositAmount);

        uint256 tabId = 0xABCD;
        uint256 reqId = 77;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _guarantee(
            tabId,
            tabTimestamp,
            USER1,
            USER2,
            reqId,
            remunerationAmount,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(
            tabId,
            address(usdc),
            remunerationAmount
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        assertEq(usdc.balanceOf(USER2), remunerationAmount);
        (uint256 collateral, , ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, depositAmount - remunerationAmount);
    }

    function test_Remunerate_Stablecoin_USDT() public {
        uint256 depositAmount = 3_500 ether;
        uint256 remunerationAmount = 1_000 ether;
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdt), depositAmount);

        uint256 tabId = 0x0BEEF;
        uint256 reqId = 99;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _guarantee(
            tabId,
            tabTimestamp,
            USER1,
            USER2,
            reqId,
            remunerationAmount,
            address(usdt)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(
            tabId,
            address(usdt),
            remunerationAmount
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        assertEq(usdt.balanceOf(USER2), remunerationAmount);
        (uint256 collateral, , ) = core4Mica.getUser(USER1, address(usdt));
        assertEq(collateral, depositAmount - remunerationAmount);
    }

    function test_Remunerate_Revert_InvalidAssetForRecordedPayment() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 2 ether}();

        uint256 tabId = 0xFEED;
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, ETH_ASSET, 0.25 ether);

        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _guarantee(
            tabId,
            tabTimestamp,
            USER1,
            USER2,
            41,
            0.5 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.InvalidAsset.selector,
                address(usdc)
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_GuaranteeIssuedBeforeWithdrawalRequestSynchronization()
        public
    {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(block.timestamp + 1 days);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(0.75 ether);

        vm.warp(block.timestamp + core4Mica.synchronizationDelay() - 1);
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.warp(block.timestamp + 15 days);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        (uint256 collateral, , uint256 withdrawalAmount) = core4Mica.getUser(
            USER1
        );
        assertEq(collateral, 0.5 ether);
        assertEq(withdrawalAmount, 0.25 ether);

        vm.warp(block.timestamp + 7 days);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        assertEq(USER1.balance, 4.25 ether);
        (collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.25 ether);
    }

    function test_Remunerate_GuaranteeIssuedAfterWithdrawalRequestSynchronization()
        public
    {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(block.timestamp + 1 days);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(0.75 ether);

        vm.warp(block.timestamp + core4Mica.synchronizationDelay() + 1);
        uint256 amount = 0.24 ether;
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            amount
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        (uint256 collateral, , uint256 withdrawalAmount) = core4Mica.getUser(
            USER1
        );
        assertLe(amount, collateral - withdrawalAmount);

        vm.warp(block.timestamp + 15 days);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
        assertEq(USER2.balance, 0.24 ether);

        (collateral, , withdrawalAmount) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.76 ether);
        assertEq(withdrawalAmount, 0.75 ether);

        vm.warp(block.timestamp + 7 days);
        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        assertEq(USER1.balance, 4.75 ether);
        (collateral, , withdrawalAmount) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.01 ether);
    }

    function test_Remunerate_Revert_AmountZero() public {
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            0,
            USER1,
            USER2,
            17,
            0
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_InvalidRecipient() public {
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            0,
            USER1,
            address(0),
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.InvalidRecipient.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_NotYetOverdue() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.TabNotYetOverdue.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_TabExpired() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.tabExpirationTime() + 5);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            0,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.TabExpired.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_PreviouslyRemunerated() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tabId = 0x1234;
        Core4Mica.Guarantee memory g = _ethGuarantee(
            tabId,
            0,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        core4Mica.remunerate(guaranteeData, signature);

        g = _ethGuarantee(tabId, 0, USER1, USER2, 37, 0.75 ether);
        guaranteeData = _encodeGuaranteeWithVersion(g);
        signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.TabPreviouslyRemunerated.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_TabAlreadyPaid() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tabId = 0x1234;
        vm.prank(OPERATOR);
        core4Mica.recordPayment(tabId, ETH_ASSET, 0.6 ether);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            tabId,
            0,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.TabAlreadyPaid.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_InvalidSignature() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            0,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        bytes32 otherKey = bytes32(
            0x1234123412341234123412341234123412341234123412341234123412341234
        );
        BLS.G2Point memory invalidSignature = _signGuarantee(g, otherKey);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, invalidSignature);
    }

    function test_Remunerate_Revert_DoubleSpending() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 0.25 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            0,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_StablecoinWithoutMatchingCollateral() public {
        vm.warp(block.timestamp + 10 days);
        vm.prank(USER1);
        core4Mica.deposit{value: 2 ether}();

        vm.warp(block.timestamp + core4Mica.remunerationGracePeriod() + 5);
        uint256 tabTimestamp = block.timestamp -
            (core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = _guarantee(
            0xBEEF,
            tabTimestamp,
            USER1,
            USER2,
            11,
            500 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_EthWithoutMatchingCollateral() public {
        vm.warp(block.timestamp + 10 days);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 750 ether);

        vm.warp(block.timestamp + core4Mica.remunerationGracePeriod() + 5);
        uint256 tabTimestamp = block.timestamp -
            (core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0xC0FFEE,
            tabTimestamp,
            USER1,
            USER2,
            12,
            1 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_UnsupportedAsset() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 500 ether);

        Core4Mica.Guarantee memory g = _guarantee(
            0xAAAA,
            10,
            USER1,
            USER2,
            1,
            100 ether,
            address(0xBEEF)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.warp(10 + core4Mica.remunerationGracePeriod() + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(0xBEEF)
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_UsesOnlyAssetCollateral() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 5 ether}();
        core4Mica.depositStablecoin(address(usdc), 500 ether);
        vm.stopPrank();

        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = _guarantee(
            0xCCDD,
            tabTimestamp,
            USER1,
            USER2,
            7,
            200 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        (uint256 ethCollateral, , ) = core4Mica.getUser(USER1);
        (uint256 usdcCollateral, , ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(ethCollateral, 5 ether);
        assertEq(usdcCollateral, 300 ether);
    }

    function test_Remunerate_DifferentAssetDoesNotAffectEthWithdrawal() public {
        vm.warp(block.timestamp + 10 days);
        vm.startPrank(USER1);
        core4Mica.deposit{value: 5 ether}();
        core4Mica.depositStablecoin(address(usdc), 500 ether);
        core4Mica.requestWithdrawal(3 ether);
        (, uint256 requestTimestamp, ) = core4Mica.getUser(USER1);
        vm.stopPrank();

        vm.warp(requestTimestamp + core4Mica.remunerationGracePeriod() + 5);
        uint256 tabTimestamp = block.timestamp -
            (core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = _guarantee(
            0xDD01,
            tabTimestamp,
            USER1,
            USER2,
            21,
            200 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);
        assertEq(withdrawalAmount, 3 ether);
        assertEq(withdrawalTimestamp, requestTimestamp);
        assertEq(collateral, 5 ether);
    }

    function test_Remunerate_DifferentAssetDoesNotAffectStablecoinWithdrawal()
        public
    {
        vm.warp(block.timestamp + 10 days);
        vm.startPrank(USER1);
        core4Mica.deposit{value: 5 ether}();
        core4Mica.depositStablecoin(address(usdc), 500 ether);
        core4Mica.requestWithdrawal(address(usdc), 250 ether);
        (, uint256 requestTimestamp, uint256 requestAmount) = core4Mica.getUser(
            USER1,
            address(usdc)
        );
        assertEq(requestAmount, 250 ether);
        vm.stopPrank();

        vm.warp(requestTimestamp + core4Mica.remunerationGracePeriod() + 5);
        uint256 tabTimestamp = block.timestamp -
            (core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0xDD02,
            tabTimestamp,
            USER1,
            USER2,
            22,
            1 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        (
            uint256 collateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(withdrawalAmount, 250 ether);
        assertEq(withdrawalTimestamp, requestTimestamp);
        assertEq(collateral, 500 ether);
    }

    function test_Remunerate_StablecoinBeforeSynchronizationReducesWithdrawal()
        public
    {
        vm.warp(block.timestamp + 10 days);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 600 ether);

        vm.prank(USER1);
        core4Mica.requestWithdrawal(address(usdc), 400 ether);
        (, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica
            .getUser(USER1, address(usdc));
        assertEq(withdrawalAmount, 400 ether);

        uint256 tabTimestamp = withdrawalTimestamp - 1;
        Core4Mica.Guarantee memory g = _guarantee(
            0xAA01,
            tabTimestamp,
            USER1,
            USER2,
            48,
            150 ether,
            address(usdc)
        );
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        (
            uint256 collateralAfter,
            uint256 withdrawalTimestampAfter,
            uint256 withdrawalAmountAfter
        ) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateralAfter, 450 ether);
        assertEq(withdrawalTimestampAfter, withdrawalTimestamp);
        assertEq(withdrawalAmountAfter, 250 ether);
    }

    function test_DoubleSpend_IllegalGuarantee() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(block.timestamp + 5 days);
        vm.prank(USER1);
        core4Mica.requestWithdrawal(0.75 ether);

        (
            uint256 initialCollateral,
            uint256 withdrawalTimestamp,
            uint256 withdrawalAmount
        ) = core4Mica.getUser(USER1);

        uint256 delay = 2 days;
        vm.warp(block.timestamp + delay);
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            0.5 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.warp(block.timestamp + 20 days);

        vm.prank(USER1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.25 ether);
        assertEq(USER1.balance, 4.75 ether);

        vm.warp(block.timestamp + 6 hours);
        vm.prank(USER2);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        core4Mica.remunerate(guaranteeData, signature);

        assertGt(
            g.timestamp,
            withdrawalTimestamp + core4Mica.synchronizationDelay()
        );
        assertGt(g.amount, initialCollateral - withdrawalAmount);
    }

    function test_Remunerate_TransfersTotalAmountNotAmount() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9999;
        uint256 reqId = 42;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        // Create a guarantee where amount differs from total_amount
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee({
            domain: core4Mica.guaranteeDomainSeparator(),
            tab_id: tabId,
            req_id: reqId,
            client: USER1,
            recipient: USER2,
            amount: 0.3 ether,
            total_amount: 0.7 ether,
            asset: ETH_ASSET,
            timestamp: uint64(tabTimestamp),
            version: 1
        });
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        uint256 user2BalanceBefore = USER2.balance;

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tabId, ETH_ASSET, 0.7 ether);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        // Verify total_amount (0.7 ether) was transferred to recipient, not amount (0.3 ether)
        assertEq(USER2.balance, user2BalanceBefore + 0.7 ether);

        // Verify total_amount (0.7 ether) was deducted from client collateral
        (uint256 collateral, , ) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.3 ether);
    }

    function test_Remunerate_Revert_InsufficientCollateralForTotalAmount()
        public
    {
        vm.prank(USER1);
        core4Mica.deposit{value: 0.5 ether}();

        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        // User has enough for amount (0.3 ether) but not for total_amount (0.8 ether)
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee({
            domain: core4Mica.guaranteeDomainSeparator(),
            tab_id: 0x8888,
            req_id: 55,
            client: USER1,
            recipient: USER2,
            amount: 0.3 ether,
            total_amount: 0.8 ether,
            asset: ETH_ASSET,
            timestamp: uint64(tabTimestamp),
            version: 1
        });
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_Remunerate_Revert_TotalAmountZero() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        // amount is non-zero but total_amount is zero
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee({
            domain: core4Mica.guaranteeDomainSeparator(),
            tab_id: 0x7777,
            req_id: 66,
            client: USER1,
            recipient: USER2,
            amount: 0.5 ether,
            total_amount: 0,
            asset: ETH_ASSET,
            timestamp: uint64(tabTimestamp),
            version: 1
        });
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }
}
