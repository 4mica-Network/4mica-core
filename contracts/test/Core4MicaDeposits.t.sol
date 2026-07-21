// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase, MockERC20} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";

contract Core4MicaDepositsTest is Core4MicaTestBase {
    function test_Deposit() public {
        vm.startPrank(USER1);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(USER1, ETH_ASSET, 1 ether);

        core4Mica.deposit{value: 1 ether}();

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) = core4Mica.getUser(USER1);
        assertEq(collateral, 1 ether, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    function test_Deposit_MultipleDepositsAccumulate() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 3 ether}();

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) = core4Mica.getUser(USER1);
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

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) =
            core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, amount);
        assertEq(withdrawTimestamp, 0);
        assertEq(withdrawAmount, 0);
        assertEq(usdc.balanceOf(USER1), starting - amount);
        assertEq(usdc.balanceOf(address(core4Mica)), 0);
        assertEq(usdc.balanceOf(address(mockPool)), amount);
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
        MockERC20 fake = new MockERC20("Fake", "FAKE", 6);
        fake.mint(USER1, 100 ether);
        vm.prank(USER1);
        fake.approve(address(core4Mica), type(uint256).max);

        vm.expectRevert(abi.encodeWithSelector(Core4Mica.UnsupportedAsset.selector, address(fake)));
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(fake), 10 ether);
    }

    function test_DepositStablecoin_RevertAmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 0);
    }

    /// A deposit too small to mint even one scaled aToken unit (dust relative to the liquidity
    /// index) would credit face-value principal with no scaled backing, so it must revert. (audit L-1)
    function test_DepositStablecoin_RevertZeroScaledCredit() public {
        // Advance the liquidity index above RAY so a 1-wei deposit rounds down to 0 scaled.
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ZeroCollateralCredit.selector, address(usdc), 1));
        core4Mica.depositStablecoin(address(usdc), 1);
    }

    /// Boundary: the smallest deposit that mints exactly one scaled unit still succeeds.
    function test_DepositStablecoin_MinScaledCreditSucceeds() public {
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 2); // mulDiv(2, RAY, 2*RAY) = 1 scaled
        assertEq(core4Mica.collateral(USER1, address(usdc)), 2, "min deposit credited");
    }

    function test_DepositStablecoin_USDT() public {
        uint256 amount = 750 ether;
        uint256 starting = usdt.balanceOf(USER1);

        vm.prank(USER1);
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(USER1, address(usdt), amount);
        core4Mica.depositStablecoin(address(usdt), amount);

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) =
            core4Mica.getUser(USER1, address(usdt));
        assertEq(collateral, amount);
        assertEq(withdrawTimestamp, 0);
        assertEq(withdrawAmount, 0);
        assertEq(usdt.balanceOf(USER1), starting - amount);
        assertEq(usdt.balanceOf(address(core4Mica)), 0);
        assertEq(usdt.balanceOf(address(mockPool)), amount);
    }

    // ========================= Edge cases =========================

    /// No prior ERC-20 approval to the contract → the underlying `transferFrom` reverts.
    function test_DepositStablecoin_RevertNoApproval() public {
        usdc.mint(USER2, 1_000 ether); // USER2 has balance but never approved the contract
        vm.prank(USER2);
        vm.expectRevert(bytes("ALLOWANCE"));
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
    }

    /// Approved but insufficient token balance → the underlying transfer reverts.
    function test_DepositStablecoin_RevertInsufficientBalance() public {
        vm.startPrank(USER2);
        usdc.approve(address(core4Mica), type(uint256).max);
        vm.expectRevert(bytes("BALANCE"));
        core4Mica.depositStablecoin(address(usdc), 1 ether); // USER2 balance is zero
        vm.stopPrank();
    }

    /// Two depositors into the same asset keep isolated balances; the tracked total is their sum.
    function test_DepositStablecoin_TwoUsersIsolated() public {
        usdc.mint(USER2, 1_000_000 ether);
        vm.prank(USER2);
        usdc.approve(address(core4Mica), type(uint256).max);

        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
        vm.prank(USER2);
        core4Mica.depositStablecoin(address(usdc), 2_500 ether);

        assertEq(core4Mica.collateral(USER1, address(usdc)), 1_000 ether, "USER1 isolated");
        assertEq(core4Mica.collateral(USER2, address(usdc)), 2_500 ether, "USER2 isolated");
        // Index is RAY so scaled == underlying; total scaled backs the sum.
        assertEq(core4Mica.totalUserScaledBalance(address(usdc)), 3_500 ether, "total tracked");
        assertEq(core4Mica.contractScaledATokenBalance(address(usdc)), 3_500 ether, "observed backs tracked");
    }

    /// A depositor's withdrawable balance grows with accrued yield (index rising above RAY).
    function test_DepositStablecoin_ReflectsYieldAfterIndexRise() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);

        // Double the liquidity index — the depositor's 1000 scaled now backs 2000 underlying.
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        assertEq(core4Mica.collateral(USER1, address(usdc)), 2_000 ether, "yield reflected in withdrawable");
    }

    /// A fresh deposit made after the index has risen credits the correct (smaller) scaled amount,
    /// and its withdrawable equals its face value (no yield yet).
    function test_DepositStablecoin_AtRaisedIndexCreditsFaceValue() public {
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether); // scaled 1000 at RAY
        mockPool.setNormalizedIncome(address(usdc), 2e27);

        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether); // scaled 500 at 2*RAY

        // Total scaled = 1000 (first) + 500 (second) = 1500; withdrawable = 2000 (yielded) + 1000 = 3000.
        assertEq(core4Mica.totalUserScaledBalance(address(usdc)), 1_500 ether, "scaled reflects index");
        assertEq(core4Mica.collateral(USER1, address(usdc)), 3_000 ether, "withdrawable = yielded + fresh");
    }

    function test_Deposit_ETH_RevertWhenPaused() public {
        core4Mica.pause();
        vm.prank(USER1);
        vm.expectRevert();
        core4Mica.deposit{value: 1 ether}();
    }

    function test_DepositStablecoin_RevertWhenPaused() public {
        core4Mica.pause();
        vm.prank(USER1);
        vm.expectRevert();
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
    }

    /// Depositing while a withdrawal is pending tops up the balance without touching the request.
    function test_DepositStablecoin_DuringPendingWithdrawal() public {
        vm.startPrank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
        core4Mica.requestWithdrawal(address(usdc), 500 ether);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
        vm.stopPrank();

        (uint256 collateral,, uint256 withdrawAmount) = core4Mica.getUser(USER1, address(usdc));
        assertEq(collateral, 2_000 ether, "balance topped up");
        assertEq(withdrawAmount, 500 ether, "pending request unchanged");
    }

    /// ETH deposits credit msg.sender only.
    function test_Deposit_ETH_CreditsMsgSenderOnly() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 3 ether}();
        assertEq(core4Mica.collateral(USER1), 3 ether, "depositor credited");
        assertEq(core4Mica.collateral(USER2), 0, "other user not credited");
    }

    /// After a mix of deposits the on-chain scaled balance exactly backs the tracked user total.
    function test_DepositStablecoin_ReconciliationInvariantHolds() public {
        vm.startPrank(USER1);
        core4Mica.depositStablecoin(address(usdc), 1_000 ether);
        core4Mica.depositStablecoin(address(usdc), 250 ether);
        core4Mica.depositStablecoin(address(usdc), 7 ether);
        vm.stopPrank();

        assertEq(
            core4Mica.contractScaledATokenBalance(address(usdc)),
            core4Mica.totalUserScaledBalance(address(usdc)),
            "observed == tracked user scaled"
        );
    }
}
