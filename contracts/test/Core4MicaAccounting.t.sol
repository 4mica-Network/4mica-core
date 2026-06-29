// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Core4MicaAccounting} from "../src/libraries/Core4MicaAccounting.sol";

/// Regression coverage for audit 4MCA-H03: the protocol-fee reallocation in
/// `_debitUserStablecoin` must never underflow, which reduces to
/// `grossForNetYield` returning a preimage no larger than the original gross.
contract Core4MicaAccountingTest is Test {
    uint256 internal constant BASIS_POINTS = 10_000;

    /// grossForNetYield must round-trip exactly: its result re-nets to `desiredNet`.
    function testFuzz_grossForNetYield_roundTrips(uint256 gross, uint256 feeBps) public pure {
        feeBps = bound(feeBps, 0, 5_000);
        gross = bound(gross, 0, 1e30);

        uint256 net = Core4MicaAccounting.netYieldFromGross(gross, feeBps);
        uint256 preimage = Core4MicaAccounting.grossForNetYield(net, feeBps);
        assertEq(Core4MicaAccounting.netYieldFromGross(preimage, feeBps), net, "preimage does not re-net");
    }

    /// The smallest-preimage property: the returned gross never exceeds any gross that
    /// produced `net`. This is exactly what prevents the seize-path underflow, since the
    /// fee reallocation computes `gross - grossForNetYield(net(gross))`.
    function testFuzz_grossForNetYield_neverOvershoots(uint256 gross, uint256 feeBps) public pure {
        feeBps = bound(feeBps, 0, 5_000);
        gross = bound(gross, 0, 1e30);

        uint256 net = Core4MicaAccounting.netYieldFromGross(gross, feeBps);
        uint256 preimage = Core4MicaAccounting.grossForNetYield(net, feeBps);
        assertLe(preimage, gross, "grossForNetYield overshot the original gross");
    }

    /// Direct model of the seize-path arithmetic (userYieldWithdrawn == 0): the
    /// subtraction that previously panicked (0x11) must never underflow.
    function testFuzz_seizeFeeReallocation_neverUnderflows(uint256 gross, uint256 feeBps) public pure {
        feeBps = bound(feeBps, 0, 5_000);
        gross = bound(gross, 0, 1e30);

        uint256 userNet = Core4MicaAccounting.netYieldFromGross(gross, feeBps);
        uint256 remainingGross = Core4MicaAccounting.grossForNetYield(userNet, feeBps);
        // Must hold for `gross - remainingGross` to be safe in _debitUserStablecoin.
        assertGe(gross, remainingGross, "remainingGross exceeds gross");
    }

    /// Walk a window of gross values around fee-step boundaries to deterministically
    /// hit the case the fuzzer reaches probabilistically.
    function test_grossForNetYield_feeStepBoundaries() public pure {
        uint256 feeBps = 100; // 1%
        for (uint256 gross = 0; gross < 2_000; gross++) {
            uint256 net = Core4MicaAccounting.netYieldFromGross(gross, feeBps);
            uint256 preimage = Core4MicaAccounting.grossForNetYield(net, feeBps);
            assertLe(preimage, gross, "overshoot at fee-step boundary");
            assertEq(Core4MicaAccounting.netYieldFromGross(preimage, feeBps), net, "round-trip at boundary");
        }
    }
}
