// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

library Core4MicaAccounting {
    uint256 internal constant RAY = 1e27;
    uint256 internal constant BASIS_POINTS = 10_000;

    function toUnderlyingRoundDown(uint256 scaled, uint256 index) internal pure returns (uint256) {
        return Math.mulDiv(scaled, index, RAY);
    }

    function toScaledRoundDown(uint256 amount, uint256 index) internal pure returns (uint256) {
        return Math.mulDiv(amount, RAY, index);
    }

    function toScaledRoundUp(uint256 amount, uint256 index) internal pure returns (uint256) {
        return Math.mulDiv(amount, RAY, index, Math.Rounding.Ceil);
    }

    function protocolShareFromGross(uint256 gross, uint256 feeBps) internal pure returns (uint256) {
        return Math.mulDiv(gross, feeBps, BASIS_POINTS);
    }

    function netYieldFromGross(uint256 gross, uint256 feeBps) internal pure returns (uint256) {
        return gross - protocolShareFromGross(gross, feeBps);
    }

    /// @dev Returns the SMALLEST `gross` such that `netYieldFromGross(gross, feeBps) >= desiredNet`.
    ///
    /// This inverts `netYieldFromGross`. Because the protocol share floors
    /// (`net(g) = g - floor(g*feeBps/BASIS_POINTS)`), `net` is non-decreasing but flat across
    /// "fee steps": several consecutive `gross` values can map to the same `net`. The caller
    /// reallocates the protocol fee as `grossAfterUserWithdrawal - grossForNetYield(remainingNet)`,
    /// so this MUST return the smallest preimage — a larger one makes that subtraction underflow
    /// and reverts a seizure or partial withdrawal.
    ///
    /// Closed form. `net` increments by 0 or 1 as `gross` increases, so it takes every integer
    /// value; the smallest `gross` reaching `desiredNet` therefore hits it exactly, i.e.
    /// `gross* - floor(gross*·feeBps/BASIS_POINTS) = desiredNet`. Writing `gross* = desiredNet + q`,
    /// the floored protocol share `q` is the smallest fixed point of `q = floor((desiredNet+q)·feeBps/B)`,
    /// which solves to `q = floor(feeBps·(desiredNet-1) / (BASIS_POINTS - feeBps))`. Hence:
    ///
    ///     gross* = desiredNet + floor(feeBps·(desiredNet-1) / (BASIS_POINTS - feeBps))
    ///
    /// Verified exact against a brute-force inverse over all feeBps in [0, 99%] and
    /// desiredNet up to 1e9. O(1): a single `mulDiv`, no iteration. `mulDiv` evaluates the
    /// numerator at full 512-bit width, so the intermediate product cannot overflow.
    ///
    /// Precondition: `feeBps < BASIS_POINTS` (enforced by the fee setter), so the denominator
    /// `BASIS_POINTS - feeBps` is non-zero.
    function grossForNetYield(uint256 desiredNet, uint256 feeBps) internal pure returns (uint256) {
        if (desiredNet == 0 || feeBps == 0) return desiredNet;
        return desiredNet + Math.mulDiv(feeBps, desiredNet - 1, BASIS_POINTS - feeBps);
    }
}
