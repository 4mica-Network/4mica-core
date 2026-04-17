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

    /// @dev Finds the smallest gross such that netYieldFromGross(gross, feeBps) == desiredNet.
    /// The initial ceil-rounded estimate is within 1 unit of the answer, so each correction
    /// loop runs at most 1 iteration in practice (bounded by the mulDiv rounding error).
    function grossForNetYield(uint256 desiredNet, uint256 feeBps) internal pure returns (uint256) {
        if (desiredNet == 0 || feeBps == 0) return desiredNet;

        uint256 denominator = BASIS_POINTS - feeBps;
        uint256 gross = Math.mulDiv(desiredNet, BASIS_POINTS, denominator, Math.Rounding.Ceil);
        while (netYieldFromGross(gross, feeBps) > desiredNet) {
            gross--;
        }
        while (netYieldFromGross(gross + 1, feeBps) <= desiredNet) {
            gross++;
        }
        return gross;
    }
}
