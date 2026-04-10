// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

library Core4MicaAccounting {
    uint256 internal constant RAY = 1e27;

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
        return Math.mulDiv(gross, feeBps, 10_000);
    }

    function netYieldFromGross(uint256 gross, uint256 feeBps) internal pure returns (uint256) {
        return gross - protocolShareFromGross(gross, feeBps);
    }

    function grossForNetYield(uint256 desiredNet, uint256 feeBps) internal pure returns (uint256) {
        if (desiredNet == 0 || feeBps == 0) return desiredNet;

        uint256 denominator = 10_000 - feeBps;
        uint256 gross = Math.mulDiv(desiredNet, 10_000, denominator, Math.Rounding.Ceil);
        while (netYieldFromGross(gross, feeBps) > desiredNet) {
            gross--;
        }
        while (netYieldFromGross(gross + 1, feeBps) <= desiredNet) {
            gross++;
        }
        return gross;
    }
}
