// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Guarantee} from "../Core4Mica.sol";

/// @notice Per-version guarantee module used by GuaranteeDecoderRouter.
interface IGuaranteeVersionModule {
    function decodeModule(bytes calldata payload)
        external
        view
        returns (Guarantee memory);
}
