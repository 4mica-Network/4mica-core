// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice A signed 4mica payment guarantee, as decoded from its versioned wire encoding.
/// Shared by [`GuaranteeVerifier`], the decoder router, and per-version decoder modules.
struct Guarantee {
    bytes32 domain;
    uint256 cycleId;
    uint256 reqId;
    address client;
    address recipient;
    uint256 amount;
    address asset;
    uint64 timestamp;
    uint64 version;
}

/// @notice Per-version decoder for the inner guarantee payload. Version 1 is decoded inline by
/// [`GuaranteeVerifier`]; every later version delegates to one of these.
interface IGuaranteeDecoder {
    function decode(bytes calldata data) external view returns (Guarantee memory);
}
