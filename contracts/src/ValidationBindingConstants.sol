// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

abstract contract ValidationBindingConstants {
    bytes32 internal constant VALIDATION_SUBJECT_BINDING_DOMAIN_HASH = keccak256("4MICA_VALIDATION_SUBJECT_V1");
    bytes32 internal constant VALIDATION_REQUEST_BINDING_DOMAIN_HASH = keccak256("4MICA_VALIDATION_REQUEST_V2");
    uint64 internal constant GUARANTEE_CLAIMS_VERSION_V2 = 2;
}
