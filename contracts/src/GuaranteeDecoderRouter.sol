// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {Guarantee, IGuaranteeDecoder} from "./Core4Mica.sol";
import {IGuaranteeVersionModule} from "./interfaces/IGuaranteeVersionModule.sol";

/// @notice Routes versioned guarantee payloads to per-version decoder modules.
/// @dev Intended for guarantee versions > 1.
contract GuaranteeDecoderRouter is IGuaranteeDecoder, AccessManaged {
    error InvalidVersion(uint64 version);
    error InvalidModule(address module);
    error UnknownVersion(uint64 version);
    error FrozenVersion(uint64 version);
    error ModuleVersionMismatch(uint64 expected, uint64 actual);

    event VersionModuleSet(
        uint64 indexed version,
        address indexed module,
        address indexed updatedBy
    );
    event VersionFrozen(uint64 indexed version, address indexed frozenBy);

    mapping(uint64 => address) public moduleByVersion;
    mapping(uint64 => bool) public isVersionFrozen;

    constructor(address manager) AccessManaged(manager) {}

    function setVersionModule(uint64 version, address module) external restricted {
        if (version == 0) revert InvalidVersion(version);
        if (isVersionFrozen[version]) revert FrozenVersion(version);
        if (module == address(0) || module.code.length == 0) {
            revert InvalidModule(module);
        }

        moduleByVersion[version] = module;
        emit VersionModuleSet(version, module, msg.sender);
    }

    function freezeVersion(uint64 version) external restricted {
        if (version == 0) revert InvalidVersion(version);
        if (moduleByVersion[version] == address(0)) revert UnknownVersion(version);
        if (isVersionFrozen[version]) revert FrozenVersion(version);

        isVersionFrozen[version] = true;
        emit VersionFrozen(version, msg.sender);
    }

    function decode(bytes calldata data) external view override returns (Guarantee memory) {
        (uint64 version, bytes memory payload) = abi.decode(data, (uint64, bytes));
        address module = moduleByVersion[version];
        if (module == address(0)) revert UnknownVersion(version);

        Guarantee memory guarantee = IGuaranteeVersionModule(module).decodeModule(payload);
        if (guarantee.version != version) {
            revert ModuleVersionMismatch(version, guarantee.version);
        }
        return guarantee;
    }
}
