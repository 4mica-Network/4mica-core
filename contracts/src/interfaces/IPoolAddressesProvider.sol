// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IPoolAddressesProvider {
    function getPool() external view returns (address);
    function getPoolDataProvider() external view returns (address);
}
