// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IMintableERC20 is IERC20 {
    function mint(address to, uint256 amount) external;
}

contract MockAToken {
    using SafeERC20 for IERC20;

    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    address public immutable underlying;
    address public immutable pool;

    mapping(address => uint256) internal _scaledBalances;

    constructor(address underlying_, address pool_, string memory name_, string memory symbol_) {
        underlying = underlying_;
        pool = pool_;
        name = name_;
        symbol = symbol_;
    }

    function scaledBalanceOf(address user) external view returns (uint256) {
        return _scaledBalances[user];
    }

    function UNDERLYING_ASSET_ADDRESS() external view returns (address) {
        return underlying;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        MockAavePool(pool).transferAToken(msg.sender, to, underlying, amount);
        return true;
    }

    function balanceOf(address user) external view returns (uint256) {
        return MockAavePool(pool).nominalATokenBalance(underlying, user);
    }

    function totalSupply() external pure returns (uint256) {
        return 0;
    }

    function allowance(address, address) external pure returns (uint256) {
        return 0;
    }

    function approve(address, uint256) external pure returns (bool) {
        revert("NOT_SUPPORTED");
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        revert("NOT_SUPPORTED");
    }

    function setScaledBalance(address user, uint256 scaledBalance) external {
        require(msg.sender == pool, "ONLY_POOL");
        _scaledBalances[user] = scaledBalance;
    }
}

contract MockAaveProtocolDataProvider {
    mapping(address => address) public reserveATokens;

    function setReserveAToken(address asset, address aToken) external {
        reserveATokens[asset] = aToken;
    }

    function getReserveTokensAddresses(address asset)
        external
        view
        returns (address aTokenAddress, address stableDebtTokenAddress, address variableDebtTokenAddress)
    {
        return (reserveATokens[asset], address(0), address(0));
    }
}

contract MockPoolAddressesProvider {
    address public pool;
    address public poolDataProvider;

    function setPool(address pool_) external {
        pool = pool_;
    }

    function getPool() external view returns (address) {
        return pool;
    }

    function setPoolDataProvider(address poolDataProvider_) external {
        poolDataProvider = poolDataProvider_;
    }

    function getPoolDataProvider() external view returns (address) {
        return poolDataProvider;
    }
}

contract MockAavePool {
    using SafeERC20 for IERC20;

    uint256 internal constant RAY = 1e27;

    mapping(address => uint256) public normalizedIncome;
    mapping(address => address) public aTokens;
    mapping(address => uint256) public availableLiquidity;
    mapping(address => bool) public supplyShouldRevert;
    mapping(address => uint256) public withdrawShortfall;

    function setReserve(address asset, address aToken, uint256 index) external {
        aTokens[asset] = aToken;
        normalizedIncome[asset] = index;
    }

    function setNormalizedIncome(address asset, uint256 index) external {
        uint256 currentIndex = normalizedIncome[asset];
        if (currentIndex != 0 && availableLiquidity[asset] != 0) {
            uint256 oldLiquidity = availableLiquidity[asset];
            uint256 newLiquidity = Math.mulDiv(oldLiquidity, index, currentIndex);
            if (newLiquidity > oldLiquidity) {
                IMintableERC20(asset).mint(address(this), newLiquidity - oldLiquidity);
            }
            availableLiquidity[asset] = newLiquidity;
        }
        normalizedIncome[asset] = index;
    }

    function setAvailableLiquidity(address asset, uint256 amount) external {
        availableLiquidity[asset] = amount;
    }

    function setSupplyShouldRevert(address asset, bool shouldRevert) external {
        supplyShouldRevert[asset] = shouldRevert;
    }

    function setWithdrawShortfall(address asset, uint256 shortfallAmount) external {
        withdrawShortfall[asset] = shortfallAmount;
    }

    function getReserveNormalizedIncome(address asset) external view returns (uint256) {
        return normalizedIncome[asset];
    }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        require(!supplyShouldRevert[asset], "SUPPLY_REVERT");
        IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        availableLiquidity[asset] += amount;

        MockAToken aToken = MockAToken(aTokens[asset]);
        uint256 scaledCredit = Math.mulDiv(amount, RAY, normalizedIncome[asset]);
        uint256 current = aToken.scaledBalanceOf(onBehalfOf);
        aToken.setScaledBalance(onBehalfOf, current + scaledCredit);
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        MockAToken aToken = MockAToken(aTokens[asset]);
        uint256 shortfall = withdrawShortfall[asset];
        uint256 actualWithdrawn = amount > shortfall ? amount - shortfall : 0;
        if (actualWithdrawn > availableLiquidity[asset]) {
            actualWithdrawn = availableLiquidity[asset];
        }

        uint256 scaledBurn = Math.mulDiv(actualWithdrawn, RAY, normalizedIncome[asset], Math.Rounding.Ceil);
        uint256 current = aToken.scaledBalanceOf(msg.sender);
        require(current >= scaledBurn, "INSUFFICIENT_A_TOKEN");
        aToken.setScaledBalance(msg.sender, current - scaledBurn);
        availableLiquidity[asset] -= actualWithdrawn;
        IERC20(asset).safeTransfer(to, actualWithdrawn);
        return actualWithdrawn;
    }

    function nominalATokenBalance(address asset, address user) external view returns (uint256) {
        return Math.mulDiv(MockAToken(aTokens[asset]).scaledBalanceOf(user), normalizedIncome[asset], RAY);
    }

    function transferAToken(address from, address to, address asset, uint256 nominalAmount) external {
        require(msg.sender == aTokens[asset], "ONLY_ATOKEN");
        MockAToken aToken = MockAToken(aTokens[asset]);
        uint256 scaledAmount = Math.mulDiv(nominalAmount, RAY, normalizedIncome[asset], Math.Rounding.Ceil);
        uint256 fromScaled = aToken.scaledBalanceOf(from);
        require(fromScaled >= scaledAmount, "INSUFFICIENT_SCALED");
        aToken.setScaledBalance(from, fromScaled - scaledAmount);
        uint256 toScaled = aToken.scaledBalanceOf(to);
        aToken.setScaledBalance(to, toScaled + scaledAmount);
    }
}
