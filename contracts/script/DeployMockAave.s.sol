// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {
    MockAToken,
    MockAavePool,
    MockAaveProtocolDataProvider,
    MockPoolAddressesProvider
} from "../test/helpers/MockAave.sol";

/// Deploys a stand-in Aave for a stablecoin that has no real Aave market.
///
/// Core4Mica denominates stablecoin collateral in Aave *scaled* units, so `depositStablecoin` and
/// `depositStablecoinWithAuthorization` both revert with `AaveNotConfigured()` unless an aToken and
/// pool exist for the asset. On testnets that is a dead end: the token with EIP-3009 support
/// (canonical USDC) is usually not listed in Aave, and the token Aave does list usually lacks
/// EIP-3009 — so no single asset satisfies both requirements.
///
/// `MockAavePool.supply` is generic over the underlying — it only does `safeTransferFrom` and
/// credits a `MockAToken` — so pointing it at the *real* EIP-3009 token resolves the conflict
/// without needing that token listed anywhere.
///
/// Run this BEFORE `Core4MicaFullStack`, then pass the printed addresses into that deployment.
/// `configureAave` sits behind the delayed governance role afterwards, so retrofitting an existing
/// deployment means a timelock cycle rather than a re-run.
///
/// Reads the same `STABLECOINS_COUNT` / `STABLECOIN_<i>` variables as `Core4MicaFullStack`, so the
/// two deployments stay in step. One pool and data provider are shared; each asset gets its own
/// aToken, which is what `configureAave` expects.
///
/// ```sh
/// STABLECOINS_COUNT=2 \
/// STABLECOIN_0=0x036CbD53842c5426634e7929541eC2318f3dCF7e \
/// STABLECOIN_1=0xba50Cd2A20f6DA35D788639E581bca8d0B5d4D5f \
///   forge script script/DeployMockAave.s.sol:DeployMockAaveScript \
///     --rpc-url http://127.0.0.1:8545 --broadcast
/// ```
contract DeployMockAaveScript is Script {
    /// Aave's ray, i.e. a liquidity index of exactly 1.0.
    uint256 internal constant RAY = 1e27;

    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        require(deployerKey != 0, "set DEPLOYER_PRIVATE_KEY");

        uint256 count = vm.envOr("STABLECOINS_COUNT", uint256(0));
        require(count > 0, "set STABLECOINS_COUNT and STABLECOIN_0..n-1");

        address[] memory assets = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            assets[i] = vm.envAddress(string.concat("STABLECOIN_", vm.toString(i)));
        }

        vm.startBroadcast(deployerKey);

        // One pool and data provider for the whole deployment; `configureAave` takes a single
        // addresses provider and an aToken per asset.
        MockAavePool pool = new MockAavePool();
        MockAaveProtocolDataProvider dataProvider = new MockAaveProtocolDataProvider();

        address[] memory aTokens = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            // `UNDERLYING_ASSET_ADDRESS()` must equal the asset, and the data provider must agree,
            // or Core4Mica's `_validateAToken` rejects the pair.
            MockAToken aToken = new MockAToken(
                assets[i], address(pool), "Mock aToken", string.concat("maTKN", vm.toString(i))
            );
            // Index fixed at RAY: scaled balances equal face value, so no yield accrues.
            // Deliberate — `MockAavePool.setNormalizedIncome` mints the difference to simulate
            // interest, which is impossible against a token you do not control.
            pool.setReserve(assets[i], address(aToken), RAY);
            dataProvider.setReserveAToken(assets[i], address(aToken));
            aTokens[i] = address(aToken);
        }

        MockPoolAddressesProvider provider = new MockPoolAddressesProvider();
        provider.setPool(address(pool));
        provider.setPoolDataProvider(address(dataProvider));

        vm.stopBroadcast();

        console.log("MockAavePool:                 %s", address(pool));
        console.log("MockAaveProtocolDataProvider: %s", address(dataProvider));
        console.log("MockPoolAddressesProvider:    %s", address(provider));
        console.log("");
        console.log("Deploy Core4Mica with:");
        console.log("  CONFIGURE_AAVE=true");
        console.log("  DEPLOY_MOCK_STABLECOINS=false");
        console.log("  AAVE_POOL_ADDRESSES_PROVIDER=%s", address(provider));
        console.log("  STABLECOINS_COUNT=%s", vm.toString(count));
        for (uint256 i = 0; i < count; i++) {
            console.log("  STABLECOIN_%s=%s", vm.toString(i), assets[i]);
            console.log("  STABLECOIN_ATOKEN_%s=%s", vm.toString(i), aTokens[i]);
        }
    }
}
