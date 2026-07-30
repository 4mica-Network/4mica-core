// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Core4Mica, Guarantee} from "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IAccessManaged} from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";
import {
    MockAavePool,
    MockAToken,
    MockAaveProtocolDataProvider,
    MockPoolAddressesProvider
} from "./helpers/MockAave.sol";

/// Mock stablecoin with EIP-2612 `permit` but no EIP-3009, mirroring the tokens that are listed on
/// Aave but lack `receiveWithAuthorization`.
///
/// That combination is not an oddity to tolerate but the case worth deploying locally: it is the
/// only one where a Permit2 deposit stays gasless, since the missing `approve(PERMIT2, …)` can be
/// signed as a permit instead of transacted.
contract MockERC20Permit {
    string public name;
    string public symbol;
    // `decimals` must stay lowercase to conform to the ERC20 `decimals()` interface.
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable decimals;
    uint256 public totalSupply;
    /// Matches USDC's FiatToken EIP-712 domain version.
    string public constant EIP712_VERSION = "2";

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    /// owner => next permit nonce, the EIP-2612 replay guard. Sequential, unlike EIP-3009's.
    mapping(address => uint256) public nonces;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    // forge-lint: disable-next-line(mixed-case-function)
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(EIP712_VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /// Sets an allowance from `owner`'s signature instead of a transaction, so a third party can
    /// pay the gas. The nonce is sequential and consumed here, making a replayed permit invalid.
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
    {
        uint256 currentTime = block.timestamp;
        require(currentTime <= deadline, "EIP2612: permit is expired");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(ecrecover(digest, v, r, s) == owner, "EIP2612: invalid signature");

        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ALLOWANCE");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// Mock stablecoin with both EIP-3009 and EIP-2612, as real USDC has. Deployed by the Foundry
/// suites and, via `Core4MicaFullStack.s.sol`, as the local dev stack's first stablecoin.
///
/// `receiveWithAuthorization` matters because it is the only truly gasless deposit: one
/// transaction, submitted by someone else, with nothing for the payer to approve first.
contract MockERC20 is MockERC20Permit {
    /// authorizer => nonce => used, the EIP-3009 replay guard. Arbitrary rather than sequential,
    /// so authorizations can be signed out of order and redeemed in any.
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    constructor(string memory name_, string memory symbol_, uint8 decimals_)
        MockERC20Permit(name_, symbol_, decimals_)
    {}

    /// Pulls `value` from `from` into the caller, authorized by `from`'s EIP-712 signature rather
    /// than by an allowance. The caller must be the payee, so a third party can submit the
    /// transaction and pay the gas without being able to redirect the funds.
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(to == msg.sender, "EIP3009: caller must be the payee");
        uint256 currentTime = block.timestamp;
        require(currentTime > validAfter, "EIP3009: authorization is not yet valid");
        require(currentTime < validBefore, "EIP3009: authorization is expired");
        require(!authorizationState[from][nonce], "EIP3009: authorization is used");

        bytes32 structHash =
            keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(ecrecover(digest, v, r, s) == from, "EIP3009: invalid signature");

        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }
}

abstract contract Core4MicaTestBase is Test {
    Core4Mica internal core4Mica;
    AccessManager internal manager;
    MockERC20 internal usdc;
    MockERC20 internal usdt;
    MockAavePool internal mockPool;
    MockAToken internal mockUsdcAToken;
    MockAToken internal mockUsdtAToken;
    MockAaveProtocolDataProvider internal mockDataProvider;
    MockPoolAddressesProvider internal mockProvider;

    address internal constant USER1 = address(0x111);
    address internal constant USER2 = address(0x222);
    address internal constant OPERATOR = address(0x333);

    uint64 internal constant USER_ADMIN_ROLE = 4;
    uint64 internal constant OPERATOR_ROLE = 9;
    address internal constant ETH_ASSET = address(0);

    bytes32 internal constant TEST_PRIVATE_KEY =
        bytes32(0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3);

    BLS.G1Point internal testPublicKey;

    function setUp() public virtual {
        manager = new AccessManager(address(this));
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether USD", "USDT", 6);
        testPublicKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);
        mockPool = new MockAavePool();
        mockDataProvider = new MockAaveProtocolDataProvider();
        mockProvider = new MockPoolAddressesProvider();
        mockUsdcAToken = new MockAToken(address(usdc), address(mockPool), "Aave USDC", "aUSDC");
        mockUsdtAToken = new MockAToken(address(usdt), address(mockPool), "Aave USDT", "aUSDT");
        mockPool.setReserve(address(usdc), address(mockUsdcAToken), 1e27);
        mockPool.setReserve(address(usdt), address(mockUsdtAToken), 1e27);
        mockDataProvider.setReserveAToken(address(usdc), address(mockUsdcAToken));
        mockDataProvider.setReserveAToken(address(usdt), address(mockUsdtAToken));
        mockProvider.setPool(address(mockPool));
        mockProvider.setPoolDataProvider(address(mockDataProvider));

        address[] memory stablecoins = new address[](2);
        stablecoins[0] = address(usdc);
        stablecoins[1] = address(usdt);
        core4Mica = new Core4Mica(address(manager), testPublicKey, stablecoins, 0);

        vm.deal(USER1, 5 ether);
        usdc.mint(USER1, 1_000_000 ether);
        usdt.mint(USER1, 1_000_000 ether);
        vm.startPrank(USER1);
        usdc.approve(address(core4Mica), type(uint256).max);
        usdt.approve(address(core4Mica), type(uint256).max);
        vm.stopPrank();

        bytes4[] memory adminSelectors = new bytes4[](9);
        adminSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        adminSelectors[1] = Core4Mica.configureGuaranteeVersion.selector;
        adminSelectors[2] = Core4Mica.pause.selector;
        adminSelectors[3] = Core4Mica.unpause.selector;
        adminSelectors[4] = Core4Mica.configureAave.selector;
        adminSelectors[5] = Core4Mica.addStablecoinAsset.selector;
        adminSelectors[6] = Core4Mica.setYieldFeeBps.selector;
        adminSelectors[7] = Core4Mica.claimProtocolYield.selector;
        adminSelectors[8] = Core4Mica.setMinWithdrawalGracePeriod.selector;
        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(adminSelectors[i]), USER_ADMIN_ROLE);
        }

        manager.grantRole(USER_ADMIN_ROLE, address(this), 0);
        manager.grantRole(OPERATOR_ROLE, OPERATOR, 0);

        address[] memory aTokens = new address[](2);
        aTokens[0] = address(mockUsdcAToken);
        aTokens[1] = address(mockUsdtAToken);
        core4Mica.configureAave(address(mockProvider), aTokens);
    }

    function _signGuarantee(Guarantee memory g, bytes32 privKey) internal view returns (BLS.G2Point memory) {
        return BlsHelper.signGuarantee(g, privKey);
    }

    function _encodeGuaranteeWithVersion(Guarantee memory g) internal pure returns (bytes memory) {
        return BlsHelper.encodeGuaranteeWithVersion(g);
    }

    function _guarantee(
        uint256 cycleId,
        uint256 tabTimestamp,
        address client,
        address recipient,
        uint256 reqId,
        uint256 amount,
        address asset
    ) internal view returns (Guarantee memory) {
        return Guarantee({
            domain: core4Mica.guaranteeDomainSeparator(),
            cycleId: cycleId,
            reqId: reqId,
            client: client,
            recipient: recipient,
            amount: amount,
            asset: asset,
            // forge-lint: disable-next-line(unsafe-typecast)
            timestamp: uint64(tabTimestamp),
            version: 1
        });
    }

    function _ethGuarantee(
        uint256 cycleId,
        uint256 tabTimestamp,
        address client,
        address recipient,
        uint256 reqId,
        uint256 amount
    ) internal view returns (Guarantee memory) {
        return _guarantee(cycleId, tabTimestamp, client, recipient, reqId, amount, ETH_ASSET);
    }

    function _asSingletonArray(bytes4 selector) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    function accessUnauthorizedError(address accessor) public pure returns (bytes memory) {
        return abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, accessor);
    }
}
