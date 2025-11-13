// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/Core4Mica.sol";
import {Guarantee} from "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IAccessManaged} from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );

    constructor(string memory name_, string memory symbol_) {
        name = name_;
        symbol = symbol_;
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

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ALLOWANCE");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

abstract contract Core4MicaTestBase is Test {
    Core4Mica internal core4Mica;
    AccessManager internal manager;
    MockERC20 internal usdc;
    MockERC20 internal usdt;

    address internal constant USER1 = address(0x111);
    address internal constant USER2 = address(0x222);
    address internal constant OPERATOR = address(0x333);

    uint64 internal constant USER_ADMIN_ROLE = 4;
    uint64 internal constant OPERATOR_ROLE = 9;
    address internal constant ETH_ASSET = address(0);

    bytes4 internal constant RECORD_PAYMENT_SELECTOR =
        bytes4(keccak256("recordPayment(uint256,address,uint256)"));

    bytes32 internal constant TEST_PRIVATE_KEY =
        bytes32(
            0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3
        );

    BLS.G1Point internal testPublicKey;

    function setUp() public virtual {
        manager = new AccessManager(address(this));
        usdc = new MockERC20("USD Coin", "USDC");
        usdt = new MockERC20("Tether USD", "USDT");
        testPublicKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);
        core4Mica = new Core4Mica(
            address(manager),
            testPublicKey,
            address(usdc),
            address(usdt)
        );

        vm.deal(USER1, 5 ether);
        usdc.mint(USER1, 1_000_000 ether);
        usdt.mint(USER1, 1_000_000 ether);
        vm.startPrank(USER1);
        usdc.approve(address(core4Mica), type(uint256).max);
        usdt.approve(address(core4Mica), type(uint256).max);
        vm.stopPrank();

        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(RECORD_PAYMENT_SELECTOR),
            OPERATOR_ROLE
        );

        bytes4[] memory adminSelectors = new bytes4[](4);
        adminSelectors[0] = Core4Mica.setSynchronizationDelay.selector;
        adminSelectors[1] = Core4Mica.configureGuaranteeVersion.selector;
        adminSelectors[2] = Core4Mica.pause.selector;
        adminSelectors[3] = Core4Mica.unpause.selector;
        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica),
                _asSingletonArray(adminSelectors[i]),
                USER_ADMIN_ROLE
            );
        }

        manager.grantRole(USER_ADMIN_ROLE, address(this), 0);
        manager.grantRole(OPERATOR_ROLE, OPERATOR, 0);
    }

    function _signGuarantee(
        Guarantee memory g,
        bytes32 privKey
    ) internal view returns (BLS.G2Point memory) {
        return BlsHelper.signGuarantee(g, privKey);
    }

    function _encodeGuaranteeWithVersion(
        Guarantee memory g
    ) internal pure returns (bytes memory) {
        return BlsHelper.encodeGuaranteeWithVersion(g);
    }

    function _guarantee(
        uint256 tabId,
        uint256 tabTimestamp,
        address client,
        address recipient,
        uint256 reqId,
        uint256 amount,
        address asset
    ) internal view returns (Guarantee memory) {
        return
            Guarantee({
                domain: core4Mica.guaranteeDomainSeparator(),
                tab_id: tabId,
                req_id: reqId,
                client: client,
                recipient: recipient,
                amount: amount,
                total_amount: amount,
                asset: asset,
                timestamp: uint64(tabTimestamp),
                version: 1
            });
    }

    function _ethGuarantee(
        uint256 tabId,
        uint256 tabTimestamp,
        address client,
        address recipient,
        uint256 reqId,
        uint256 amount
    ) internal view returns (Guarantee memory) {
        return
            _guarantee(
                tabId,
                tabTimestamp,
                client,
                recipient,
                reqId,
                amount,
                ETH_ASSET
            );
    }

    function _asSingletonArray(
        bytes4 selector
    ) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    function AccessUnauthorizedError(
        address accessor
    ) public pure returns (bytes memory) {
        return
            abi.encodeWithSelector(
                IAccessManaged.AccessManagedUnauthorized.selector,
                accessor
            );
    }
}
