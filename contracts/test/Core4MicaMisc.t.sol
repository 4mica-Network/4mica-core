// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaMiscTest is Core4MicaTestBase {
    function test_VerifyAndDecodeGuarantee() public view {
        Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        Guarantee memory decoded = core4Mica.verifyAndDecodeGuarantee(
            guaranteeData,
            signature
        );
        assertEq(keccak256(abi.encode(decoded)), keccak256(abi.encode(g)));
    }

    function test_VerifyAndDecodeGuarantee_InvalidGuarantee() public {
        Guarantee memory g1 = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g1, TEST_PRIVATE_KEY);

        Guarantee memory g2 = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            4 ether
        );
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g2);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.verifyAndDecodeGuarantee(guaranteeData, signature);
    }

    function test_VerifyAndDecodeGuarantee_InvalidSigningKey() public {
        Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );

        bytes32 otherKey = bytes32(
            0x5B85C3922AB2E2738F196576D00A8583CBE4A1C6BCA85DDFC65438574F42377C
        );
        BLS.G2Point memory signature = _signGuarantee(g, otherKey);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.verifyAndDecodeGuarantee(guaranteeData, signature);
    }

    function test_VerifyAndDecodeGuarantee_InvalidAssetField() public {
        Guarantee memory g = _guarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        Guarantee memory tampered = _ethGuarantee(
            g.tab_id,
            g.timestamp,
            g.client,
            g.recipient,
            g.req_id,
            g.amount
        );
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(tampered);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.verifyAndDecodeGuarantee(guaranteeData, signature);
    }

    function test_VerifyAndDecodeGuarantee_UnsupportedVersion() public {
        Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );

        // Create guarantee with unsupported version
        g.version = 99;
        bytes memory guaranteeData = abi.encode(uint64(99), abi.encode(g));
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedGuaranteeVersion.selector,
                uint64(99)
            )
        );
        core4Mica.verifyAndDecodeGuarantee(guaranteeData, signature);
    }

    function test_VerifyAndDecodeGuarantee_InvalidDomain() public {
        Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );

        // Modify the guarantee to have a different domain
        g.domain = keccak256("WRONG_DOMAIN");
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        bytes memory guaranteeData = _encodeGuaranteeWithVersion(g);

        vm.expectRevert(Core4Mica.InvalidGuaranteeDomain.selector);
        core4Mica.verifyAndDecodeGuarantee(guaranteeData, signature);
    }

    function test_Receive_Reverts_TransferFailed() public {
        vm.prank(USER1);
        (bool ok, bytes memory data) = address(core4Mica).call{
            value: 0.25 ether
        }("");
        assertFalse(ok);
        assertEq(
            data,
            abi.encodeWithSelector(Core4Mica.DirectTransferNotAllowed.selector)
        );
    }

    function test_Fallback_Reverts_TransferFailed() public {
        vm.prank(USER1);
        (bool ok, ) = address(core4Mica).call{value: 0.25 ether}(
            abi.encodeWithSignature("nonExistentFunction()")
        );
        assertFalse(ok);
    }

    function test_GetUserAllAssets_ReturnsOrderedBalances() public {
        vm.startPrank(USER1);
        core4Mica.deposit{value: 1 ether}();
        core4Mica.depositStablecoin(address(usdc), 250 ether);
        core4Mica.depositStablecoin(address(usdt), 750 ether);
        core4Mica.requestWithdrawal(address(usdc), 100 ether);
        vm.stopPrank();

        Core4Mica.UserAssetInfo[] memory infos = core4Mica.getUserAllAssets(
            USER1
        );
        assertEq(infos.length, 3);

        assertEq(infos[0].asset, ETH_ASSET);
        assertEq(infos[0].collateral, 1 ether);
        assertEq(infos[0].withdrawalRequestTimestamp, 0);
        assertEq(infos[0].withdrawalRequestAmount, 0);

        assertEq(infos[1].asset, address(usdc));
        assertEq(infos[1].collateral, 250 ether);
        assertEq(infos[1].withdrawalRequestAmount, 100 ether);
        assertGt(infos[1].withdrawalRequestTimestamp, 0);

        assertEq(infos[2].asset, address(usdt));
        assertEq(infos[2].collateral, 750 ether);
        assertEq(infos[2].withdrawalRequestTimestamp, 0);
        assertEq(infos[2].withdrawalRequestAmount, 0);
    }

    function test_GetERC20Tokens_ReturnsStablecoins() public view {
        address[] memory tokens = core4Mica.getERC20Tokens();
        assertEq(tokens.length, 2);
        assertEq(tokens[0], address(usdc));
        assertEq(tokens[1], address(usdt));
    }
}
