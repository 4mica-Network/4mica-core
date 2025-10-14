// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaMiscTest is Core4MicaTestBase {
    function test_VerifyGuaranteeSignature() public view {
        Core4Mica.Guarantee memory g = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);
        assertTrue(core4Mica.verifyGuaranteeSignature(g, signature));
    }

    function test_VerifyGuaranteeSignature_InvalidGuarantee() public view {
        Core4Mica.Guarantee memory g1 = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether
        );
        BLS.G2Point memory signature = _signGuarantee(g1, TEST_PRIVATE_KEY);

        Core4Mica.Guarantee memory g2 = _ethGuarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            4 ether
        );
        assertFalse(core4Mica.verifyGuaranteeSignature(g2, signature));
    }

    function test_VerifyGuaranteeSignature_InvalidSigningKey() public view {
        Core4Mica.Guarantee memory g = _ethGuarantee(
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
        assertFalse(core4Mica.verifyGuaranteeSignature(g, signature));
    }

    function test_VerifyGuaranteeSignature_InvalidAssetField() public view {
        Core4Mica.Guarantee memory g = _guarantee(
            0x1234,
            block.timestamp,
            USER1,
            USER2,
            17,
            3 ether,
            address(usdc)
        );
        BLS.G2Point memory signature = _signGuarantee(g, TEST_PRIVATE_KEY);

        Core4Mica.Guarantee memory tampered = _ethGuarantee(
            g.tab_id,
            g.tab_timestamp,
            g.client,
            g.recipient,
            g.req_id,
            g.amount
        );
        assertFalse(core4Mica.verifyGuaranteeSignature(tampered, signature));
    }

    function test_Receive_Reverts_TransferFailed() public {
        vm.prank(USER1);
        (bool ok, bytes memory data) = address(core4Mica).call{
            value: 0.25 ether
        }("");
        assertFalse(ok);
        assertEq(
            data,
            abi.encodeWithSelector(
                Core4Mica.DirectTransferNotAllowed.selector
            )
        );
    }

    function test_Fallback_Reverts_TransferFailed() public {
        vm.prank(USER1);
        (bool ok, ) = address(core4Mica).call{value: 0.25 ether}(
            abi.encodeWithSignature("nonExistentFunction()")
        );
        assertFalse(ok);
    }
}
