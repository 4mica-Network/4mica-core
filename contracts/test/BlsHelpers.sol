// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import {Core4Mica} from "../src/Core4Mica.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

library BlsHelper {

    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(uint256(31827880280837800241567138048534752271)),
            bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
            bytes32(uint256(11568204302792691131076548377920244452)),
            bytes32(uint256(114417265404584670498511149331300188430316142484413708742216858159411894806497))
        );
    }

    function getPublicKey(bytes32 privateKey) public view returns (BLS.G1Point memory) {
        return blsScalarMul(G1_GENERATOR(), privateKey);
    }

    function signGuarantee(Core4Mica.Guarantee memory g, bytes32 privateKey) public view returns (BLS.G2Point memory) {
        return blsSign(encodeGuarantee(g), privateKey);
    }

    // === Helpers ===

    function encodeGuarantee(Core4Mica.Guarantee memory g) public pure returns (bytes memory) {
        return abi.encodePacked(g.tab_id, g.req_id, g.client, g.recipient, g.amount, g.tab_timestamp);
    }

    function blsSign(bytes memory message, bytes32 privateKey) public view returns (BLS.G2Point memory) {
        return blsScalarMul(BLS.hashToG2(message), privateKey);
    }

    function blsScalarMul(BLS.G1Point memory point, bytes32 scalar) public view returns (BLS.G1Point memory) {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](1);
        g1Points[0] = point;

        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = scalar;

        return BLS.msm(g1Points, scalars);
    }

    function blsScalarMul(BLS.G2Point memory point, bytes32 scalar) public view returns (BLS.G2Point memory) {
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](1);
        g2Points[0] = point;

        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = scalar;

        return BLS.msm(g2Points, scalars);
    }
}
