// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// Minimal Permit2 `SignatureTransfer` mock, mirroring the canonical Permit2's `permitTransferFrom`
/// EIP-712 domain and witness. It is `vm.etch`ed at the canonical Permit2 address so a contract's
/// hardcoded `PERMIT2` constant resolves to it. Signatures are real EIP-712 digests verified via
/// `ecrecover`; nonces model unordered replay protection with a simple used-flag.
contract MockPermit2 {
    // owner => nonce => used
    mapping(address => mapping(uint256 => bool)) public usedNonce;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 private constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    // Permit2's PermitTransferFrom witness — note the trailing nested TokenPermissions type string.
    bytes32 private constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    // Permit2's domain omits `version`.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("Permit2")), block.chainid, address(this)));
    }

    function permitTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        // forge-lint: disable-next-line(block-timestamp)
        require(block.timestamp <= permit.deadline, "Permit2: signature expired");
        require(transferDetails.requestedAmount <= permit.permitted.amount, "Permit2: amount exceeds permission");
        require(!usedNonce[owner][permit.nonce], "Permit2: nonce used");

        bytes32 tokenPermissions =
            keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, permit.permitted.token, permit.permitted.amount));
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH,
                tokenPermissions,
                msg.sender, // spender is the caller, bound into the signed digest
                permit.nonce,
                permit.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        require(ecrecover(digest, v, r, s) == owner, "Permit2: invalid signature");

        usedNonce[owner][permit.nonce] = true;
        require(
            IERC20Like(permit.permitted.token).transferFrom(owner, transferDetails.to, transferDetails.requestedAmount),
            "Permit2: transfer failed"
        );
    }

    function _split(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Permit2: bad signature length");
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
    }
}
