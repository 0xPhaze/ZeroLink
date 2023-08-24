// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";
import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {ZeroLink} from "../src/ZeroLink.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";

/// @dev Prime field order
uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

/// @notice Exposes helper functions on `ZeroLink`
contract MockZeroLink is ZeroLink {
    function verifyProof(address receiver, bytes32 nullifier, bytes32 root_, bytes calldata proof) public view {
        _verifyProof(receiver, nullifier, root_, proof);
    }
}

/// @notice ZeroLink test base contract
contract ZeroLinkTestBase is Test {
    function Field(uint256 x) internal pure returns (uint256) {
        return x % PRIME_FIELD;
    }

    function Field(bytes32 x) internal pure returns (bytes32) {
        return bytes32(uint256(x) % PRIME_FIELD);
    }

    function toStringBytes1(bytes1 b) public pure returns (string memory out) {
        out = vm.toString(b);
        assembly {
            mstore(out, 0x04)
        }
    }

    function toStringBytes(bytes memory b) public pure returns (string memory out) {
        for (uint256 i; i < b.length; i++) {
            if (i == 0) out = string.concat('["', toStringBytes1(b[i]));
            else out = string.concat(out, '", "', toStringBytes1(b[i]));
        }
        out = string.concat(out, '"]');
    }
}

/// @notice ZeroLink tests
contract ZeroLinkTest is ZeroLinkTestBase {
    bytes proof;
    MockZeroLink zerolink;

    address bob = address(0xb0b);
    address babe = address(0xbabe);
    bytes32 nullifier = bytes32(uint256(0x222244448888));
    bytes32 secret = bytes32(uint256(0x1337));
    bytes32 nullifierSecretHash = MerkleLib.hash(nullifier, secret);
    bytes32 root = MerkleLib.zeros(DEPTH);
    bytes32[DEPTH] nodes;

    function setUp() public {
        proof = vm.parseBytes(vm.readLine("./circuits/proofs/ZeroLink.proof"));

        zerolink = new MockZeroLink();

        deal(babe, 100 ether);
    }

    /// Can successfully deposit.
    function test_deposit() public {
        // Able to deposit.
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        // Read new `root`.
        root = zerolink.root();

        // Proof is valid.
        zerolink.verifyProof(babe, nullifier, root, proof);

        // Can withdraw funds.
        vm.prank(babe);
        zerolink.withdraw(proof, nullifier);

        assertEq(babe.balance, 100 ether);
    }

    /// The same `nullifier` cannot be used twice.
    function test_verify_revert_doubleSpend() public {
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        vm.prank(babe);
        zerolink.withdraw(proof, nullifier);

        vm.prank(babe);
        vm.expectRevert(ZeroLink.NullifierUsed.selector);
        zerolink.withdraw(proof, nullifier);
    }

    /// The call to `verifyProof` cannot be front-run.
    function test_verify_revert_invalidSender(address sender) public {
        vm.assume(sender != babe);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(sender, nullifier, root, proof);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_invalidNullifier(bytes32 nullifier_) public {
        nullifier_ = Field(nullifier_);
        vm.assume(nullifier != nullifier_);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(babe, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_invalidroot(bytes32 root_) public {
        root_ = Field(root_);
        vm.assume(root != root_);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(babe, nullifier, root_, proof);
    }

    /// Cannot modify `proof`.
    function test_verify_revert_invalidProof(bytes calldata proof_) public {
        vm.assume(keccak256(proof) != keccak256(proof_));

        vm.expectRevert();
        zerolink.verifyProof(babe, nullifier, root, proof_);
    }

    /// Cannot modify any proof inputs.
    function test_verify_revert_invalidInputs(address sender, bytes calldata proof_, bytes32 nullifier_, bytes32 root_)
        public
    {
        bool invalidProof =
            keccak256(proof) != keccak256(proof_) || root != root_ || sender != babe || nullifier != nullifier_;
        vm.assume(invalidProof);

        vm.expectRevert();
        zerolink.verifyProof(sender, nullifier_, root_, proof_);
    }
}
