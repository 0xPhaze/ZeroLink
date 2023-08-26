// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {ZeroLink} from "../src/ZeroLink.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";
import {BaseUltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";

import {NoirTestBase} from "./utils/NoirTestBase.sol";

/// @notice Exposes helper functions on `ZeroLink`
contract MockZeroLink is ZeroLink {
    function verifyProof(address receiver, bytes32 nullifier, bytes32 root_, bytes calldata proof) public view {
        _verifyProof(receiver, nullifier, root_, proof);
    }
}

/// @notice ZeroLink tests
contract ZeroLinkTest is NoirTestBase {
    address bob = address(0xb0b);
    address babe = address(0xbabe);

    bytes32 nullifier = bytes32(uint256(0x222244448888));
    bytes32 secret = bytes32(uint256(0x1337));
    bytes32 nullifierSecretHash = MerkleLib.hash(nullifier, secret);
    bytes32 root = MerkleLib.zeros(DEPTH);
    bytes32[DEPTH] nodes;

    bytes proof;
    MockZeroLink zerolink = new MockZeroLink();

    function setUp() public {
        proof = getProofBytes();

        deal(bob, 100 ether);
        deal(babe, 100 ether);
    }

    // /// Can successfully generate proofs.
    // function test_generate() public {
    //     uint256 key;

    //     generateProof(babe, key, nullifier, secret, nodes);
    // }

    /// Can successfully deposit.
    function test_deposit() public {
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(hex"1234");

        vm.prank(bob);
        zerolink.deposit{value: 1 ether}(hex"4567");

        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(hex"7890");
    }

    /// Can successfully deposit.
    function test_deposit_revert_LeafAlreadyCommitted() public {
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        vm.prank(bob);
        vm.expectRevert(ZeroLink.LeafAlreadyCommitted.selector);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);
    }

    /// Can successfully withdraw.
    function test_withdraw() public {
        // Able to deposit.
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        // Read new `root`.
        root = zerolink.root();

        // Proof is valid.
        zerolink.verifyProof(babe, nullifier, root, proof);

        // Can withdraw funds.
        vm.prank(babe);
        zerolink.withdraw(nullifier, root, proof);

        // Receiver gets funds back.
        assertEq(babe.balance, 100 ether);
    }

    /// Can't withdraw with a valid proof but invalid root.
    function test_withdraw_revert_InvalidRoot() public {
        // `root` corresponds to valid proof, but it was never committed.
        root = 0x88003085d942aed66badd8d8a2e3d928aa7d1866d0d44b28e660a16579bf3881;

        vm.prank(babe);
        vm.expectRevert(ZeroLink.InvalidRoot.selector);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// The same `nullifier` cannot be used twice.
    function test_verify_revert_NullifierUsed() public {
        vm.prank(babe);
        zerolink.deposit{value: 1 ether}(nullifierSecretHash);

        // Read new `root`.
        root = zerolink.root();

        vm.prank(babe);
        zerolink.withdraw(nullifier, root, proof);

        vm.prank(babe);
        vm.expectRevert(ZeroLink.NullifierUsed.selector);
        zerolink.withdraw(nullifier, root, proof);
    }

    /// The call to `verifyProof` cannot be front-run.
    function test_verify_revert_PROOF_FAILURE_invalidSender(address sender) public {
        vm.assume(sender != babe);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(sender, nullifier, root, proof);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_PROOF_FAILURE_invalidNullifier(bytes32 nullifier_) public {
        nullifier_ = asField(nullifier_);
        vm.assume(nullifier != nullifier_);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        zerolink.verifyProof(babe, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_PROOF_FAILURE_invalidroot(bytes32 root_) public {
        root_ = asField(root_);
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
        bool validProof;
        validProof = validProof && root == root_;
        validProof = validProof && sender == babe;
        validProof = validProof && nullifier == nullifier_;
        validProof = validProof && keccak256(proof) == keccak256(proof_);
        vm.assume(!validProof);

        vm.expectRevert();
        zerolink.verifyProof(sender, nullifier_, root_, proof_);
    }
}
