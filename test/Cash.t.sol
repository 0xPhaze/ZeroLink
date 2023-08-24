// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";
import {BaseUltraVerifier} from "../circuits/contract/cashcash/plonk_vk.sol";
import {Cash} from "../src/Cash.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";

/// @dev Prime field order
uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

contract MockCash is Cash {
    function setRoot(bytes32 root_) public {
        root = root_;
    }

    function verifyProof(address receiver, bytes32 nullifier, bytes32 root_, bytes calldata proof) public view {
        _verifyProof(receiver, nullifier, root_, proof);
    }
}

contract CashTestBase is Test {
    function Field(uint256 x) internal pure returns (uint256) {
        return x % PRIME_FIELD;
    }

    function Field(bytes32 x) internal pure returns (bytes32) {
        return bytes32(uint256(x) % PRIME_FIELD);
    }
}

contract CounterTest is CashTestBase {
    bytes proof;
    MockCash cash;

    address bob = address(0xb0b);
    address babe = address(0xbabe);
    bytes32 nullifier = bytes32(uint256(0x222244448888));
    bytes32 secret = bytes32(uint256(0x1337));
    bytes32 nullifierSecretHash = MerkleLib.hash(nullifier, secret);
    bytes32 root = MerkleLib.zeros(DEPTH);
    bytes32[DEPTH] nodes;

    function setUp() public {
        proof = vm.parseBytes(vm.readLine("./circuits/proofs/cashcash.proof"));

        cash = new MockCash();

        deal(babe, 100 ether);
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

    /// Can successfully verifyProof a valid proof.
    function test_deposit() public {
        // Able to deposit.
        vm.prank(babe);
        cash.deposit{value: 1 ether}(nullifierSecretHash, nodes);

        // Read new `root`.
        root = cash.root();

        // Proof is valid.
        cash.verifyProof(babe, nullifier, root, proof);

        // Can withdraw funds.
        vm.prank(babe);
        cash.withdraw(proof, nullifier);
    }

    /// The same `nullifier` cannot be used twice.
    function test_verify_revert_doubleSpend() public {
        vm.prank(babe);
        cash.deposit{value: 1 ether}(nullifierSecretHash, nodes);

        vm.prank(babe);
        cash.withdraw(proof, nullifier);

        vm.prank(babe);
        vm.expectRevert(Cash.NullifierUsed.selector);
        cash.withdraw(proof, nullifier);
    }

    /// The call to `verifyProof` cannot be front-run.
    function test_verify_revert_invalidSender(address sender) public {
        vm.assume(sender != babe);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verifyProof(sender, nullifier, root, proof);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_invalidNullifier(bytes32 nullifier_) public {
        nullifier_ = Field(nullifier_);
        vm.assume(nullifier != nullifier_);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verifyProof(babe, nullifier_, root, proof);
    }

    /// Cannot modify `root` in proof.
    function test_verify_revert_invalidroot(bytes32 root_) public {
        root_ = Field(root_);
        vm.assume(root != root_);

        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verifyProof(babe, nullifier, root_, proof);
    }

    /// Cannot modify `proof`.
    function test_verify_revert_invalidProof(bytes calldata proof_) public {
        vm.assume(keccak256(proof) != keccak256(proof_));

        vm.expectRevert();
        cash.verifyProof(babe, nullifier, root, proof_);
    }

    /// Cannot modify any proof inputs.
    function test_verify_revert_invalidInputs(address sender, bytes calldata proof_, bytes32 nullifier_, bytes32 root_)
        public
    {
        bool invalidProof =
            (keccak256(proof) != keccak256(proof_) || root != root_ || sender != babe || nullifier != nullifier_);
        vm.assume(invalidProof);

        vm.expectRevert();
        cash.verifyProof(sender, nullifier_, root_, proof_);
    }
}
