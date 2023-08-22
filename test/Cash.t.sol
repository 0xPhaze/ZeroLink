// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";
import {BaseUltraVerifier} from "../circuits/contract/cashcash/plonk_vk.sol";
import {Cash} from "../src/Cash.sol";

/// @dev Prime field order
uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

contract MockCash is Cash {
    function setCommitment(bytes32 commitment_) public {
        commitment = commitment_;
    }

    function verify(bytes calldata proof, bytes32 nullifier, bytes32 commitment_) public {
        commitment = commitment_;

        verify(proof, nullifier);
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

    address babe = address(0xbabe);
    bytes32 nullifier = bytes32(uint256(1234));
    bytes32 commitment = 0x05ed0402db067eba0f156821fc78fb92e42e35e3f641b098854bd3f6867e3217;

    function setUp() public {
        proof = vm.parseBytes(vm.readLine("./circuits/proofs/cashcash.proof"));

        cash = new MockCash();

        cash.setCommitment(commitment);
    }

    /// Can successfully verify a valid proof.
    function test_verify() public {
        vm.prank(babe);
        cash.verify(proof, nullifier);
    }

    /// The same `nullifier` cannot be used twice.
    function test_verify_revert_doubleSpend() public {
        vm.prank(babe);
        cash.verify(proof, nullifier);

        vm.prank(babe);
        vm.expectRevert(Cash.NullifierUsed.selector);
        cash.verify(proof, nullifier, commitment);
    }

    /// The call to `verify` cannot be front-run.
    function test_verify_revert_invalidSender(address sender) public {
        vm.assume(sender != babe);

        vm.prank(sender);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verify(proof, nullifier, commitment);
    }

    /// Cannot modify `nullifier` in proof.
    function test_verify_revert_invalidNullifier(bytes32 nullifier_) public {
        nullifier_ = Field(nullifier_);
        vm.assume(nullifier != nullifier_);

        vm.prank(babe);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verify(proof, nullifier_, commitment);
    }

    /// Cannot modify `commitment` in proof.
    function test_verify_revert_invalidCommitment(bytes32 commitment_) public {
        commitment_ = Field(commitment_);
        vm.assume(commitment != commitment_);

        vm.prank(babe);
        vm.expectRevert(BaseUltraVerifier.PROOF_FAILURE.selector);
        cash.verify(proof, nullifier, commitment_);
    }

    /// Cannot modify `proof`.
    function test_verify_revert_invalidProof(bytes calldata proof_) public {
        vm.assume(keccak256(proof) != keccak256(proof_));

        vm.prank(babe);
        vm.expectRevert();
        cash.verify(proof_, nullifier, commitment);
    }

    /// Cannot modify any proof inputs.
    function test_verify_revert_invalidInputs(
        address sender,
        bytes calldata proof_,
        bytes32 nullifier_,
        bytes32 commitment_
    ) public {
        bool invalidProof = (
            keccak256(proof) != keccak256(proof_) || commitment != commitment_ || sender != babe
                || nullifier != nullifier_
        );
        vm.assume(invalidProof);

        vm.prank(sender);
        vm.expectRevert();
        cash.verify(proof_, nullifier_, commitment_);
    }
}
