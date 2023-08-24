// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/cashcash/plonk_vk.sol";
import {MerkleLib, DEPTH} from "./MerkleLib.sol";

contract Cash is UltraVerifier {
    error InvalidNodes();
    error NullifierUsed();
    error RefundFailed();
    error InvalidDepositAmount();

    uint256 constant DEPOSIT_AMOUNT = 1 ether;

    uint256 public key;
    bytes32 public root = MerkleLib.zeros(DEPTH);

    mapping(bytes32 => bool) nullifierUsed;

    function deposit(bytes32 nullifierSecretHash, bytes32[DEPTH] memory nodes) public payable {
        // Require 1 ether deposit value.
        if (msg.value != 1 ether) revert InvalidDepositAmount();

        // Cache `key`.
        uint256 key_ = key;

        // Validate supplied `nodes` by recomputing current `root`.
        if (root != MerkleLib.computeRoot(key_, MerkleLib.zeros(0), nodes)) revert InvalidNodes();

        // Compute and update root with `nullifierSecretHash` inserted at `key` index.
        root = MerkleLib.computeRoot(key_, nullifierSecretHash, nodes);
    }

    function withdraw(bytes calldata proof, bytes32 nullifier) public {
        // Check `nullifier` to prevent replay.
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        // Mark `nullifier` as used.
        nullifierUsed[nullifier] = true;

        // The prover verifies the zero knowledge proof, demonstrating
        //   - Knowledge of pre-image of a leaf: `nullifier` and `secret` hash.
        //   - The leaf is contained in merkle tree with `root`.
        //   - The proof is generated for `receiver`.
        _verifyProof(msg.sender, nullifier, root, proof);

        // Refund caller.
        (bool success,) = msg.sender.call{value: 1 ether}("");
        if (!success) revert RefundFailed();
    }

    function _verifyProof(address receiver, bytes32 nullifier, bytes32 root_, bytes calldata proof) internal view {
        // Set up public inputs for `proof` verification.
        bytes32[] memory publicInputs = new bytes32[](65);

        publicInputs[0] = bytes32(uint256(uint160(receiver)));
        // publicInputs[1] = nullifier;
        // publicInputs[2] = root_;

        for (uint256 i; i < 32; i++) {
            publicInputs[1 + i] = bytes32(uint256(uint8(nullifier[i])));
        }

        for (uint256 i; i < 32; i++) {
            publicInputs[33 + i] = bytes32(uint256(uint8(root_[i])));
        }

        // Verify zero knowledge proof.
        this.verify(proof, publicInputs);
    }
}
