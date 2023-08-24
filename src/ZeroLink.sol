// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "./MerkleLib.sol";

contract ZeroLink is UltraVerifier {
    error InvalidNodes();
    error NullifierUsed();
    error RefundFailed();
    error InvalidDepositAmount();

    uint256 constant DEPOSIT_AMOUNT = 1 ether;

    uint256 public key;
    bytes32[DEPTH + 1] public nodes;

    mapping(bytes32 => bool) nullifierUsed;

    constructor() {
        // Initialize inner nodes of empty tree.
        for (uint256 i; i < DEPTH + 1; ++i) {
            nodes[i] = MerkleLib.zeros(i);
        }
    }

    /// @dev The `root` is stored as the last node.
    function root() public view returns (bytes32) {
        return nodes[DEPTH];
    }

    /// @dev Makes a deposit by committing a leaf node to an
    ///      append-only merkle tree. Every new leaf appended
    ///      to the next available position in the merkle tree
    ///      at `key`.
    ///      The leaf `nullifierSecretHash` is the hash of the
    ///      `nullifier` and `secret` private values.
    function deposit(bytes32 nullifierSecretHash) public payable {
        // Require 1 ether deposit value.
        if (msg.value != 1 ether) revert InvalidDepositAmount();

        // Append leaf `nullifierSecretHash` at `key` index of merkle tree.
        // Compute and update root with `nullifierSecretHash` inserted at `key` index.
        // Increment the merkle tree `key`.
        nodes = MerkleLib.appendLeaf(key++, nullifierSecretHash, nodes);
    }

    function withdraw(bytes calldata proof, bytes32 nullifier) public {
        // Check `nullifier` to prevent replay.
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        // Mark `nullifier` as used.
        nullifierUsed[nullifier] = true;

        // The prover verifies the zero knowledge proof, demonstrating
        // * Knowledge of pre-image of a leaf: `nullifier` and `secret` hash.
        // * The leaf is contained in merkle tree with `root`.
        // * The proof is generated for `receiver`.
        _verifyProof(msg.sender, nullifier, root(), proof);

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
