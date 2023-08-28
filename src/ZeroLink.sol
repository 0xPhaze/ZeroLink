// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "./MerkleLib.sol";

contract ZeroLink is UltraVerifier {
    error InvalidRoot();
    error NullifierUsed();
    error TransferFailed();
    error InvalidDepositAmount();
    error LeafAlreadyCommitted();

    uint256 constant NUM_ROOTS = 10;
    uint256 constant DEPOSIT_AMOUNT = 1 ether;

    uint256 public key;
    bytes32 public root;
    bytes32[DEPTH] public nodes;

    uint256 public rootsIndex;
    bytes32[NUM_ROOTS] public roots;

    mapping(bytes32 => bool) nullifierUsed;
    mapping(bytes32 => bool) committedLeafs;

    constructor() {
        // Initialize inner nodes of empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();
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
        // Prevent committing an already existing leaf as
        // the `nullifier` cannot be spent twice.
        if (committedLeafs[nullifierSecretHash]) revert LeafAlreadyCommitted();

        // Mark the leaf as committed.
        committedLeafs[nullifierSecretHash] = true;

        // Store old `root` in `roots` array and increase `rootsIndex`.
        roots[rootsIndex++ % NUM_ROOTS] = root;

        // Append leaf `nullifierSecretHash` at index `key` of merkle tree.
        // Update merkle root and internal nodes inserting `nullifierSecretHash` at index `key`.
        // Increment the merkle tree index `key`.
        (root, nodes) = MerkleLib.appendLeaf(key++, nullifierSecretHash, nodes);
    }

    function withdraw(bytes32 nullifier, bytes32 root_, bytes calldata proof) public {
        // Check `nullifier` to prevent replay.
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        // Mark `nullifier` as used.
        nullifierUsed[nullifier] = true;

        // Withdrawer's proof must relate to a a previously committed root.
        if (!_isValidRoot(root_)) revert InvalidRoot();

        // The prover verifies the zero knowledge proof, demonstrating
        // * Knowledge of pre-image of a leaf: `nullifier` and `secret` hash.
        // * The leaf is contained in a merkle tree with root `root`.
        // * The proof is generated for `msg.sender`.
        _verifyProof(msg.sender, nullifier, root_, proof);

        // Refund caller.
        (bool success,) = msg.sender.call{value: 1 ether}("");
        if (!success) revert TransferFailed();
    }

    function _isValidRoot(bytes32 root_) internal view returns (bool) {
        if (root_ == root) return true;

        uint256 endIndex = rootsIndex;
        uint256 index = endIndex + NUM_ROOTS;
        do {
            // Cycle back `index`.
            // Return `true` if a valid previously committed root was found.
            if (roots[(index--) % NUM_ROOTS] == root_) return true;
        } while (index != endIndex);

        return false;
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
