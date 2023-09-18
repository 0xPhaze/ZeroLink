// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "./utils/MerkleLib.sol";
import {NoirUtils} from "./utils/NoirUtils.sol";

contract ZeroLink is UltraVerifier {
    error InvalidRoot();
    error NullifierUsed();
    error TransferFailed();
    error InvalidDepositAmount();
    error LeafAlreadyCommitted();

    uint256 constant NUM_ROOTS = 10;
    uint256 constant DEPOSIT_AMOUNT = 1 ether;

    uint256 public key;
    uint256 public root;
    uint256[DEPTH] public nodes;

    uint256 public rootsIndex;
    uint256[NUM_ROOTS] public roots;

    mapping(uint256 => bool) nullifierUsed;
    mapping(uint256 => bool) committedLeafs;

    constructor() {
        // Initialize inner nodes of empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();
    }

    /// @dev Makes a deposit by committing a leaf node to an
    ///      append-only merkle tree. Every new leaf appended
    ///      to the next available position in the merkle tree
    ///      at `key`.
    ///      The leaf is the hash of `secret + 1`.
    function deposit(uint256 leaf) public payable {
        // Require `DEPOSIT_AMOUNT` deposit value.
        if (msg.value != DEPOSIT_AMOUNT) revert InvalidDepositAmount();
        // Prevent committing an already existing leaf as
        // the `nullifier` cannot be spent twice.
        if (committedLeafs[leaf]) revert LeafAlreadyCommitted();

        // Mark the leaf as committed.
        committedLeafs[leaf] = true;

        // Store old `root` in `roots` array and increase `rootsIndex`.
        roots[rootsIndex++ % NUM_ROOTS] = root;

        // Append leaf `leaf` at index `key` of merkle tree.
        // Update merkle root and internal nodes inserting `leaf` at index `key`.
        // Increment the merkle tree index `key`.
        // Throws if `leaf` or any of `nodes` is not a field element.
        (root, nodes) = MerkleLib.appendLeaf(key++, leaf, nodes);
    }

    function withdraw(address receiver, uint256 nullifier, uint256 root_, bytes calldata proof) public {
        // Check `nullifier` to prevent replay.
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        // Mark `nullifier` as used.
        nullifierUsed[nullifier] = true;

        // Withdrawer's proof must relate to a a previously committed root.
        if (!_isValidRoot(root_)) revert InvalidRoot();

        // The prover verifies the zero knowledge proof, demonstrating
        // * Knowledge of pre-image of a leaf: `hash(secret + 1)`.
        // * The leaf is contained in a merkle tree with root `root`.
        // * The proof is generated for `receiver`.
        _verifyProof(receiver, nullifier, root_, proof);

        // Refund caller.
        (bool success,) = receiver.call{value: DEPOSIT_AMOUNT}("");
        if (!success) revert TransferFailed();
    }

    function _isValidRoot(uint256 root_) internal view returns (bool) {
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

    function _verifyProof(address receiver, uint256 nullifier, uint256 root_, bytes calldata proof) internal view {
        // Set up public inputs for `proof` verification.
        bytes32[] memory publicInputs = new bytes32[](3);

        publicInputs[0] = bytes32(uint256(uint160(receiver)));
        publicInputs[1] = bytes32(NoirUtils.toField(nullifier));
        publicInputs[2] = bytes32(NoirUtils.toField(root_));

        // Verify zero knowledge proof.
        this.verify(proof, publicInputs);
    }
}
