// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PoseidonT2, PoseidonT3} from "./Poseidon.sol";

uint256 constant DEPTH = 4;

library MerkleLib {
    error InvalidKey();
    error InvalidZerosLevel();

    /// @notice Hashes two values `left` and `right`.
    function hash(uint256 left, uint256 right) internal pure returns (uint256 result) {
        return PoseidonT3.hash(left, right);
    }

    /// @notice Hashes one value.
    function hash(uint256 input) internal pure returns (uint256 result) {
        return PoseidonT2.hash(input);
    }

    /// @notice Computes the merkle root starting with `leaf` at given `key`.
    ///         Next level nodes are computed by hashing the current nodes with
    ///         the provided nodes to either left or right, depending on `key`.
    /// @dev Does not read and validate all provided `nodes`. If these are not
    ///      part of the proof, these can be set to arbitrary values.
    ///      `key` is a malleable parameter if not all bits are read.
    function computeRoot(uint256 key, uint256 leaf, uint256[DEPTH] memory nodes) internal pure returns (uint256 root) {
        // Maximum number of leaves committed to fixed size merkle tree.
        if (key >> DEPTH != 0) revert InvalidKey();

        // Start with the `leaf` node.
        root = leaf;

        for (uint256 i; i < DEPTH; ++i) {
            // Either hash current node with `nodes[i]` to right or left.
            root = ((key >> i) & 1 == 0) // Read `key`s i-th least-significant bit.
                ? hash(root, nodes[i])
                : hash(nodes[i], root);
        }
    }

    /// @notice Computes the merkle root starting with `leaf` at given `key`.
    ///         Next level nodes are computed by hashing with either,
    ///         pre-computed zero subtrees if the current node is to the left,
    ///         or with `nodes[i]` to if the current node is to the right.
    /// @dev Does not read and validate all provided `nodes`. If these are not
    ///      part of the proof, these can be set to arbitrary values.
    ///      `key` is a malleable parameter if not all bits are read.
    //       Note: These nodes are used to updating the subsequent nodes and root
    //       following the next deposit. THEY ARE NOT USED FOR PROVING THE CURRENT DEPOSIT.
    function appendLeaf(uint256 key, uint256 leaf, uint256[DEPTH] memory nodes)
        internal
        pure
        returns (uint256 root, uint256[DEPTH] memory newNodes)
    {
        // Maximum number of leaves committed to fixed size merkle tree.
        if (key >> DEPTH != 0) revert InvalidKey();

        // Start with the `leaf` node.
        uint256 node = leaf;

        for (uint256 i; i < DEPTH; ++i) {
            newNodes[i] = node;
            // Compute new internal nodes in tree. Either hash
            // current node with right zero subtree `zeros(i)` of depth `i`
            // or with left provided node `nodes[i]`.
            node = ((key >> i) & 1 == 0) // Read `key`s i-th least-significant bit.
                ? hash(node, zeros(i))
                : hash(nodes[i], node);
        }

        root = node;
    }

    function getEmptyTree() internal pure returns (uint256 root, uint256[DEPTH] memory nodes) {
        // Initialize inner nodes of empty tree.
        for (uint256 i; i < DEPTH; ++i) {
            nodes[i] = zeros(i);
        }

        // Set `root` node.
        root = zeros(DEPTH);
    }

    /// @notice Returns pre-computed zero sub-trees of depth `level`.
    function zeros(uint256 level) internal pure returns (uint256) {
        if (level == 0) return 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        if (level == 1) return 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1;
        if (level == 2) return 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        if (level == 3) return 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        if (level == 4) return 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        revert InvalidZerosLevel();
    }
}
