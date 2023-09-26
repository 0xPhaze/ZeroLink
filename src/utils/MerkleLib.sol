// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PoseidonT2, PoseidonT3} from "./Poseidon.sol";

uint256 constant DEPTH = 4;

library MerkleLib {
    error InvalidKey();
    error InvalidZerosLevel();

    // uint256 constant BLOCKED = MerkleLib.hash(NoirUtils.asField(uint256(bytes32("BLOCKED"))));
    uint256 constant BLOCKED = 19323182000490760459883314209775534503927497343460954693715928383294955029669;

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
        unchecked {
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
    }

    /// @notice Computes the merkle root starting with `leaf` at given `key`.
    ///         Next level nodes are computed by hashing with either,
    ///         pre-computed zero subtrees if the current node is to the left,
    ///         or with `nodes[i]` to if the current node is to the right.
    /// @dev Does not read and validate all provided `nodes`. If these are not
    ///      part of the proof, these can be set to arbitrary values.
    ///      `key` is a malleable parameter if not all bits are read.
    //       Note: These nodes are used for updating the subsequent nodes and root
    //       following the next deposit.
    //
    //       WARNING: THEY SHOULD NOT BE USED FOR PROVING THE CURRENT DEPOSIT.
    //                This would reveal the key used for the deposit.
    function appendLeaf(uint256 key, uint256 leaf, uint256[DEPTH] memory nodes)
        internal
        pure
        returns (uint256 root, uint256[DEPTH] memory newNodes)
    {
        unchecked {
            // Maximum number of leaves committed to fixed size merkle tree.
            if (key >> DEPTH != 0) revert InvalidKey();

            // Start with the `leaf` node.
            uint256 node = leaf;

            for (uint256 i; i < DEPTH; ++i) {
                // Compute new internal nodes in tree. Either hash
                // current node with right zero subtree `zeros(i)` of depth `i`
                // or with left provided node `nodes[i]`.
                // Read `key`s i-th least-significant bit.
                if ((key >> i) & 1 == 0) {
                    // The next update (key + 1) will require the newly computed node.
                    newNodes[i] = node;
                    node = hash(node, zeros(i));
                } else {
                    // Store newly computed internal node `node` if we require it
                    // at the next update (for the next key at the same level),
                    // otherwise we will still require the same `nodes[i]`.
                    newNodes[i] = (key + 1 >> i) & 1 == 0 ? node : nodes[i];
                    node = hash(nodes[i], node);
                }
            }

            root = node;
        }
    }

    /// @notice Computes the merkle root, given a sequential list of leaves.
    /// @dev    Helper function. Not required as part of the main protocol.
    function computeRoot(uint256[] memory leaves) internal pure returns (uint256 root) {
        unchecked {
            uint256 leavesLen = leaves.length;

            if (leavesLen == 0) return zeros(DEPTH);

            uint256 nodesPrevLen = leavesLen;
            uint256 nodesCurrLen = (leavesLen + 1) / 2;
            uint256[] memory nodesPrev = leaves;
            uint256[] memory nodesCurr = new uint256[](nodesCurrLen);

            for (uint256 layer; layer < DEPTH; ++layer) {
                for (uint256 k; k < nodesCurrLen; ++k) {
                    (uint256 leftKey, uint256 rightKey) = (2 * k, 2 * k + 1);

                    nodesCurr[k] = hash(
                        nodesPrev[leftKey], // Read left node from previous node layer.
                        (rightKey < nodesPrevLen)
                            ? nodesPrev[rightKey] // Read right node from previous node layer.
                            : zeros(layer) // Use pre-computed zero sub tree root hash.
                    );
                }

                // `nodesPrev == leaves` and `nodesPrevLen == leavesLen`
                // only during the first iteration. This saves the
                // initial memory copy `nodesPrev` <- `leaves`.
                nodesPrev = nodesCurr;
                nodesPrevLen = nodesCurrLen;
                // Next node layer will have half the number of nodes, rounded up.
                nodesCurrLen = (nodesCurrLen + 1) / 2;
            }

            return root = nodesCurr[0];
        }
    }

    /// @notice Computes the merkle root, given a sequential list of leaves.
    /// @dev    Helper function. Not required as part of the main protocol.
    function getProof(uint256 key, uint256[] memory leaves) internal pure returns (uint256[DEPTH] memory proofNodes) {
        unchecked {
            uint256 leavesLen = leaves.length;

            if (key >= leavesLen) revert InvalidKey();

            uint256 nodesPrevLen = leavesLen;
            uint256 nodesCurrLen = (leavesLen + 1) / 2;
            uint256[] memory nodesCurr = new uint256[](nodesCurrLen);
            uint256[] memory nodesPrev = leaves;

            for (uint256 layer; layer < DEPTH; ++layer) {
                for (uint256 k; k < nodesCurrLen; ++k) {
                    (uint256 leftKey, uint256 rightKey) = (2 * k, 2 * k + 1);

                    // Read left node from previous node layer.
                    uint256 leftNode = nodesPrev[leftKey];
                    uint256 rightNode = (rightKey < nodesPrevLen)
                        ? nodesPrev[rightKey] // Read right node from previous node layer.
                        : zeros(layer); // Use pre-computed zero sub tree root hash.
                    nodesCurr[k] = hash(leftNode, rightNode);

                    // Check if the leaf with `key` is contained in the
                    // sub-tree with root `nodesCurr[k]`.
                    // This is the case if all lsb of `key` match up with
                    // the running key `k` at the current layer.
                    if ((key >> layer + 1) == k) {
                        // Check which node (left/right) is required for the proof.
                        proofNodes[layer] = ((key >> layer) & 1 == 0) // Read `key`s i-th least-significant bit.
                            ? rightNode
                            : leftNode;
                    }
                }

                // `nodesPrev == leaves` and `nodesPrevLen == leavesLen`
                // only during the first iteration. This saves the
                // initial memory copy `nodesPrev` <- `leaves`.
                nodesPrev = nodesCurr;
                nodesPrevLen = nodesCurrLen;
                // Next node layer will have half the number of nodes, rounded up.
                nodesCurrLen = (nodesCurrLen + 1) / 2;
            }
        }
    }

    function getEmptyTree() internal pure returns (uint256 root, uint256[DEPTH] memory nodes) {
        // Initialize inner nodes of empty tree.
        for (uint256 i; i < DEPTH; ++i) {
            nodes[i] = zeros(i);
        }

        // Set `root` node.
        root = zeros(DEPTH);
    }

    /// @notice Returns pre-computed zero sub-tree root of depth `level`.
    ///         Each sub-tree root is computed by:
    ///             root(0) := hash(0)
    ///             root(N) := hash(root(N-1), root(N-1))
    function zeros(uint256 level) internal pure returns (uint256) {
        if (level == 0) return 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        if (level == 1) return 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1;
        if (level == 2) return 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        if (level == 3) return 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        if (level == 4) return 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        revert InvalidZerosLevel();
    }
}
