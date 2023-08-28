// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

uint256 constant DEPTH = 4;

library MerkleLib {
    error InvalidZerosLevel();

    /// @notice Efficiently hashes two values `left` and `right`.
    function hash(bytes32 left, bytes32 right) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)

            result := keccak256(0x00, 0x40)
        }
    }

    /// @notice Computes the merkle root starting with `leaf` at given `key`.
    ///         Next level nodes are computed by hashing the current nodes with
    ///         the provided nodes to either left or right, depending on `key`.
    /// @dev Does not read and validate all provided `nodes`. If these are not
    ///      part of the proof, these can be set to arbitrary values.
    ///      `key` is a malleable parameter if not all bits are read.
    function computeRoot(uint256 key, bytes32 leaf, bytes32[DEPTH] memory nodes) internal pure returns (bytes32 root) {
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
    function appendLeaf(uint256 key, bytes32 leaf, bytes32[DEPTH] memory nodes)
        internal
        pure
        returns (bytes32 root, bytes32[DEPTH] memory newNodes)
    {
        // Start with the `leaf` node.
        bytes32 node = leaf;

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

    function getEmptyTree() internal pure returns (bytes32 root, bytes32[DEPTH] memory nodes) {
        // Initialize inner nodes of empty tree.
        for (uint256 i; i < DEPTH; ++i) {
            nodes[i] = zeros(i);
        }

        // Set `root` node.
        root = zeros(DEPTH);
    }

    /// @notice Returns pre-computed zero sub-trees of depth `level`.
    function zeros(uint256 level) internal pure returns (bytes32) {
        if (level == 0) return 0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5;
        if (level == 1) return 0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30;
        if (level == 2) return 0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85;
        if (level == 3) return 0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344;
        if (level == 4) return 0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d;
        revert InvalidZerosLevel();
    }
}
