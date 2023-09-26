// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2 as console} from "forge-std/Test.sol";

import {MerkleLib, DEPTH} from "../src/utils/MerkleLib.sol";
import {NoirUtils} from "../src/utils/NoirUtils.sol";

contract MerkleLibTest is Test {
    using NoirUtils for bytes32;

    uint256 key;
    uint256 nullifier;
    uint256 secret;
    uint256 leaf;
    uint256 root;
    uint256[DEPTH] nodes;

    constructor() {
        // Initialize inner nodes of empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();
    }

    function logNodes() internal view {
        console.log();
        for (uint256 i; i < DEPTH; i++) {
            console.log(i, vm.toString(nodes[i]));
        }
        console.log("root", vm.toString(root));
    }

    /// Test `MerkleLib.zeros` return correct hash values.
    function test_zeros() public {
        uint256 node;

        for (uint256 i; i < DEPTH + 1; i++) {
            node = MerkleLib.hash(node, node);

            assertEq(MerkleLib.zeros(i), node);
        }
    }

    function test_zeros_revert_InvalidZerosLevel() public {
        vm.expectRevert(MerkleLib.InvalidZerosLevel.selector);
        MerkleLib.zeros(DEPTH + 1);
    }

    /// Test computing and updating merkle root.
    function test_computeRoot() public {
        /* ------------- leaf_1 ------------- */

        //               ...
        //               /
        //              o
        //            /    \
        //          /        \
        //        /            \
        //       o           node[1]             zero(1)
        //      /  \            /  \             /
        //     /    \          /    \           /
        //    /      \        /      \         /
        // leaf_1  node[0] zero(0) zero(0)  zero(0)

        // Start with an empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();

        // Insert `leaf` into an empty tree at position 0.
        key = 0;
        leaf = keccak256("leaf_1").asField();

        // Recompute root with `leaf` at leftmost key.
        root = leaf;

        // Always hash zero subtrees to the right of current node.
        for (uint256 i = key; i < DEPTH; ++i) {
            root = MerkleLib.hash(root, MerkleLib.zeros(i));
        }

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        nodes[0] = leaf;

        // Should also be able to arrive at same `root`
        // starting at any other zero leaf.
        key = 1;
        leaf = MerkleLib.zeros(0);

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        /* ------------- leaf_2 ------------- */

        //               ...
        //               /
        //              o
        //            /    \
        //          /        \
        //        /            \
        //       o           node[1]             zero(1)
        //      /  \            /  \             /
        //     /    \          /    \           /
        //    /      \        /      \         /
        // node[0]  leaf_2 zero(0) zero(0)  zero(0)

        // Update tree nodes.
        nodes[0] = keccak256("leaf_1").asField();

        // Insert another `leaf` into tree at position 1.
        key = 1;
        leaf = keccak256("leaf_2").asField();

        // First hash will be with left node ("leaf_1").
        root = MerkleLib.hash(nodes[0], leaf);

        // Hash all other zero subtrees to the right of current node.
        for (uint256 i = key; i < DEPTH; ++i) {
            root = MerkleLib.hash(root, MerkleLib.zeros(i));
        }

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        // Prove equal `root` starting from `key = 0`.
        key = 0;
        nodes[0] = leaf;
        leaf = keccak256("leaf_1").asField();

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        // Prove equal `root` starting from `key = 2`.
        key = 2;
        nodes[0] = MerkleLib.zeros(0);
        nodes[1] = MerkleLib.hash(keccak256("leaf_1").asField(), keccak256("leaf_2").asField());
        leaf = MerkleLib.zeros(0);

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        /* ------------- leaf_3 ------------- */

        //               ...
        //               /
        //              o
        //            /    \
        //          /        \
        //        /            \
        //     node[1]           o             zero(1)
        //      /  \            /  \             /
        //     /    \          /    \           /
        //    /      \        /      \         /
        // leaf_1  leaf_2 leaf_3   node[0]  zero(0)

        // Reset first node to zero node.
        nodes[0] = MerkleLib.zeros(0);
        // Update sub-tree node.
        nodes[1] = MerkleLib.hash(keccak256("leaf_1").asField(), keccak256("leaf_2").asField());

        // Insert another `leaf` into tree at position 2.
        key = 2;
        leaf = keccak256("leaf_3").asField();

        // First hash will be with right zero node.
        root = MerkleLib.hash(leaf, MerkleLib.zeros(0));

        // Second hash will be with left subtree ("leaf_1", "leaf_2").
        root = MerkleLib.hash(nodes[1], root);

        // Hash all other zero subtrees to the right of current node.
        for (uint256 i = key; i < DEPTH; ++i) {
            root = MerkleLib.hash(root, MerkleLib.zeros(i));
        }

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        // Prove equal `root` starting from `key = 1`.
        key = 1;
        leaf = keccak256("leaf_2").asField();
        nodes[0] = keccak256("leaf_1").asField();
        nodes[1] = MerkleLib.hash(keccak256("leaf_3").asField(), MerkleLib.zeros(0));

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));
    }

    /// Test computing and updating merkle root.
    function test_appendLeaf() public {
        // Start with an empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();

        // Insert `leaf` into an empty tree at position 0.
        key = 0;
        leaf = keccak256("leaf_1").asField();

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Insert another `leaf` into tree at position 1.
        key = 1;
        leaf = keccak256("leaf_2").asField();

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Insert another `leaf` into tree at position 2.
        key = 2;
        leaf = keccak256("leaf_3").asField();

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Prove inclusion of "leaf_2" starting at `key = 1`.
        key = 1;
        leaf = keccak256("leaf_2").asField();

        // Configure proof nodes.
        (, nodes) = MerkleLib.getEmptyTree();
        nodes[0] = keccak256("leaf_1").asField();
        nodes[1] = MerkleLib.hash(keccak256("leaf_3").asField(), MerkleLib.zeros(0));

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));
    }

    /// Test computing and updating merkle root.
    function test_computeRoot_with_leaves() public {
        uint256[] memory leaves = new uint256[](0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](1);
        leaves[0] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](2);
        leaves[0] = MerkleLib.zeros(0);
        leaves[1] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](3);
        leaves[0] = MerkleLib.zeros(0);
        leaves[1] = MerkleLib.zeros(0);
        leaves[2] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  -    -    -    -    -    -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x1, nodes);

        leaves = new uint256[](1);
        leaves[0] = 0x1;

        assertEq(MerkleLib.computeRoot(leaves), root);

        // Adding extra zero leaves should not
        // change the computed root.
        leaves = new uint256[](2);
        leaves[0] = 0x1;
        leaves[1] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](3);
        leaves[0] = 0x1;
        leaves[1] = MerkleLib.zeros(0);
        leaves[2] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  -    -    -    -    -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x2, nodes);

        leaves = new uint256[](2);
        leaves[0] = 0x1;
        leaves[1] = 0x2;

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](3);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](4);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = MerkleLib.zeros(0);
        leaves[3] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  -    -    -    -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x3, nodes);

        leaves = new uint256[](3);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](4);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](5);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = MerkleLib.zeros(0);
        leaves[4] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  0x4  -    -    -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x4, nodes);

        leaves = new uint256[](4);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;

        assertEq(MerkleLib.computeRoot(leaves), root);

        leaves = new uint256[](5);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = MerkleLib.zeros(0);

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  0x4  0x5  -    -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x5, nodes);

        leaves = new uint256[](5);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = 0x5;

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  0x4  0x5  0x6  -    -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x6, nodes);

        leaves = new uint256[](6);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = 0x5;
        leaves[5] = 0x6;

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  0x4  0x5  0x6  0x8  -
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x7, nodes);

        leaves = new uint256[](7);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = 0x5;
        leaves[5] = 0x6;
        leaves[6] = 0x7;

        assertEq(MerkleLib.computeRoot(leaves), root);

        // leaves: 0x1  0x2  0x3  0x4  0x5  0x6  0x8  0x9
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x8, nodes);

        leaves = new uint256[](8);
        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = 0x5;
        leaves[5] = 0x6;
        leaves[6] = 0x7;
        leaves[7] = 0x8;

        assertEq(MerkleLib.computeRoot(leaves), root);
    }

    /// Test computing and updating merkle root.
    function test_getProof() public {
        uint256[] memory leaves = new uint256[](5);

        leaves[0] = 0x1;
        leaves[1] = 0x2;
        leaves[2] = 0x3;
        leaves[3] = 0x4;
        leaves[4] = 0x5;

        (root, nodes) = MerkleLib.appendLeaf(key++, 0x1, nodes);
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x2, nodes);
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x3, nodes);
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x4, nodes);
        (root, nodes) = MerkleLib.appendLeaf(key++, 0x5, nodes);

        for (uint256 i; i < 5; i++) {
            uint256 proofKey = i;
            uint256 proofLeaf = leaves[i];
            uint256[DEPTH] memory proofNodes = MerkleLib.getProof(proofKey, leaves);

            assertEq(MerkleLib.computeRoot(proofKey, proofLeaf, proofNodes), root);
        }
    }
}
