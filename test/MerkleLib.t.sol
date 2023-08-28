// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2 as console} from "forge-std/Test.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";

contract MerkleLibTest is Test {
    uint256 key;
    bytes32 nullifier;
    bytes32 secret;
    bytes32 leaf;
    bytes32 root;
    bytes32[DEPTH] nodes;

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
        bytes32 node;

        for (uint256 i; i < DEPTH + 1; i++) {
            node = MerkleLib.hash(node, node);

            assertEq(MerkleLib.zeros(i), node);
        }

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
        leaf = keccak256("leaf_1");

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
        nodes[0] = keccak256("leaf_1");

        // Insert another `leaf` into tree at position 1.
        key = 1;
        leaf = keccak256("leaf_2");

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
        leaf = keccak256("leaf_1");

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        // Prove equal `root` starting from `key = 2`.
        key = 2;
        nodes[0] = MerkleLib.zeros(0);
        nodes[1] = MerkleLib.hash(keccak256("leaf_1"), keccak256("leaf_2"));
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
        nodes[1] = MerkleLib.hash(keccak256("leaf_1"), keccak256("leaf_2"));

        // Insert another `leaf` into tree at position 2.
        key = 2;
        leaf = keccak256("leaf_3");

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
        leaf = keccak256("leaf_2");
        nodes[0] = keccak256("leaf_1");
        nodes[1] = MerkleLib.hash(keccak256("leaf_3"), MerkleLib.zeros(0));

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));
    }

    /// Test computing and updating merkle root.
    function test_appendLeaf() public {
        // Start with an empty tree.
        (root, nodes) = MerkleLib.getEmptyTree();

        // Insert `leaf` into an empty tree at position 0.
        key = 0;
        leaf = keccak256("leaf_1");

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Insert another `leaf` into tree at position 1.
        key = 1;
        leaf = keccak256("leaf_2");

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Insert another `leaf` into tree at position 2.
        key = 2;
        leaf = keccak256("leaf_3");

        (root, nodes) = MerkleLib.appendLeaf(key, leaf, nodes);

        // Prove inclusion of "leaf_2" starting at `key = 1`.
        key = 1;
        leaf = keccak256("leaf_2");

        // Configure proof nodes.
        (, nodes) = MerkleLib.getEmptyTree();
        nodes[0] = keccak256("leaf_1");
        nodes[1] = MerkleLib.hash(keccak256("leaf_3"), MerkleLib.zeros(0));

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));
    }
}
