// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test, console2 as console} from "forge-std/Test.sol";
import {MerkleLib, DEPTH} from "../src/MerkleLib.sol";

/// @dev Prime field order
uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

contract MerkleLibTest is Test {
    function toStringBytes1(bytes1 b) public pure returns (string memory out) {
        out = vm.toString(b);
        assembly {
            mstore(out, 0x04)
        }
    }

    function toStringBytes(bytes memory b) public pure returns (string memory out) {
        for (uint256 i; i < b.length; i++) {
            if (i == 0) out = string.concat('["', toStringBytes1(b[i]));
            else out = string.concat(out, '", "', toStringBytes1(b[i]));
        }
        out = string.concat(out, '"]');
    }

    /// Test `MerkleLib.zeros` return correct hash values.
    function test_zeros() public {
        bytes32 node;

        for (uint256 i; i < DEPTH + 1; i++) {
            node = MerkleLib.hash(node, node);

            assertEq(MerkleLib.zeros(i), node);
        }
    }

    /// Validate `Prover.toml` inputs.
    function test_computeRoot_toy_example() public {
        // Insert `leaf` into an empty tree (position 0).
        uint256 key;
        bytes32 nullifier = bytes32(uint256(0x222244448888));
        bytes32 secret = bytes32(uint256(0x1337));
        bytes32 leaf = 0xce0d28d72737db4c1aa07822707c7f7f825e39ccc548332728a9f923cde0263b;
        bytes32 root = 0x88003085d942aed66badd8d8a2e3d928aa7d1866d0d44b28e660a16579bf3881;
        bytes32[DEPTH] memory nodes;

        assertEq(MerkleLib.hash(nullifier, secret), leaf);
        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));
    }

    /// Test computing and updating merkle root.
    function test_computeRoot_append() public {
        // Insert `leaf` into an empty tree (position 0).
        bytes32 root;
        uint256 key;
        bytes32 leaf = keccak256("leaf_1");
        bytes32[DEPTH] memory nodes;

        // Recompute root with `leaf` at leftmost key.
        root = leaf;

        // Always hash zero subtrees to the right of current node.
        for (uint256 i = key; i < DEPTH; ++i) {
            root = MerkleLib.hash(root, MerkleLib.zeros(i));
        }

        assertEq(root, MerkleLib.computeRoot(key, leaf, nodes));

        // Update tree nodes.
        nodes[key] = leaf;

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

        // Update tree nodes with subtree.
        nodes[key] = MerkleLib.hash(nodes[0], leaf);

        // Insert another `leaf` into tree.
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
    }

    // function test_logZeros() public {
    //     bytes32 node;

    //     for (uint256 i; i < DEPTH; i++) {
    //         node = MerkleLib.hash(node, node);
    //         console.log()

    //         assertEq(MerkleLib.zeros(i + 1), node);
    //     }
    // }

    // function test_print_computeRoot() public pure {
    //     // Insert `leaf` into an empty tree (position 0).
    //     uint256 key;
    //     bytes32 nullifier = bytes32(uint256(0x222244448888));
    //     bytes32 secret = bytes32(uint256(0x1337));
    //     bytes32[DEPTH] memory nodes;

    //     bytes32 leaf = MerkleLib.hash(nullifier, secret);

    //     console.log("root =", toStringBytes(abi.encode(MerkleLib.computeRoot(key, leaf, nodes))));

    //     // bytes memory nodesBytes;
    //     for (uint256 i; i < DEPTH; i++) {
    //         nodes[i] = MerkleLib.zeros(i);
    //         // nodesBytes = bytes.concat(nodesBytes, MerkleLib.zeros(i));
    //     }

    //     console.log("nodes =", toStringBytes(abi.encode(nodes)));
    // }
}
