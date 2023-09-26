// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {DEPTH} from "../../src/utils/MerkleLib.sol";

/// @notice Noir test base contract
contract NoirTestBase is Test {
    error InvalidFieldElement();

    /// @dev Prime field order
    uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    string constant CIRCUITS_DIR = "circuits";
    string constant PROVER_FILE = "Prover.toml";
    string constant PROOF_FILE = "circuits/proofs/ZeroLink.proof";
    string constant GENERATE_PROOF_SCRIPT = "generate_proof.sh";

    function readProofBytes() internal view returns (bytes memory proof) {
        proof = vm.parseBytes(vm.readLine(PROOF_FILE));
    }

    function toStringBytes32Array(bytes memory b) internal pure returns (string memory out) {
        bytes32[] memory a;
        assembly {
            a := b
            mstore(b, shr(5, mload(b))) // Not safe.
        }

        for (uint256 i; i < a.length; i++) {
            if (i == 0) out = string.concat("[", quote(vm.toString(a[i])));
            else out = string.concat(out, ", ", quote(vm.toString(a[i])));
        }

        out = string.concat(out, "]");
    }

    function toStringUint8Array(bytes memory b) internal pure returns (string memory out) {
        for (uint256 i; i < b.length; i++) {
            if (i == 0) out = string.concat("[", vm.toString(uint8(b[i])));
            else out = string.concat(out, ", ", vm.toString(uint8(b[i])));
        }

        out = string.concat(out, "]");
    }

    function toStringBinaryArray(bytes memory b, uint256 lsb) internal pure returns (string memory out) {
        if (lsb > b.length << 3) lsb = b.length >> 3;

        for (uint256 i; i < lsb; i++) {
            uint256 j = (b.length << 3) - i - 1; // Start from least significant bit.
            uint8 bit = (uint8(b[j >> 3]) >> (7 - (j & 7))) & 1; // Read j-th bit from `b` bytestring.
            out = string.concat(out, i == 0 ? "[" : ", ", vm.toString(bit));
        }

        out = string.concat(out, "]");
    }

    function quote(string memory input) internal pure returns (string memory out) {
        out = string.concat('"', input, '"');
    }

    function bracket(string memory input) internal pure returns (string memory out) {
        out = string.concat("[", input, "]");
    }

    function generateProof(
        address receiver,
        uint256 key,
        uint256 nullifier,
        uint256 secret,
        uint256[DEPTH] memory nodes,
        uint256 root,
        string memory proverFile
    ) internal returns (bytes memory proof) {
        // Bash script executes inside `CIRCUITS_DIR`.
        string memory proverFileAbs = string.concat(CIRCUITS_DIR, "/", proverFile);

        // Write prover data.
        vm.writeFile(proverFileAbs, "");
        vm.writeLine(proverFileAbs, string.concat("receiver = ", quote(vm.toString(receiver))));
        vm.writeLine(proverFileAbs, string.concat("key = ", toStringBinaryArray(abi.encode(key), DEPTH)));
        vm.writeLine(proverFileAbs, string.concat("nullifier = ", quote(vm.toString(bytes32(nullifier)))));
        vm.writeLine(proverFileAbs, string.concat("secret = ", quote(vm.toString(bytes32(secret)))));
        vm.writeLine(proverFileAbs, string.concat("nodes = ", toStringBytes32Array(abi.encode(nodes))));
        vm.writeLine(proverFileAbs, string.concat("root = ", quote(vm.toString(bytes32(root)))));

        // Execute `nargo prove` to generate the proof.
        string[] memory script = new string[](3);

        script[0] = "bash";
        script[1] = GENERATE_PROOF_SCRIPT;
        script[2] = proverFile;

        // Generate proof data.
        proof = vm.ffi(script);

        require(proof.length != 0, "Invalid proof generated");

        // Don't cleanup main `Prover.toml`.
        if (keccak256(bytes(proverFile)) == keccak256(bytes(PROVER_FILE))) return proof;

        // // Cleanup temporary prover files.
        // script = new string[](2);

        // script[0] = "rm";
        // script[1] = proverFileAbs;

        // vm.ffi(script);
    }
}
