// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2 as console} from "forge-std/Test.sol";

import {DEPTH} from "../../src/MerkleLib.sol";

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

    function toField(uint256 x) internal pure returns (uint256) {
        if (x >= PRIME_FIELD) revert InvalidFieldElement();

        return x;
    }

    function toField(bytes32 x) internal pure returns (bytes32) {
        if (uint256(x) >= PRIME_FIELD) revert InvalidFieldElement();

        return x;
    }

    function asField(uint256 x) internal pure returns (uint256) {
        return x % PRIME_FIELD;
    }

    function asField(bytes32 x) internal pure returns (bytes32) {
        return bytes32(uint256(x) % PRIME_FIELD);
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
        bytes32 nullifier,
        bytes32 secret,
        bytes32[DEPTH] memory nodes,
        bytes32 root,
        string memory proverFile
    ) internal returns (bytes memory proof) {
        // Bash script executes inside `CIRCUITS_DIR`.
        string memory proverFileAbs = string.concat(CIRCUITS_DIR, "/", proverFile);

        // Write prover data.
        vm.writeFile(proverFileAbs, "");
        vm.writeLine(proverFileAbs, string.concat("receiver = ", quote(vm.toString(receiver))));
        vm.writeLine(proverFileAbs, string.concat("key = ", toStringBinaryArray(abi.encode(key), DEPTH)));
        vm.writeLine(proverFileAbs, string.concat("nullifier = ", toStringUint8Array(abi.encode(nullifier))));
        vm.writeLine(proverFileAbs, string.concat("secret = ", toStringUint8Array(abi.encode(secret))));
        vm.writeLine(proverFileAbs, string.concat("nodes = ", toStringUint8Array(abi.encode(nodes))));
        vm.writeLine(proverFileAbs, string.concat("root = ", toStringUint8Array(abi.encode(root))));

        // Execute `nargo prove` to generate the proof.
        string[] memory script = new string[](3);

        script[0] = "bash";
        script[1] = GENERATE_PROOF_SCRIPT;
        script[2] = proverFile;

        vm.ffi(script);

        // Read generated proof file.
        proof = readProofBytes();

        // Don't cleanup main `Prover.toml`.
        if (keccak256(bytes(proverFile)) == keccak256(bytes(PROVER_FILE))) return proof;

        // // Cleanup temporary prover files.
        // script = new string[](2);

        // script[0] = "rm";
        // script[1] = proverFileAbs;

        // vm.ffi(script);
    }
}
