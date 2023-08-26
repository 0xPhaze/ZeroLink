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
    string constant PROVER_FILE = "circuits/Prover.toml";
    string constant PROOF_FILE = "circuits/proofs/ZeroLink.proof";

    function getProofBytes() internal view returns (bytes memory proof) {
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

    function toStringBinaryArray(bytes memory b) internal pure returns (string memory out) {
        for (uint256 i; i < b.length; i++) {
            if (i == 0) out = string.concat("[", vm.toString(uint8(b[i >> 3]) >> (7 - (i & 7)) & 1));
            else out = string.concat(out, ", ", vm.toString(uint8(b[i >> 3]) >> (7 - (i & 7)) & 1));
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
        bytes32[DEPTH] memory nodes
    ) internal returns (bytes memory out) {
        vm.writeFile(PROVER_FILE, "");
        vm.writeLine(PROVER_FILE, string.concat("receiver = ", quote(vm.toString(receiver))));
        vm.writeLine(PROVER_FILE, string.concat("key = ", toStringBinaryArray(abi.encode(key))));
        vm.writeLine(PROVER_FILE, string.concat("nullifier = ", toStringUint8Array(abi.encode(nullifier))));
        vm.writeLine(PROVER_FILE, string.concat("secret = ", toStringUint8Array(abi.encode(secret))));
        vm.writeLine(PROVER_FILE, string.concat("nodes = ", toStringUint8Array(abi.encode(nodes))));

        // string[] memory script = new string[](4);
        // script[0] = "cd";
        // script[1] = CIRCUITS_DIR;
        // out = vm.ffi(script);

        // script = new string[](1);
        // script[0] = "ls";

        string[] memory script = new string[](5);
        script[0] = "cd";
        script[1] = CIRCUITS_DIR;
        script[2] = "&&";
        script[3] = "nargo";
        script[4] = "prove";

        out = vm.ffi(script);

        console.log(string(out));
    }
}
