// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/cashcash/plonk_vk.sol";

contract Cash is UltraVerifier {
    error NullifierUsed();

    bytes32 commitment;

    mapping(bytes32 => bool) nullifierUsed;

    function verify(bytes calldata proof, bytes32 nullifier) public {
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        nullifierUsed[nullifier] = true;

        bytes32[] memory publicInputs = new bytes32[](3);

        publicInputs[0] = bytes32(uint256(uint160(msg.sender)));
        publicInputs[1] = nullifier;
        publicInputs[2] = commitment;

        this.verify(proof, publicInputs);
    }
}
