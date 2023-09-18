// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @notice Noir utils contract
library NoirUtils {
    error InvalidFieldElement();

    /// @dev Prime field order
    uint256 constant PRIME_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

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
}
