// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UltraVerifier} from "../circuits/contract/ZeroLink/plonk_vk.sol";
import {MerkleLib, DEPTH} from "./utils/MerkleLib.sol";
import {NoirUtils} from "./utils/NoirUtils.sol";

contract ZeroLink is UltraVerifier {
    error InvalidRoot();
    error NullifierUsed();
    error TransferFailed();
    error InvalidDepositAmount();
    error LeafAlreadyCommitted();
    error LeafNonexistent();
    error InvalidReceiver();

    /// @notice Event emitted when proving that `nullifier` belongs to
    ///         a custom merkle tree with root `aspRoot` given by
    ///         an association set provider.
    event AssociationProven(uint256 indexed nullifier, uint256 indexed aspRoot);

    /// @notice Number of old merkle tree roots stored.
    uint256 public constant NUM_OLD_ROOTS = 10;
    /// @notice Fixed deposit amount.
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;

    /// @notice Sequential merkle tree leaf index.
    uint256 public key;
    /// @notice Current merkle tree root.
    uint256 public root;
    /// @notice Internal nodes used for updating the merkle root.
    /// @dev    These can not be used for proving a current deposit.
    uint256[DEPTH] public proofNodes;

    /// @notice Running index for array of old roots.
    uint256 public rootsIndex;
    /// @notice Array of old roots.
    uint256[NUM_OLD_ROOTS] public roots;

    /// @notice Keep track of already used nullifiers.
    mapping(uint256 nullifier => bool used) public nullifierUsed;
    /// @notice Keep track of already committed leaves.
    mapping(uint256 leaf => bool committed) public leafCommitted;

    constructor() {
        // Initialize inner nodes of empty tree.
        (root, proofNodes) = MerkleLib.getEmptyTree();
    }

    /// @notice Create a deposit by committing a leaf node to an
    ///         append-only, fixed size merkle tree. Every new leaf is
    ///         appended at `key`--the next available position in the merkle tree.
    ///         The leaf must correspond to the hash of `secret + 1`.
    function deposit(uint256 leaf) public payable {
        unchecked {
            // Require `DEPOSIT_AMOUNT` deposit value.
            if (msg.value != DEPOSIT_AMOUNT) revert InvalidDepositAmount();
            // Prevent committing an already existing leaf as
            // the `nullifier` cannot be spent twice.
            if (leafCommitted[leaf]) revert LeafAlreadyCommitted();

            // Mark the leaf as committed.
            leafCommitted[leaf] = true;

            // Store old `root` in `roots` array and increase `rootsIndex`.
            // Overflow not possible. Max 2^{DEPTH} deposits possible.
            roots[rootsIndex++ % NUM_OLD_ROOTS] = root;

            // Append leaf `leaf` at index `key` of merkle tree.
            // Update merkle root and internal nodes inserting `leaf` at index `key`.
            // Increment the merkle tree index `key`.
            // Throws if `leaf` or any of `nodes` is not a field element.
            (root, proofNodes) = MerkleLib.appendLeaf(key++, leaf, proofNodes);
        }
    }

    /// @notice Withdraw from a previously committed deposit, consuming the
    ///         single-use `nullifier` note. A previous committment is proven
    ///         via a zero knowledge proof.
    function withdraw(address receiver, uint256 nullifier, uint256 root_, bytes calldata proof) public {
        // We use `receiver == address(0)` to prove an association.
        if (receiver == address(0)) revert InvalidReceiver();

        // Check `nullifier` to prevent replay.
        if (nullifierUsed[nullifier]) revert NullifierUsed();

        // Mark `nullifier` as used.
        nullifierUsed[nullifier] = true;

        // Withdrawer's proof must relate to a recently committed root.
        if (!_isValidRoot(root_)) revert InvalidRoot();

        // Verify the zero knowledge proof.
        verifyProof(receiver, nullifier, root_, proof);

        // Refund caller.
        (bool success,) = receiver.call{value: DEPOSIT_AMOUNT}("");
        if (!success) revert TransferFailed();
    }

    /// @notice Prove an association of a withdrawal (tied to `nullifier`)
    ///         to a set of deposit leaves via a zero knowledge proof.
    function proveAssociation(uint256 nullifier, uint256 aspRoot, bytes calldata proof) public {
        // We use `receiver == address(0)` to prove an association.
        address receiver = address(0);

        // Verify the zero knowledge proof.
        verifyProof(receiver, nullifier, aspRoot, proof);

        // Emit event.
        // Note: This does NOT guarantee existence of the leaf.
        emit AssociationProven(nullifier, aspRoot);
    }

    /// @notice Checks whether `root_` is one of the last `NUM_OLD_ROOTS` stored roots.
    function _isValidRoot(uint256 root_) internal view returns (bool) {
        unchecked {
            if (root_ == root) return true;

            uint256 endIndex = rootsIndex;
            // Overflow not possible. Max 2^{DEPTH} nodes and root updates.
            uint256 index = endIndex + NUM_OLD_ROOTS;
            do {
                // Cycle back `index`.
                // Return `true` if a valid previously committed root was found.
                if (roots[index % NUM_OLD_ROOTS] == root_) return true;
            } while (--index != endIndex); // Underflow not possible.

            return false;
        }
    }

    /// @notice Verifies a zero knowledge proof.
    ///         The proof demonstrates:
    ///           * Knowledge of pre-image of leaf: `hash(secret + 1)`
    ///           * `nullifier` is derived correctly: `hash(secret + 2)`
    ///           * The leaf is contained in a merkle tree with root `root`
    ///           * The proof is generated for `receiver`
    function verifyProof(address receiver, uint256 nullifier, uint256 root_, bytes calldata proof) public view {
        // Set up public inputs for `proof` verification.
        // The circuit in Noir expects 3 public inputs.
        bytes32[] memory publicInputs = new bytes32[](3);

        publicInputs[0] = bytes32(uint256(uint160(receiver)));
        publicInputs[1] = bytes32(NoirUtils.toField(nullifier));
        publicInputs[2] = bytes32(NoirUtils.toField(root_));

        // Verify zero knowledge proof.
        this.verify(proof, publicInputs);
    }
}
