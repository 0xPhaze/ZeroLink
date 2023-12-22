use dep::std;

global DEPTH: Field = 4;

/// Hashing function
fn hash_1(input: Field) -> Field {
    std::hash::poseidon::bn254::hash_1([input])
}

fn hash_2(left: Field, right: Field) -> Field {
    std::hash::poseidon::bn254::hash_2([left, right])
}

/// Compute the merkle tree root
fn compute_merkle_root(key: [u1; DEPTH], leaf: Field, nodes: [Field; DEPTH]) -> Field {
    // Start with the `leaf` node.
    let mut node: Field = leaf;

    for i in 0..DEPTH {
        // Hash current node `node` with provided node `nodes[i]`
        // to left or right with `nodes[i]` depending on `key`s i-th bit.
        node = if (key[i] == 0) {
            hash_2(node, nodes[i])
        } else {
            hash_2(nodes[i], node)
        };
    }

    node
}

/// Main circuit.
fn main(
    receiver: pub Field,
    key: [u1; DEPTH],
    secret: Field,
    nullifier: pub Field,
    nodes: [Field; DEPTH],
    root: pub Field
) {
    // Compute `leaf` using `secret`.
    let leaf: Field = hash_1(secret + 1);

    // Assert given `nullifier` is derived from `secret`.
    assert(nullifier == hash_1(secret + 2));

    // Ensure `leaf` is included in the merkle tree.
    assert(compute_merkle_root(key, leaf, nodes) == root);

    // Tie `receiver` into proof.
    assert(receiver + leaf + nullifier != 0);
}

/// Tests
fn helper_get_zero_nodes() -> [Field; DEPTH] {
    let mut nodes = [0; DEPTH];

    let mut z = 0;

    for d in 0..DEPTH {
        z = hash_2(z, z);

        nodes[d] = z;
    }

    nodes
}

#[test]
fn test_compute_merkle_root() {
    // This should produce the same root
    // for any `key` value on an empty tree.
    let key       = [0; DEPTH];
    let nodes     = helper_get_zero_nodes();
    let leaf      = nodes[0];
    let root      = hash_2(nodes[DEPTH - 1], nodes[DEPTH - 1]);
    let c_root    = compute_merkle_root(key, leaf, nodes);

    assert(root == c_root);
}
