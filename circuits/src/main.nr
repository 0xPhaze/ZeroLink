use dep::std;

global DEPTH: Field = 4;

/// Hashing function
fn hash(left: Field, right: Field) -> Field {
  std::hash::poseidon::bn254::hash_2([left, right])
}

/// Compute the merkle tree root
fn compute_merkle_root(key: [u1; DEPTH], leaf: Field, nodes: [Field; DEPTH]) -> Field {
  // Start with the `leaf` node.
  let mut root: Field = leaf;

  for i in 0..DEPTH {
    let n = nodes[i];

    // Hash current node `root` with left provided node `nodes[i]`.
    let mut left = n;
    let mut right = root;

    // Or hash it with right `nodes[i]` to the right,
    // depending on `key`s i-th bit.
    if (key[i] == 0) {
      left = root;
      right = n;
    }

    root = hash(left, right);
  }

  root
}

/// Main circuit.
fn main(
  receiver: pub Field,
  key: [u1; DEPTH],
  nullifier: pub Field,
  secret: Field,
  nodes: [Field; DEPTH],
  root: pub Field,
) {
  // Compute `leaf` using `nullifier` and `secret`.
  let leaf: Field = hash(nullifier, secret);

  // Ensure `leaf` is included in the merkle tree.
  assert(compute_merkle_root(key, leaf, nodes) == root);

  // Tie `receiver` into proof.
  // TODO: Is this safe enough?
  assert(receiver != 0);
}




/// Tests

fn helper_get_zero_nodes() -> [Field; DEPTH] {
  let mut nodes = [0; DEPTH];

  let mut z = 0;

  for d in 0..DEPTH {
    z = hash(z, z);

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
  let root      = hash(nodes[DEPTH - 1], nodes[DEPTH - 1]);
  let c_root    = compute_merkle_root(key, leaf, nodes);

  assert(root == c_root);

}

// #[test]
// fn test_main() {
//   let receiver  = 0x00000000000000000000000000000000000A11cE;
//   let key       = [0; DEPTH];
//   let nullifier = [0x22 as u8, 0x22, 0x44, 0x44, 0x88, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//   let secret    = [0x13 as u8, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//   let leaf      = hash(nullifier, secret);
//   let nodes     = helper_get_zero_nodes();
//   let root      = compute_merkle_root(key, leaf, nodes);

//   std::println("receiver =");
//   std::println(receiver);
//   std::println("key =");
//   std::println(key);
//   std::println("nullifier =");
//   std::println(nullifier);
//   std::println("secret =");
//   std::println(secret);
//   std::println("leaf =");
//   std::println(leaf);
//   std::println("nodes =");
//   std::println(nodes);
//   std::println("root =");
//   std::println(root);

//   main(receiver, key, nullifier, secret, nodes, root);

//   let receiver  = 0x0000000000000000000000000000000000000B0b;
//   let key       = [1, 0, 0, 0];
//   let nullifier = [0xab as u8, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//   let secret    = [0x12 as u8, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//   let leaf      = hash(nullifier, secret);
//   let nodes     = [0xe2 as u8,0x4b,0xc9,0xee,0x22,0xe1,0xb0,0x7b,0xf1,0x3e,0x1d,0x42,0x48,0xc1,0xf6,0xcd,0x95,0xbc,0x32,0x65,0xfe,0xda,0xc5,0x8f,0x13,0xf8,0xb6,0x02,0xcb,0xd1,0x70,0x7a , 180, 193, 25, 81, 149, 124, 111, 143, 100, 44, 74, 246, 28, 214, 178, 70, 64, 254, 198, 220, 127, 198, 7, 238, 130, 6, 169, 158, 146, 65, 13, 48, 33, 221, 185, 163, 86, 129, 92, 63, 172, 16, 38, 182, 222, 197, 223, 49, 36, 175, 186, 219, 72, 92, 155, 165, 163, 227, 57, 138, 4, 183, 186, 133, 229, 135, 105, 179, 42, 27, 234, 241, 234, 39, 55, 90, 68, 9, 90, 13, 31, 182, 100, 206, 45, 211, 88, 231, 252, 191, 183, 140, 38, 161, 147, 68];
//   let root      = compute_merkle_root(key, leaf, nodes);

//   std::println("receiver =");
//   std::println(receiver);
//   std::println("key =");
//   std::println(key);
//   std::println("nullifier =");
//   std::println(nullifier);
//   std::println("secret =");
//   std::println(secret);
//   std::println("leaf =");
//   std::println(leaf);
//   std::println("nodes =");
//   std::println(nodes);
//   std::println("root =");
//   std::println(root);

//   main(receiver, key, nullifier, secret, nodes, root);
// }

// #[test]
// fn test_zeros() {
//   assert(zeros(0) == [0xad,0x32,0x28,0xb6,0x76,0xf7,0xd3,0xcd,0x42,0x84,0xa5,0x44,0x3f,0x17,0xf1,0x96,0x2b,0x36,0xe4,0x91,0xb3,0x0a,0x40,0xb2,0x40,0x58,0x49,0xe5,0x97,0xba,0x5f,0xb5]);
//   assert(zeros(1) == [0xb4,0xc1,0x19,0x51,0x95,0x7c,0x6f,0x8f,0x64,0x2c,0x4a,0xf6,0x1c,0xd6,0xb2,0x46,0x40,0xfe,0xc6,0xdc,0x7f,0xc6,0x07,0xee,0x82,0x06,0xa9,0x9e,0x92,0x41,0x0d,0x30]);
//   assert(zeros(2) == [0x21,0xdd,0xb9,0xa3,0x56,0x81,0x5c,0x3f,0xac,0x10,0x26,0xb6,0xde,0xc5,0xdf,0x31,0x24,0xaf,0xba,0xdb,0x48,0x5c,0x9b,0xa5,0xa3,0xe3,0x39,0x8a,0x04,0xb7,0xba,0x85]);
//   assert(zeros(3) == [0xe5,0x87,0x69,0xb3,0x2a,0x1b,0xea,0xf1,0xea,0x27,0x37,0x5a,0x44,0x09,0x5a,0x0d,0x1f,0xb6,0x64,0xce,0x2d,0xd3,0x58,0xe7,0xfc,0xbf,0xb7,0x8c,0x26,0xa1,0x93,0x44]);
//   assert(zeros(4) == [0x0e,0xb0,0x1e,0xbf,0xc9,0xed,0x27,0x50,0x0c,0xd4,0xdf,0xc9,0x79,0x27,0x2d,0x1f,0x09,0x13,0xcc,0x9f,0x66,0x54,0x0d,0x7e,0x80,0x05,0x81,0x11,0x09,0xe1,0xcf,0x2d]);
// }

// #[test]
// fn test_poseidon() {
//   // let hash1 = std::hash::poseidon::bn254::hash_2([1, 2]);
//   // assert(hash1 == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
//   let mut out = 0;

//   for _ in 0..(DEPTH + 1) {
//     out = std::hash::poseidon::bn254::hash_2([out, out]);

//     std::println(out);
//   }
// }