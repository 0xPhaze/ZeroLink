global CANDIDATES: Field = 2;

use dep::std;

/// Main circuit.
fn main(
  receiver: pub Field,
  nullifier: pub Field,
  secret: Field,
  polynomial: [Field; CANDIDATES],
  commitment: pub Field,
) {
  // Compute `leaf` using `nullifier` and `secret`.
  let leaf: Field = std::hash::pedersen([nullifier, secret])[0];

  // Ensure `leaf` is included in the polynomial.
  assert(evaluate_polynomial(polynomial, leaf) == 0);

  // Ensure the the public commitment corresponds to the provided polynomial.
  assert(std::hash::pedersen(polynomial)[0] == commitment);

  // Tie `receiver` into proof.
  assert(receiver != 0);
}

/// Evaluate a polynomial with given roots at `x`.
fn evaluate_polynomial(polynomial: [Field; CANDIDATES], x: Field) -> Field {
  let mut out: Field = 1;

  for i in 0..CANDIDATES {
    out *= (x - polynomial[i]);
  }
  
  out
}


#[test]
fn test_main() {
  let receiver: Field = 0xbabe;
  let nullifier: Field = 1234;
  let secret: Field = 33887744;

  let leaf: Field = std::hash::pedersen([nullifier, secret])[0];

  let polynomial = [
    leaf,
    0x30644e72e131a029b85045b51d480807486e4c754ae9f95bbfba6db6d86a63d3,
  ];

  let commitment = std::hash::pedersen(polynomial)[0];

  std::println(f"receiver: {receiver}");
  std::println(f"nullifier: {nullifier}");
  std::println(f"secret: {secret}");
  std::println(f"leaf: {leaf}");
  std::println(f"commitment: {commitment}");

  main(receiver, nullifier, secret, polynomial, commitment);
}

