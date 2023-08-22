# CashCash

ZK privacy pools using [Noir](https://noir-lang.org/).

## Installation

### Foundry

Install [foundry](https://book.getfoundry.sh/getting-started/installation).

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Install dependencies.

```sh
forge install
```

### Noir

Install [nargo](https://noir-lang.org/getting_started/nargo_installation).

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -n
```

## Circuit Compilation

Navigate to the [circuits](circuits) directory.

```sh
cd circuits
```

### Test

Run the tests in [main.nr](circuits/src/main.nr).

```sh
nargo test
```

### Compile

Compile the main circuit in [main.nr](circuits/src/main.nr).

```sh
nargo compile
```

### Prove

Create a proof with public & private data from [`Prover.toml`](circuits/Prover.toml).

```sh
nargo prove
```

This creates the proof file [cashcash.proof](circuits/proofs/cashcash.proof).

### Verify

Successful verification of the proof [cashcash.proof](circuits/proofs/cashcash.proof) and the public input from [`Verifier.toml`](circuits/Verifier.toml) can be tested.

```sh
nargo verify
```

### Solidity Ultra Plonk Verifier

A proof for the circuit can be verified in Solidity.

```sh
nargo codegen-verifier
```

This creates the solidity Ultra Plonk verifier [plonk_vk.sol](circuits/contract/cashcash/plonk_vk.sol) specific to the circuit.

## Smart Contract Verification

Navigate to the project's root directory.

### Test

Run the tests in [Cash.t.sol](test/Cash.t.sol).

```sh
forge test
```
