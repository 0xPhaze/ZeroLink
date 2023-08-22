# CashCash

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

## Circuits

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
