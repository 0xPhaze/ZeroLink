# [ZeroLink](https://github.com/anupsv/ZeroLink-monorepo)

ZK [privacy pools](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364) using [Noir](https://noir-lang.org/).

```ml
.
├── README.md
├── circuits - "Noir circuits"
│   ├── Nargo.toml
│   ├── Prover.toml - "Circuit proof inputs"
│   ├── Verifier.toml - "Circuit verification inputs"
│   ├── contract
│   │   └── ZeroLink
│   │       └── plonk_vk.sol - "UltraPlonk Solidity verifier"
│   ├── proofs
│   │   └── ZeroLink.proof - "Generated proof data"
│   ├── src
│   │   └── main.nr - "Main Noir circuit"
│   └── target
│       └── ZeroLink.json
├── foundry.toml
├── src
│   └── ZeroLink.sol - "Main Solidity contract"
└── test
    └── ZeroLink.t.sol - "Solidity tests"
```

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

This creates the proof file [ZeroLink.proof](circuits/proofs/ZeroLink.proof).

### Verify

Successful verification of the proof [ZeroLink.proof](circuits/proofs/ZeroLink.proof) and the public input from [`Verifier.toml`](circuits/Verifier.toml) can be tested.

```sh
nargo verify
```

### Solidity Ultra Plonk Verifier

A proof for the circuit can be verified in Solidity.

```sh
nargo codegen-verifier
```

This creates the solidity Ultra Plonk verifier [plonk_vk.sol](circuits/contract/ZeroLink/plonk_vk.sol) specific to the circuit.

## Smart Contract Verification

Navigate to the project's root directory.

### Test

Run the tests in [ZeroLink.t.sol](test/ZeroLink.t.sol).

```sh
forge test
```
