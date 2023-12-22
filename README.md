# [ZeroLink](https://github.com/0xPhaze/ZeroLink)

ZK [privacy pools](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4563364) written in [Noir](https://noir-lang.org/) and [Solidity](https://soliditylang.org/).

**Project layout:**

```ml
.
├── README.md
├── circuits - "Noir circuits"
│   ├── Nargo.toml
│   ├── contract
│   │   └── ZeroLink
│   │       └── plonk_vk.sol - "Generated UltraPlonk Solidity verifier"
│   └── src
│       └── main.nr - "ZeroLink Noir circuit"
├── foundry.toml
├── src
│   └── ZeroLink.sol - "ZeroLink Solidity contract"
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

Install foundry dependencies.

```sh
forge install
```

### Noir

Install [nargo](https://noir-lang.org/getting_started/nargo_installation) and switch to latest nightly version.

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -n
```

## Noir Circuit Compilation

Navigate to the [circuits](circuits) directory.

```sh
cd circuits
```

### Test

Run the tests in [circuits/src/main.nr](circuits/src/main.nr).

```sh
nargo test
```

### Compile

Compile the main circuit.

```sh
nargo compile
```

### Prove

Create a proof with dummy public & private data from [`Prover.toml`](circuits/Prover.toml).

```sh
nargo prove
```

This creates the proof file [circuits/proofs/ZeroLink.proof](circuits/proofs/ZeroLink.proof).

### Verify

The verification of the proof ([ZeroLink.proof](circuits/proofs/ZeroLink.proof)) and the verifier public input ([`Verifier.toml`](circuits/Verifier.toml)) can be tested.

```sh
nargo verify
```

### Generating Solidity Ultra Plonk Verifier

A proof for the circuit can be verified in Solidity.

```sh
nargo codegen-verifier
```

This creates the Solidity Ultra Plonk verifier ([circuits/contract/ZeroLink/plonk_vk.sol](circuits/contract/ZeroLink/plonk_vk.sol)) specific to the circuit.

## Smart Contract Verification

Navigate to the project's root directory.

### Solidity Testing

Run the tests in [ZeroLink.t.sol](test/ZeroLink.t.sol).

```sh
forge test
```

Note that the tests contain hardcoded proofs that need to be updated in the case that the verification key ([plonk_vk.sol](circuits/contract/ZeroLink/plonk_vk.sol)) changes.
