# Gnark Sandbox

This repository contains Rust FFI bindings for the [Gnark](https://github.com/ConsenSys/gnark) zero-knowledge proof library from Go. It has been extracted and adapted from the [SP1](https://github.com/succinctlabs/sp1) project (commit [a80c17c66313918352b14561fbe5f12cc8416409](https://github.com/succinctlabs/sp1/commit/a80c17c66313918352b14561fbe5f12cc8416409)).

## Components

The repository contains two main crates:

1. `gnark-ffi` - Rust FFI bindings to the Gnark Go library
2. `gnark-cli` - A command-line interface for interacting with the Gnark FFI bindings

## Dependencies

The project has several key dependencies:

### Field Arithmetic Libraries
- `p3-field` - Core field arithmetic traits and operations
- `p3-baby-bear` - Implementation of the BabyBear finite field used in cryptographic operations
- `p3-symmetric` - Cryptographic primitives for symmetric cryptography

### SP1-specific Libraries
- `sp1-recursion-compiler` - Provides constraint system representation for proofs
- `sp1-core-machine` - Core state machine functionality
- `sp1-stark` - STARK proving system components

These SP1-specific dependencies are used by the FFI bindings to represent and handle circuit constraints, witnesses, and proof verification. The `p3-*` libraries provide the underlying finite field arithmetic operations that are essential for cryptographic operations.

## Functionality

The Gnark FFI bindings support:

1. **Building** circuits for both Plonk and Groth16 proving systems
2. **Proving** with these systems using witnesses
3. **Verifying** proofs against verification keys
4. **Testing** witness and constraint combinations

Each operation is available through both a Rust API and the `gnark-cli` command-line interface.

## Why Gnark?

Gnark is a powerful zero-knowledge proof library implemented in Go that supports multiple proving systems, including Plonk and Groth16. The FFI bindings allow Rust applications to leverage Gnark's capabilities while maintaining a Rust-native interface.

## Notes on Dependencies

The original SP1 context provides a comprehensive zero-knowledge VM ecosystem. This extract focuses only on the Gnark bindings, preserving the necessary dependencies while removing SP1-specific context that isn't required for the core Gnark functionality.

Key considerations:
- The field arithmetic libraries (p3-*) are essential for the cryptographic operations
- The SP1 dependencies provide necessary constraint and witness structures
- Further refactoring could potentially replace some SP1-specific dependencies with more generic implementations

## Usage

### Using Cargo

To build the project:
```bash
cargo build
```

To use the CLI:
```bash
cargo run --bin gnark-cli -- --help
```

#### Cargo Aliases

For convenience, the following cargo aliases are available:

```bash
# Test Groth16 system with test data
cargo test-groth16

# Generate a Groth16 proof with test data
cargo prove-groth16
```

These aliases are defined in `.cargo/config.toml` and provide shortcuts for common operations with the test data.

### Using Docker

You can also run the CLI using Docker:

#### Building the Docker Image

```bash
docker build -t gnark-sandbox .
```

#### Running Commands with Docker

```bash
# Show help
docker run gnark-sandbox --help

# Generate a Groth16 proof with test data
docker run -v $(pwd)/test-data:/test-data gnark-sandbox prove --system groth16 /test-data/groth16_circuit /test-data/groth16_circuit/groth16_witness.json /test-data/groth16_output/proof.bin
```

The Docker container mounts the test-data directory from your local machine, allowing the container to access the necessary files and write the output back to your local filesystem.