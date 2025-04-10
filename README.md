# Gnark Sandbox

This repository contains Rust FFI bindings for the [Gnark](https://github.com/ConsenSys/gnark) zero-knowledge proof library from Go. It has been extracted and adapted from the [SP1](https://github.com/succinctlabs/sp1) project (commit [a80c17c66313918352b14561fbe5f12cc8416409](https://github.com/succinctlabs/sp1/commit/a80c17c66313918352b14561fbe5f12cc8416409)).

This branch is for debugging the integration of [icicle-gnark](https://github.com/ingonyama-zk/icicle-gnark) and GPU acceleration of groth16 recursive proofs.

## Components

The repository contains two main crates:

1. `gnark-ffi` - Rust FFI bindings to the Gnark Go library
2. `gnark-cli` - A command-line interface for interacting with the Gnark FFI bindings

## Usage

### Using Docker

You can also run the CLI using Docker:

#### Building the Docker Image

```bash
docker build -t gnark-sandbox .
```

#### Running Commands with Docker

##### Test Data

The test-data folder is not included in this repository and should be downloaded separately. It contains the necessary circuit definitions, witness data, and expected outputs for running tests and examples.

To obtain the test data:
1. Download it from the official release page
2. Extract it to the project root directory
3. Ensure the folder is named 'test-data'

The test-data directory structure should contain:
- `groth16_circuit/` - Circuit definitions for Groth16 tests
- `groth16_output/` - Expected output files for verification
- Additional test vectors and example inputs


```bash
# Show help
docker run gnark-sandbox --help

# Generate a Groth16 proof with test data
docker run --gpus all -v $(pwd)/test-data:/test-data gnark-sandbox prove --system groth16 /test-data/groth16_circuit /test-data/groth16_circuit/groth16_witness.json /test-data/groth16_output/proof.bin
```

The Docker container mounts the test-data directory from your local machine, allowing the container to access the necessary files and write the output back to your local filesystem.
