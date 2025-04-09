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

### Debug Information

Directly calling the go-build command, as well as linking the ICICLE libraries, takes place in [build.rs](gnark-ffi/build.rs).

The Go build command that runs during compilation:
```bash
go build -tags=debug,icicle -o <OUTPUT_PATH>/libsp1gnark.a -buildmode=c-archive .
```

This builds the `sp1gnark` library from Go code, which is then linked with the Rust application. The linking configuration includes:

- Main static library: `sp1gnark` (built from Go code)
- Dynamic ICICLE libraries:
  - `icicle_curve_bn254`
  - `icicle_device` 
  - `icicle_field_bn254`
  - `icicle_backend_cuda_device`
  - `icicle_backend_cuda_curve_bn254`
  - `icicle_backend_cuda_field_bn254`
- Library search paths:
  - `/usr/local/lib`
  - `/usr/local/lib/backend/bn254/cuda`
  - `/usr/local/lib/backend/cuda`
- Additional framework links on macOS: `CoreFoundation` and `Security`

You can find all the preparatory things you need to build with ICICLE and CUDA in [Dockerfile](./Dockerfile), namely:
```Dockerfile
RUN go get github.com/ingonyama-zk/icicle-gnark/v3; \
    cd $(go env GOMODCACHE)/github.com/ingonyama-zk/icicle-gnark/v3@v3.2.2/wrappers/golang; \
    /bin/bash build.sh -curve=bn254;
```

#### Repeat problem

```bash
docker build -t gnark-sandbox .
```

and get an error
```
23.34   = note: some arguments are omitted. use `--verbose` to show all linker arguments
23.34   = note: /usr/bin/ld: /gnark-sandbox/target/release/deps/libgnark_ffi-f8e0c3c2801a3465.rlib(000036.o): in function `_cgo_1710fb6b19b6_Cfunc_bn254_matrix_transpose':
23.34           /tmp/go-build/cgo-gcc-prolog:59: undefined reference to `bn254_matrix_transpose'
23.34           collect2: error: ld returned 1 exit status
23.34
23.34   = note: some `extern` functions couldn't be found; some native libraries may need to be installed or have their path specified
23.34   = note: use the `-l` flag to specify native libraries to link
23.34   = note: use the `cargo:rustc-link-lib` directive to specify the native libraries to link with Cargo (see https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib)
23.34
23.35 error: could not compile `gnark-cli` (bin "gnark-cli") due to 1 previous error
23.40 cp: cannot stat './target/release/gnark-cli': No such file or directory
------
Dockerfile:65
--------------------
  64 |     # Build the gnark-ffi CLI with CUDA support
  65 | >>> RUN \
  66 | >>>   --mount=type=cache,target=/root/.cargo/registry \
  67 | >>>   --mount=type=cache,target=/gnark-sandbox/target \
  68 | >>>   cargo build --package gnark-cli --release; \
  69 | >>>   cp ./target/release/gnark-cli /gnark-cli
  70 |
--------------------
ERROR: failed to solve: process "/bin/sh -c cargo build --package gnark-cli --release;   cp ./target/release/gnark-cli /gnark-cli" did not complete successfully: exit code: 1
```
