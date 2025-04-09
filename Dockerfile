FROM golang:1.22 AS go-builder

FROM rustlang/rust:nightly-bullseye-slim AS rust-builder

# Dependencies
RUN apt update && apt install -y clang

# Install Go 1.22
COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /gnark-sandbox

# Install Rust toolchain
COPY ./rust-toolchain.toml /gnark-sandbox/rust-toolchain.toml
RUN rustup install stable
RUN rustup show

# Copy repo
COPY . /gnark-sandbox

# Build the gnark-ffi CLI
RUN \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/gnark-sandbox/target \
  cargo build --package gnark-cli --release && cp ./target/release/gnark-cli /gnark-cli

FROM rustlang/rust:nightly-bullseye-slim
COPY --from=rust-builder /gnark-cli /gnark-cli

ENTRYPOINT ["/gnark-cli"]
