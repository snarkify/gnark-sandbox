# Start with CUDA base image
FROM nvidia/cuda:12.2.2-devel-ubuntu22.04 AS cuda-base

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    git \
    cmake \
    curl \
    ca-certificates \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Go
ENV GOLANG_VERSION=1.23.0
RUN curl -L https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -xz -C /usr/local
ENV PATH="/usr/local/go/bin:${PATH}"
RUN go version

WORKDIR /gnark-sandbox

# Install Rust toolchain
COPY ./rust-toolchain.toml /gnark-sandbox/rust-toolchain.toml
RUN rustup show

# Copy repository
COPY . /gnark-sandbox

# Explicitly fix go.mod versions
WORKDIR /gnark-sandbox/gnark-ffi/go

RUN go mod tidy

# Add caching for the icicle-gnark build

# This is the normal version of build icicle command, but because it takes a long time to compile, I added a cache
#RUN go get github.com/ingonyama-zk/icicle-gnark/v3; \
#    cd $(go env GOMODCACHE)/github.com/ingonyama-zk/icicle-gnark/v3@v3.2.2/wrappers/golang; \
#    /bin/bash build.sh -curve=bn254;

RUN --mount=type=cache,target=/root/.cache/icicle-gnark \
    go get github.com/ingonyama-zk/icicle-gnark/v3; \
    ICICLE_DIR=$(go env GOMODCACHE)/github.com/ingonyama-zk/icicle-gnark/v3@v3.2.2; \
    if [ -d "/root/.cache/icicle-gnark/libs" ]; then \
        echo "Using cached icicle-gnark libraries"; \
        mkdir -p /usr/local/lib /usr/local/lib/backend/bn254/cuda /usr/local/lib/backend/cuda; \
        cp -r /root/.cache/icicle-gnark/libs/* /usr/local/lib/; \
    else \
        cd $ICICLE_DIR/wrappers/golang; \
        /bin/bash build.sh -curve=bn254; \
        mkdir -p /root/.cache/icicle-gnark/libs; \
        cp -r /usr/local/lib/libicicle_* /root/.cache/icicle-gnark/libs/; \
        mkdir -p /root/.cache/icicle-gnark/libs/backend/; \
        cp -r /usr/local/lib/backend/* /root/.cache/icicle-gnark/libs/backend/; \
    fi;

# Build the gnark-ffi CLI with CUDA support
RUN \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/gnark-sandbox/target \
  cargo build --package gnark-cli --release; \ 
  cp ./target/release/gnark-cli /gnark-cli

FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04

COPY --from=cuda-base /gnark-cli /gnark-cli

# Copy the frontend libs
COPY --from=cuda-base /usr/local/lib/libicicle_curve_bn254.so /usr/local/lib/libicicle_curve_bn254.so
COPY --from=cuda-base /usr/local/lib/libicicle_device.so /usr/local/lib/libicicle_device.so
COPY --from=cuda-base /usr/local/lib/libicicle_field_bn254.so /usr/local/lib/libicicle_field_bn254.so

# Set the backend lib location and copy them
ENV ICICLE_BACKEND_INSTALL_DIR=/usr/local/lib/backend
COPY --from=cuda-base /usr/local/lib/backend/**/*.so /usr/local/lib/backend

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/cuda/lib64:$LD_LIBRARY_PATH

RUN ldconfig

ENTRYPOINT ["/gnark-cli"]
