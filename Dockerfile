# Multi-stage build for µDCN
FROM rust:1.76-buster as builder

# Install dependencies needed for eBPF development
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    linux-headers-amd64 \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty project
WORKDIR /usr/src/rust-udcn

# Copy over manifests and source code
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./rust-udcn-common ./rust-udcn-common
COPY ./rust-udcn-ebpf ./rust-udcn-ebpf
COPY ./rust-udcn-xdp ./rust-udcn-xdp
COPY ./rust-udcn-quic ./rust-udcn-quic
COPY ./rust-udcn-cli ./rust-udcn-cli

# Install bpf-linker for eBPF compilation
RUN cargo install bpf-linker

# Build the project
RUN cargo build --release

# Create a smaller runtime image
FROM debian:buster-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    libpcap0.8 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binaries from the builder stage
COPY --from=builder /usr/src/rust-udcn/target/release/rust-udcn-cli /usr/local/bin/udcn

# Create directory for certificates
RUN mkdir -p /etc/udcn/certs

# Set working directory
WORKDIR /usr/local/bin

# Create volume for persistent data
VOLUME ["/etc/udcn"]

# Default command
ENTRYPOINT ["udcn"]
CMD ["--help"]
