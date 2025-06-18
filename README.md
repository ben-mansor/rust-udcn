# µDCN: Micro Data-Centric Networking

µDCN is a high-performance, Rust-based implementation of Data-Centric Networking (DCN) principles, designed for modern networking environments. It utilizes eBPF/XDP for kernel-level packet processing and QUIC for reliable, secure transport.

## Features

- **All-Rust Implementation**: Entire codebase is written in Rust, offering memory safety and performance
- **eBPF/XDP Processing**: Kernel-level packet filtering and forwarding using eBPF for high-performance
- **QUIC Transport**: Modern, secure, and reliable transport over QUIC, based on the quinn crate
- **NDN Compatibility**: Implements Named Data Networking (NDN) protocol with TLV encoding
- **Low-Latency Data Exchange**: Optimized for Interest/Data model with minimal overhead
- **Content Store**: LRU-based caching in kernel space for content objects
- **Modular Design**: Well-structured crate design allows for flexible deployment scenarios

## Architecture

The project is structured as a Rust workspace with the following crates:

- `rust-udcn-common`: Common data structures, NDN packet definitions, and utility functions
- `rust-udcn-ebpf`: eBPF/XDP programs for kernel-space packet processing
- `rust-udcn-xdp`: Userspace management for eBPF/XDP programs
- `rust-udcn-quic`: QUIC-based NDN transport implementation
- `rust-udcn-cli`: Command-line interface for management and testing

### System Components

1. **Kernel-Space (eBPF/XDP)**:
   - Interest packet filtering and forwarding
   - LRU-based Content Store (CS)
   - Pending Interest Table (PIT)
   - Forwarding Information Base (FIB)

2. **Userspace Components**:
   - XDP program loader and manager
   - QUIC server and client for NDN transport
   - CLI tools for management and benchmarking

## Requirements

- **OS**: Linux 5.10+ (kernel must support eBPF/XDP)
- **Hardware**: Network interface with XDP support (optional for hardware offloading)
- **Build Requirements**: 
  - Rust 1.58+
  - LLVM/Clang for eBPF compilation
  - Linux headers for the target kernel

## Installation

### Build from Source

1. **Clone the repository**:
   ```
   git clone https://github.com/yourusername/rust-udcn.git
   cd rust-udcn
   ```

2. **Build the project**:
   ```
   cargo build --release
   ```

3. **Install the CLI tool**:
   ```
   cargo install --path rust-udcn-cli
   ```

### Docker Installation

Build and run using Docker:

```
docker build -t udcn .
docker run --privileged -v /sys/fs/bpf:/sys/fs/bpf udcn
```

### System Service Installation

1. **Copy the binary**:
   ```
   sudo cp target/release/rust-udcn-cli /usr/local/bin/udcn
   ```

2. **Install systemd service files**:
   ```
   sudo cp systemd/*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. **Enable and start the services**:
   ```
   sudo systemctl enable --now udcn-xdp.service
   sudo systemctl enable --now udcn-quic.service
   ```

## Usage

### Basic CLI Usage

```
# Load the XDP program on an interface
udcn xdp load --interface eth0

# Add a route to the FIB
udcn fib add /example/route 1

# Send an Interest packet
udcn interest /example/data

# Publish data
udcn publish /example/data "Hello, DCN World!" --ttl 60000

# Run a benchmark
udcn benchmark --count 1000 --prefix /benchmark --concurrent 10

# Check XDP statistics
udcn xdp stats
```

### Quick Test

Run the included test script to verify functionality:

```
./test_udcn.sh
```

## Development

### Building the eBPF Program

```
cd rust-udcn-ebpf
cargo build
```

### Running Tests

```
cargo test --workspace
```

## Performance Notes

- For optimal performance, use network interfaces with XDP offload capability
- The Content Store size is configurable through the LRU cache parameters
- QUIC transport parameters can be tuned for specific network conditions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [aya](https://github.com/aya-rs/aya) - Rust eBPF library
- [quinn](https://github.com/quinn-rs/quinn) - QUIC transport implementation
- [Named Data Networking (NDN)](https://named-data.net/) - For the NDN architecture
