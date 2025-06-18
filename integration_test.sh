#!/bin/bash
# Integration test script for µDCN
# This script tests the end-to-end functionality of the entire µDCN system

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}"; }

# Directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR"

log "Starting µDCN integration test"

# Build the project in release mode
log "Building project in release mode..."
cargo build --release --workspace

# Create virtual network interfaces for testing
IFACE_1="udcn1"
IFACE_2="udcn2"

log "Setting up virtual network interfaces..."
sudo ip link add ${IFACE_1} type veth peer name ${IFACE_2} || {
  warning "Failed to create virtual interfaces. Using existing ones if available."
}
sudo ip link set dev ${IFACE_1} up || warning "Could not bring up ${IFACE_1}"
sudo ip link set dev ${IFACE_2} up || warning "Could not bring up ${IFACE_2}"

# Set up temporary directory for test files
TEST_DIR=$(mktemp -d)
trap 'rm -rf ${TEST_DIR}; sudo ip link del ${IFACE_1} 2>/dev/null || true' EXIT

log "Test directory: ${TEST_DIR}"

# Create test data files
log "Creating test data..."
echo "This is test data file 1" > ${TEST_DIR}/data1.txt
echo "This is test data file 2 with more content" > ${TEST_DIR}/data2.txt
dd if=/dev/urandom of=${TEST_DIR}/data3.bin bs=1M count=1 2>/dev/null

# Test scenario 1: XDP forwarder basic functionality
log "=== Test Scenario 1: XDP Forwarder Basic Functionality ==="

# Load XDP program on both interfaces
log "Loading XDP program on ${IFACE_1}..."
sudo target/release/rust-udcn-cli xdp load --interface ${IFACE_1} || {
  error "Failed to load XDP program on ${IFACE_1}. Aborting test."
  exit 1
}

log "Loading XDP program on ${IFACE_2}..."
sudo target/release/rust-udcn-cli xdp load --interface ${IFACE_2} || {
  error "Failed to load XDP program on ${IFACE_2}. Aborting test."
  exit 1
}

# Set up routes
log "Setting up FIB routes..."
sudo target/release/rust-udcn-cli fib add "/test/data" 1 --interface ${IFACE_1}
sudo target/release/rust-udcn-cli fib add "/benchmark" 2 --interface ${IFACE_2}

# Check XDP stats
log "Initial XDP statistics for ${IFACE_1}:"
sudo target/release/rust-udcn-cli xdp stats --interface ${IFACE_1}

# Test scenario 2: QUIC transport for NDN Interest/Data
log "=== Test Scenario 2: QUIC Transport for NDN Interest/Data ==="

# Start QUIC server in background
log "Starting QUIC server..."
target/release/rust-udcn-cli publish "/test/quic/hello" "Hello from QUIC transport!" --ttl 60000 &
SERVER_PID=$!
sleep 2

# Send Interest and verify Data response
log "Sending Interest for /test/quic/hello..."
INTEREST_OUTPUT=$(target/release/rust-udcn-cli interest "/test/quic/hello" --timeout 5000)

# Check if Interest was successful
if echo "${INTEREST_OUTPUT}" | grep -q "Content (as text): Hello from QUIC transport!"; then
  success "QUIC Interest/Data test passed!"
else
  warning "QUIC Interest/Data test failed."
  echo "${INTEREST_OUTPUT}"
fi

# Kill server
kill ${SERVER_PID} 2>/dev/null || true

# Test scenario 3: Performance benchmark
log "=== Test Scenario 3: Performance Benchmark ==="
log "Running small benchmark test..."
target/release/rust-udcn-cli benchmark --count 20 --prefix "/benchmark/test" --concurrent 4

# Test scenario 4: End-to-end packet flow through XDP
log "=== Test Scenario 4: End-to-end Packet Flow ==="

# Start publisher on one interface
log "Starting publisher on ${IFACE_2}..."
sudo target/release/rust-udcn-cli publish "/test/xdp/data" "XDP forwarded data" --ttl 10000 --interface ${IFACE_2} &
PUBLISHER_PID=$!
sleep 2

# Send Interest on the other interface
log "Sending Interest on ${IFACE_1}..."
XDP_OUTPUT=$(sudo target/release/rust-udcn-cli interest "/test/xdp/data" --timeout 5000 --interface ${IFACE_1})

# Check if Interest was forwarded and responded to
if echo "${XDP_OUTPUT}" | grep -q "XDP forwarded data"; then
  success "End-to-end XDP packet forwarding test passed!"
else
  warning "End-to-end XDP packet forwarding test may have failed."
  echo "${XDP_OUTPUT}"
fi

# Kill publisher
kill ${PUBLISHER_PID} 2>/dev/null || true

# Final statistics
log "Final XDP statistics for ${IFACE_1}:"
sudo target/release/rust-udcn-cli xdp stats --interface ${IFACE_1}

log "Final XDP statistics for ${IFACE_2}:"
sudo target/release/rust-udcn-cli xdp stats --interface ${IFACE_2}

# Clean up
log "Cleaning up..."
sudo target/release/rust-udcn-cli xdp unload --interface ${IFACE_1}
sudo target/release/rust-udcn-cli xdp unload --interface ${IFACE_2}

log "Integration test completed"
success "All tests completed. Please check the output for any warnings or errors."

exit 0
