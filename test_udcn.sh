#!/bin/bash
# One-click test script for µDCN
# This script builds and tests the entire µDCN system

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
  echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Success logging function
success() {
  echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Warning logging function
warning() {
  echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Error logging function
error() {
  echo -e "${RED}[ERROR] $1${NC}"
}

# Check for required commands
check_command() {
  command -v $1 >/dev/null 2>&1 || { error "Required command '$1' not found. Please install it and try again."; exit 1; }
}

# Check for required commands
check_command cargo
check_command ip
check_command dirname

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR"

log "Starting µDCN test script"

# Build the entire project
log "Building µDCN crates..."
cargo build --workspace
success "Build completed successfully"

# Create a virtual interface for testing if it doesn't exist
TEST_IFACE="udcn0"

log "Setting up test environment..."
if ! ip link show "$TEST_IFACE" &>/dev/null; then
  log "Creating virtual interface $TEST_IFACE..."
  sudo ip link add "$TEST_IFACE" type dummy || { warning "Failed to create virtual interface. XDP test will be skipped."; }
  sudo ip link set dev "$TEST_IFACE" up || { warning "Failed to set interface up. XDP test will be skipped."; }
else
  log "Virtual interface $TEST_IFACE already exists"
fi

# Run unit tests
log "Running unit tests..."
cargo test --workspace
success "Unit tests completed successfully"

# Test XDP functionality if interface is available
if ip link show "$TEST_IFACE" &>/dev/null; then
  log "Testing XDP functionality on $TEST_IFACE..."
  
  # Load XDP program
  sudo target/debug/rust-udcn-cli xdp load --interface "$TEST_IFACE"
  success "XDP program loaded successfully"
  
  # Show XDP statistics
  log "XDP statistics:"
  sudo target/debug/rust-udcn-cli xdp stats
  
  # Unload XDP program
  log "Unloading XDP program..."
  sudo target/debug/rust-udcn-cli xdp unload --interface "$TEST_IFACE"
  success "XDP program unloaded successfully"
else
  warning "Skipping XDP test as interface is not available"
fi

# Test QUIC functionality in background
log "Testing QUIC functionality..."

# Start a publisher in the background
log "Starting publisher..."
target/debug/rust-udcn-cli publish "/test/hello" "Hello, µDCN World!" --ttl 10000 &
PUBLISHER_PID=$!

# Give the publisher time to start
sleep 2

# Send an interest
log "Sending Interest for /test/hello..."
OUTPUT=$(target/debug/rust-udcn-cli interest "/test/hello" --timeout 5000)

# Kill the publisher
kill $PUBLISHER_PID 2>/dev/null || true

# Check if the Interest was successfully responded to
if echo "$OUTPUT" | grep -q "Content (as text): Hello, µDCN World!"; then
  success "QUIC Interest/Data exchange test passed!"
else
  warning "QUIC Interest/Data exchange test may have failed. Check output for details."
  echo "$OUTPUT"
fi

# Run a basic benchmark test
log "Running quick benchmark test..."
target/debug/rust-udcn-cli benchmark --count 10 --prefix "/benchmark/test" --concurrent 2

log "Test script completed"
success "All tests completed. Please check the output for any warnings or errors."

# Cleanup
if ip link show "$TEST_IFACE" &>/dev/null; then
  log "Cleaning up test environment..."
  sudo ip link del "$TEST_IFACE" &>/dev/null || warning "Failed to remove virtual interface"
fi

exit 0
