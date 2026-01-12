#!/bin/bash
# Kestrel Build Script
# Builds the entire Kestrel project in release mode

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "  Kestrel Build Script"
echo "========================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v rustc &> /dev/null; then
    echo -e "${RED}Error: Rust not found${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

RUST_VERSION=$(rustc --version | grep -oE '[0-9]+\.[0-9]+')
REQUIRED_VERSION="1.82"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$RUST_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${YELLOW}Warning: Rust version $RUST_VERSION detected, 1.82+ recommended${NC}"
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Cargo not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Rust found: $(rustc --version)${NC}"

# Check for clang (required for eBPF)
if command -v clang &> /dev/null; then
    echo -e "${GREEN}✓ clang found: $(clang --version | head -n1)${NC}"
else
    echo -e "${YELLOW}Warning: clang not found. eBPF programs will not be built.${NC}"
    echo "  Install clang: sudo apt-get install clang"
fi

echo ""
echo "Building Kestrel..."
echo ""

# Set build flags
export RUSTFLAGS="-C opt-level=3 -C lto=fat -C codegen-units=1"
export CARGO_TERM_COLOR=always

# Build
if cargo build --workspace --release; then
    echo ""
    echo -e "${GREEN}========================================"
    echo "  Build Successful!"
    echo "========================================${NC}"
    echo ""
    echo "Binaries:"
    echo "  - target/release/kestrel"
    echo "  - target/release/kestrel-benchmark"
    echo ""
    echo "To install:"
    echo "  sudo cp target/release/kestrel /usr/local/bin/"
    echo "  sudo cp target/release/kestrel-benchmark /usr/local/bin/"
else
    echo ""
    echo -e "${RED}========================================"
    echo "  Build Failed!"
    echo "========================================${NC}"
    exit 1
fi
