#!/bin/bash
# Kestrel End-to-End Test Script
# Tests the complete detection pipeline with sample events

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  Kestrel End-to-End Test"
echo "========================================"
echo ""

# Build if needed
if [ ! -f "target/release/kestrel" ]; then
    echo "Building Kestrel..."
    bash scripts/build.sh
    echo ""
fi

# Create test rules directory
TEST_RULES_DIR="/tmp/kestrel-test-rules"
mkdir -p "$TEST_RULES_DIR"

# Create a simple EQL rule for testing
cat > "$TEST_RULES_DIR/suspicious-exec.json" << 'EOF'
{
  "id": "suspicious-exec-001",
  "name": "Suspicious /tmp Execution",
  "description": "Detects execution of binaries from /tmp directory",
  "severity": "High",
  "eql": "process where process.executable contains \"/tmp/\"",
  "enabled": true
}
EOF

# Create a sequence rule
cat > "$TEST_RULES_DIR/privilege-escalation.json" << 'EOF'
{
  "id": "priv-esc-001",
  "name": "Potential Privilege Escalation",
  "description": "Detects sudo followed by chmod on sensitive files",
  "severity": "Critical",
  "eql": "sequence by process.entity_id [process where process.executable == \"/usr/bin/sudo\"] [file where file.path == \"/etc/shadow\"] with maxspan=5s",
  "enabled": true
}
EOF

echo -e "${GREEN}✓ Test rules created at $TEST_RULES_DIR${NC}"
echo ""

# Run integration test using cargo
echo "Running integration tests..."
echo ""

if cargo test --workspace --test integration_e2e 2>&1 | tee /tmp/e2e-test.log; then
    echo ""
    echo -e "${GREEN}========================================"
    echo "  E2E Tests Passed!"
    echo "========================================${NC}"
    EXIT_CODE=0
else
    echo ""
    echo -e "${RED}========================================"
    echo "  E2E Tests Failed!"
    echo "========================================${NC}"
    echo ""
    echo "Check logs at: /tmp/e2e-test.log"
    EXIT_CODE=1
fi

# Cleanup
rm -rf "$TEST_RULES_DIR"

exit $EXIT_CODE
