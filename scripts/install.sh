#!/bin/bash
# Kestrel Installation Script
# Installs Kestrel binaries and sets up the system

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Use: sudo $0"
    exit 1
fi

echo "========================================"
echo "  Kestrel Installation Script"
echo "========================================"
echo ""

# Parse arguments
SKIP_BUILD=false
SKIP_SERVICE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-service)
            SKIP_SERVICE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build    Skip building (assume binaries exist)"
            echo "  --skip-service  Skip systemd service setup"
            echo "  --help          Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

# Build if needed
if [ "$SKIP_BUILD" = false ]; then
    echo "Building Kestrel..."
    bash "$(dirname "$0")/build.sh"
    echo ""
fi

# Check if binaries exist
if [ ! -f "target/release/kestrel" ]; then
    echo -e "${RED}Error: kestrel binary not found${NC}"
    echo "Run without --skip-build to build first"
    exit 1
fi

# Install binaries
echo "Installing binaries..."
cp target/release/kestrel /usr/local/bin/
cp target/release/kestrel-benchmark /usr/local/bin/
chmod +x /usr/local/bin/kestrel
chmod +x /usr/local/bin/kestrel-benchmark
echo -e "${GREEN}✓ Binaries installed to /usr/local/bin/${NC}"

# Create directories
echo ""
echo "Creating directories..."
mkdir -p /opt/kestrel/rules
mkdir -p /opt/kestrel/bpf
mkdir -p /var/log/kestrel
mkdir -p /var/lib/kestrel
mkdir -p /etc/kestrel
echo -e "${GREEN}✓ Directories created${NC}"

# Copy example rules if exist
if [ -d "rules" ] && [ "$(ls -A rules)" ]; then
    echo ""
    echo "Copying example rules..."
    cp -r rules/* /opt/kestrel/rules/
    echo -e "${GREEN}✓ Rules copied to /opt/kestrel/rules/${NC}"
fi

# Create config file
if [ ! -f /etc/kestrel/config.toml ]; then
    echo ""
    echo "Creating configuration file..."
    cat > /etc/kestrel/config.toml << 'EOF'
# Kestrel Configuration File

[general]
log_level = "info"
mode = "detect"  # detect, enforce, offline
workers = 4
max_memory_mb = 2048

[engine]
event_bus_partitions = 4
channel_size = 10000
batch_size = 100

[ebpf]
enabled = true
program_path = "/opt/kestrel/bpf"
ringbuf_size = 4096

[wasm]
enabled = true
memory_limit_mb = 16
fuel_limit = 1000000
instance_pool_size = 10

[lua]
enabled = true
jit_enabled = true
memory_limit_mb = 16

[alerts]
output = ["stdout", "file"]
file_path = "/var/log/kestrel/alerts.json"
file_rotation = "daily"
retention_days = 30

[performance]
enable_profiling = false
metrics_enabled = true
metrics_port = 9090
EOF
    echo -e "${GREEN}✓ Configuration created at /etc/kestrel/config.toml${NC}"
else
    echo ""
    echo -e "${YELLOW}Configuration file already exists, skipping${NC}"
fi

# Set up systemd service
if [ "$SKIP_SERVICE" = false ]; then
    echo ""
    echo "Setting up systemd service..."

    cat > /etc/systemd/system/kestrel.service << 'EOF'
[Unit]
Description=Kestrel Detection Engine
After=network.target
Documentation=https://github.com/kestrel-detection/kestrel

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/kestrel
ExecStart=/usr/local/bin/kestrel run --rules /opt/kestrel/rules --config /etc/kestrel/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/kestrel /var/lib/kestrel

# Resource limits
LimitNOFILE=65536
MemoryLimit=2G
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kestrel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service installed${NC}"
    echo ""
    echo "To enable and start Kestrel:"
    echo "  sudo systemctl enable kestrel"
    echo "  sudo systemctl start kestrel"
    echo "  sudo systemctl status kestrel"
else
    echo ""
    echo "Skipping systemd service setup"
fi

echo ""
echo -e "${GREEN}========================================"
echo "  Installation Complete!"
echo "========================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Review configuration: /etc/kestrel/config.toml"
echo "  2. Add rules to: /opt/kestrel/rules/"
echo "  3. Start the service:"
echo "     sudo systemctl start kestrel"
echo "  4. View logs:"
echo "     sudo journalctl -u kestrel -f"
echo ""
echo "For more information, see docs/deployment.md"
