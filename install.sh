#!/bin/bash

# SPM Installation Script
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download the repo
echo "Downloading SPM..."
git clone https://github.com/barely-a-dev/spm.git
cd spm

# Enable network features by default
echo "net_enabled=true" > ~/.spm.conf

# Create necessary directories
mkdir -p /var/cache/spm

# Create database and cache file
touch ~/.spm.db
touch /var/cache/spm/spm.cache

echo "Installing SPM..."
# Build and install the package
cargo build --release
cp target/release/spm /usr/bin/
chmod +x /usr/bin/spm

# Clean up
cd - > /dev/null
rm -rf "$TMP_DIR"

echo "SPM installed successfully!"
echo "Run 'spm --help' for usage information"
