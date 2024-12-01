#!/bin/bash

# SPM Installation Script with Debugging
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create a menu for selecting components
echo "Which components would you like to install?"
echo "1. spm (main package manager)"
echo "2. spmc (conversion utility)"
echo "3. spmd (developer tools)"
echo "4. All"
read -p "Enter the numbers (comma-separated, e.g., 1,2): " choices

# Parse the user's selection into an array
IFS=',' read -r -a selected <<< "$choices"

# Map components to subdirectories
declare -A components=(
    [1]="spm"
    [2]="spmc"
    [3]="spmd"
)

# Decide whether to download all
if [[ " ${selected[@]} " =~ "4" ]]; then
    selected=(1 2 3)
fi

# Create temporary directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone the entire repository
echo "Cloning the repository..."
git clone https://github.com/barely-a-dev/spm.git
cd spm

# Enable network features by default
echo "net_enabled=true" > ~/.spm.conf

# Create necessary directories
mkdir -p /var/cache/spm

# Create database and cache file
touch ~/.spm.db
touch /var/cache/spm/spm.cache

# Build and install selected components
for choice in "${selected[@]}"; do
    if [[ -n "${components[$choice]}" ]]; then
        component="${components[$choice]}"
        echo "Building and installing $component..."
        if [ -d "$component" ]; then
            cd "$component"
            cargo build --release || { echo "Failed to build $component"; continue; }
            cd ..
            cp target/release/"$component" /usr/bin/ || { echo "Failed to copy $component"; continue; }
            chmod +x /usr/bin/"$component"
            echo "Successfully installed $component!"
        else
            echo "$component directory not found"
            exit 1
        fi
    fi
done

# Clean up
cd - > /dev/null
rm -rf "$TMP_DIR"

echo "Installation complete!"
if [[ " ${selected[@]} " =~ "1" ]]; then
    echo "Run 'spm --help' for usage information"
fi
if [[ " ${selected[@]} " =~ "2" ]]; then
    echo "Use the \"spmc <file>\" command to convert other package files into spm packages"
fi
if [[ " ${selected[@]} " =~ "3" ]]; then
    echo "Use the \"spmd\" command for developer operations"
fi
