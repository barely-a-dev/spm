# SPM - Simple Package Manager

A modern, simple package manager written in Rust that handles binary packages and patches with a focus on convenience.

## Key Features

- 🔒 **Secure Package Management**
  - Root privilege protection
  - Package integrity verification
  - Secure file permission handling
  - GitHub-based authentication for publishing

- 📦 **Advanced Package Handling**
  - Binary package compression with zstd
  - Incremental binary patching
  - Multi-file package support
  - Custom installation directories
  - File removal and emptying support

- 🛠️ **Developer Tools**
  - Automatic project type detection (Rust, Node.js, CMake, Meson, Autotools)
  - Automated build and publish workflow
  - Version tracking and management
  - Pull request-based publishing for contributors

- 🔄 **Package Distribution**
  - GitHub-based package repository
  - Automatic updates and version tracking
  - Delta updates through binary patches
  - Package caching and state management

## Installation

### From Source
```bash
git clone https://github.com/barely-a-dev/spm_repo
cd spm
cargo build --release
sudo mv target/release/spm /usr/bin/
```

### Initial Setup
```bash
# Enable network features
spm --config net_enabled true

# Configure GitHub token (optional, for publishing)
spm --config github_token YOUR_TOKEN
```

## Usage Examples

### Package Management
```bash
# Install a package
sudo spm -I package_name

# Search packages
spm -s query

# List installed packages
spm -l

# Update package database
sudo spm -u

# Check for updates
sudo spm -U

# Uninstall a package
sudo spm -R package_name
```

### Package Creation
```bash
# Package a directory
spm -P source_dir output.spm

# Package a single file
spm -f input_file output.spm

# Auto-detect and package a project
spm --dev-pub path/to/project
```

### Patch Management
```bash
# Create a binary patch
spm -c old_file new_file patch.rpat

# Apply a patch
sudo spm -p /target/dir patch.rpat

# Verify a patch
spm -v patch.rpat
```

## Configuration

SPM uses the following configuration files:
- `~/.spm.conf` - Main configuration
- `~/.spm.db` - Package database
- `~/.spm.cache` - Installation cache

### Package Configuration
Create `pkg.toml` in your package directory:
```toml
name = "package_name"
version = "1.0.0"
file_permissions = { "binary" = "755" }
install_dirs = { "binary" = "/usr/bin" }
files_to_remove = ["/etc/old.conf"]
files_to_empty = ["/var/log/service.log"]
```

## Security Notes

- Package operations requiring system modifications need root privileges
- GitHub tokens are stored in plaintext - use tokens with minimal necessary permissions
- All packages are verified before installation
- File permissions are preserved and enforced during installation

## License

[LICENSE](LICENSE)
