# SPM Technical Documentation

## Overview

SPM (Simple Package Manager) is a package management system implementing:
- Custom binary package format (SPKG)
- Binary patch format (RPAT)
- Secure installation management
- GitHub-based package distribution

## Package Format Specification

### SPKG Format
```
1. Magic number "SPKG" (4 bytes)
2. Format version (1 byte)
3. Package name length (2 bytes, little endian)
4. Package name (UTF-8 bytes)
5. Package version length (2 bytes, little endian)
6. Package version (UTF-8 bytes)
7. Root requirement flag (1 byte)
8. Number of files (4 bytes, little endian)
9. File entries:
   - Path length (2 bytes, little endian)
   - Path (UTF-8 bytes)
   - Permissions (4 bytes, little endian)
   - Content length (4 bytes, little endian)
   - Content bytes
10. Number of patches (4 bytes, little endian)
11. Patch entries
12. Files to remove
13. Files to empty
```

### RPAT Format
```
1. Magic number "RPAT" (4 bytes)
2. Format version (1 byte)
3. Filename length (2 bytes, little endian)
4. Filename (UTF-8 bytes)
5. Number of sections (4 bytes, little endian)
6. Compressed sections:
   - Relative offset (varint)
   - Length (varint)
   - Content bytes
```

## Security Architecture

### Permission Management
- Root privilege verification for system operations
- File permission preservation
- Secure ownership handling
- Installation directory validation

### Package Verification
- Magic number validation
- Content integrity verification
- Permission constraint validation

### GitHub Integration
- Token-based authentication
- Permission-level-based operations
- Pull request workflow for contributors
- Secure version tracking

## Package Creation Guide

### Directory-Based Packages

1. Create package structure:
```
mypackage/
├── pkg.toml
├── bin/
│   └── executable
└── etc/
    └── config.conf
```

2. Configure pkg.toml:
```toml
name = "mypackage"
version = "1.0.0"
file_permissions = {
    "bin/executable" = "755",
    "etc/config.conf" = "644"
}
install_dirs = {
    "bin/executable" = "/usr/bin",
    "etc/config.conf" = "/etc"
}
files_to_remove = ["/etc/old.conf"]
files_to_empty = ["/var/log/old.log"]
```

3. Build package:
```bash
spm -P mypackage output.spm
```

### Auto-Build Projects

SPM supports automatic detection and building of:
- Rust (Cargo.toml)
- Node.js (package.json)
- CMakeists.txt)
- Meson (meson.build)
- Autotools (configure.ac)
- Make (Makefile)

Usage:
```bash
spm --dev-pub project_directory
```

## API Documentation

### Package Operations

#### Package Creation
```rust
pub fn new() -> Package;
pub fn add_file(&mut self, path: PathBuf, permissions: u32, contents: Vec<u8>, target_dir: Option<PathBuf>);
pub fn add_patch(&mut self, patch: Patch);
pub fn mark_for_removal(&mut self, path: PathBuf);
pub fn mark_for_empty(&mut self, path: PathBuf);
```

#### Package Installation
```rust
pub fn install(&self, target_dir: Option<&Path>, cache: &mut Cache) -> Result<(), Box<dyn Error>>;
```

#### Patch Operations
```rust
pub fn create_patch_from_files(old_file: &Path, new_file: &Path) -> Result<Patch, Box<dyn Error>>;
pub fn apply(&self, dir_of_file: &str) -> Result<(), Box<dyn Error>>;
```

## Command Reference

| Command | Description | Privileges | Example |
|---------|-------------|------------|---------|
| -I, --install | Install package | Root** | `sudo spm -I package` |
| -u, --update-db | Update database | Root | `sudo spm -u` |
| -s, --search | Search packages | None | `spm -s query` |
| -l, --list | List installed | None | `spm -l` |
| -P, --package-dir | Package directory | None | `spm -P src out.spm` |
| -f, --package-file | Package file | None | `spm -f input out.spm` |
| -b, --publish | Publish package | None* | `spm -b pkg.spm` |
| -p, --install-patch | Install patch | Root | `sudo spm -p /target patch.rpat` |
| -q, --dev-pub | Auto-build & publish | Root* | `sudo spm -q` |
| -C, --config | Configure the program | Root | `sudo spm -C net_enabled true` |
| -F, --fetch | Fetch package from repo and store in output | None | `sudo spm -F package output` |

*Requires GitHub token configuration
**Requires GitHub token configuration if not using on a local file

## Cache System

SPM maintains a cache at `~/.spm.cache` tracking installed packages

This enables clean uninstallation and system state tracking.

## Best Practices

1. **Package Creation**
   - Include clear version numbers using [semantic versioning](https://semver.org)
   - Set appropriate file permissions
   - Test packages locally before publishing

2. **Installation**
   - Regular database updates
   - Review package contents before installation

3. **Security**
   - Use minimal-privilege tokens
   - Regular system updates
   - Backup important files before updates

## Configuration Reference

### Global Settings
```toml
# ~/.spm.conf
net_enabled = true
github_token = "your_token" # This will be automatically removed, encrypted, and stored elsewhere.
source_repo = "https://github.com/user/repo"
```

### Package Settings
```toml
# pkg.toml
name = "package"
version = "1.0.0"
file_permissions = { ... }
install_dirs = { ... }
files_to_remove = [ ... ]
files_to_empty = [ ... ]
```

## Troubleshooting

Common issues and solutions:

1. **Installation Failures**
   - Check root privileges
   - Verify package integrity
   - Check disk space
   - Review package dependencies

2. **Publishing Issues**
   - Verify GitHub token
   - Check repository permissions
   - Validate package format

3. **Update Problems**
   - Check network connectivity
   - Update package database
   - Verify cache integrity

## Future Development

Planned features by priority:
- Top priority: 
  - Bug fixes
- Medium priority:
  - Improved cache system allowing for more complete uninstallations
  - More descriptive and helpful error messages
- Low priority:
  - Dependency management
  - Package verification improvements
  - Package signing
