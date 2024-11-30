/* Package binary format:
1. Magic number "SPKG" (4 bytes)
2. Format version (1 byte)
3. Package name length (2 bytes, little endian)
4. Package name (UTF-8 bytes)
5. Package version length (2 bytes, little endian)
6. Package version (UTF-8 bytes)
7. Compressed data block containing:
    a. Requires root flag (1 byte)
    b. Number of files (4 bytes, little endian)
    c. For each file:
        - Path length (2 bytes, little endian)
        - Path (UTF-8 bytes)
        - Permissions (4 bytes, little endian)
        - Content length (4 bytes, little endian)
        - Content (bytes)
        - Target directory flag (1 byte)
        - If target directory flag is 1:
            - Target path length (2 bytes, little endian)
            - Target path (UTF-8 bytes)
    d. Number of patches (4 bytes, little endian)
    e. For each patch:
        - Patch length (4 bytes, little endian)
        - Patch data containing:
            - Magic number "RPAT" (4 bytes)
            - Version (1 byte)
            - Filename length (2 bytes, little endian)
            - Filename (UTF-8 bytes)
            - Number of sections (4 bytes, little endian)
            - For each section:
                - Relative offset (varint)
                - Length (varint)
                - Contents (bytes)
    f. Number of files to remove (4 bytes, little endian)
    g. For each file to remove:
        - Path length (2 bytes, little endian)
        - Path (UTF-8 bytes)
    h. Number of files to empty (4 bytes, little endian)
    i. For each file to empty:
        - Path length (2 bytes, little endian)
        - Path (UTF-8 bytes)
*/

use crate::db::FileState;
use crate::db::PackageState;
use crate::helpers::{get_real_user, is_root, read_varint, write_varint};
use crate::patch::Patch;
use crate::db::Cache;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::chown;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zstd::{decode_all, encode_all};

const MAGIC: &[u8] = b"SPKG";
const VERSION: u8 = 2;

//TODO: dependencies, alternate package versions aside from most recent (do before dependencies), build scripts, pre/post install scripts, downgrade packages/choose specific versions, package groups

pub struct Dependency {
    pub name: String,
    pub valid_versions: Vec<String>,
}

impl Dependency {
    pub fn add_valid_ver(&mut self, ver: String) -> anyhow::Result<()> {
        if ver.contains('-') {
            // Treat it as a range here (IE 0.2.1-0.2.9 corresponds to 0.2.1..=9)
            let mut s = ver.split('-');
            let start = s.next().expect("Failed to get start of version range");
            let end = s.next().expect("Failed to get end of version range");

            // Split version numbers into components
            let start_parts: Vec<u32> = start
                .split('.')
                .map(|n| n.parse::<u32>())
                .collect::<Result<Vec<u32>, _>>()?;

            let end_parts: Vec<u32> = end
                .split('.')
                .map(|n| n.parse::<u32>())
                .collect::<Result<Vec<u32>, _>>()?;

            // Validate that we have versions in major.minor.patch format
            if start_parts.len() != 3 || end_parts.len() != 3 {
                return Err(anyhow::anyhow!(
                    "Version numbers must be in format major.minor.patch"
                ));
            }

            // Check that only the minor or patch number differs
            if start_parts[0] != end_parts[0] {
                return Err(anyhow::anyhow!(
                    "Only minor or patch version can differ in version ranges"
                ));
            }

            let patch_range: bool = start_parts[2] != end_parts[2];
            let minor_range: bool = start_parts[1] != end_parts[1];

            if patch_range && minor_range {
                return Err(anyhow::anyhow!(
                    "Only one version number can differ in version ranges"
                ));
            } else if patch_range {
                for patch in start_parts[2]..=end_parts[2] {
                    let version = format!("{}.{}.{}", start_parts[0], start_parts[1], patch);
                    self.valid_versions.push(version);
                }
            } else if minor_range {
                for minor in start_parts[1]..=end_parts[1] {
                    let version = format!("{}.{}.{}", start_parts[0], minor, start_parts[2]);
                    self.valid_versions.push(version);
                }
            }
        } else {
            // Directly add it
            self.valid_versions.push(ver);
        }
        Ok(())
    }
}

pub struct Package {
    pub files: HashMap<PathBuf, FileEntry>,
    pub patches: Vec<Patch>,
    pub files_to_remove: Vec<PathBuf>,
    pub files_to_empty: Vec<PathBuf>,
    pub requires_root: bool,
    pub version: String,
    pub name: String,
    pub dependencies: Vec<Dependency>,
}

pub struct FileEntry {
    pub path: PathBuf,
    pub permissions: u32,
    pub contents: Vec<u8>,
    pub target_dir: Option<PathBuf>,
}

impl Package {
    pub fn new() -> Self {
        Package {
            name: String::from("unnamed"),  // Default name
            version: String::from("0.0.0"), // Default version
            files: HashMap::new(),
            patches: Vec::new(),
            files_to_remove: Vec::new(),
            files_to_empty: Vec::new(),
            requires_root: false,
            dependencies: Vec::new(),
        }
    }

    pub fn add_dependency(&mut self, name: String, vers: Vec<String>) {
        let mut dep = Dependency {
            name,
            valid_versions: Vec::new(),
        };
        for ver in vers {
            dep.add_valid_ver(ver).expect("Failed to add valid version");
        }
        self.dependencies.push(dep);
    }

    pub fn add_file(
        &mut self,
        path: PathBuf,
        permissions: u32,
        contents: Vec<u8>,
        target_dir: Option<PathBuf>,
    ) {
        self.files.insert(
            path.clone(),
            FileEntry {
                path,
                permissions,
                contents,
                target_dir,
            },
        );
    }

    pub fn add_patch(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    pub fn mark_for_removal(&mut self, path: PathBuf) {
        self.files_to_remove.push(path);
    }

    pub fn mark_for_empty(&mut self, path: PathBuf) {
        self.files_to_empty.push(path);
    }

    pub fn save_package(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let mut file = File::create(path)?;

        // Write header
        file.write_all(MAGIC)?;
        file.write_all(&[VERSION])?;

        if self.name.is_empty() || self.version.is_empty() {
            return Err("Package name and version must be specified".into());
        }

        // Write package name
        let name_bytes = self.name.as_bytes();
        file.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
        file.write_all(name_bytes)?;

        // Write package version
        let version_bytes = self.version.as_bytes();
        file.write_all(&(version_bytes.len() as u16).to_le_bytes())?;
        file.write_all(version_bytes)?;

        // TODO: dependency stuff here

        // Prepare package data
        let mut data = Vec::new();

        // Write requires_root flag
        data.push(self.requires_root as u8);

        // Write number of files
        data.extend_from_slice(&(self.files.len() as u32).to_le_bytes());

        // Write files
        for (_, entry) in &self.files {
            let lossy_ent_path = entry.path.to_string_lossy();
            let path_bytes = lossy_ent_path.as_bytes();
            data.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
            data.extend_from_slice(path_bytes);
            data.extend_from_slice(&entry.permissions.to_le_bytes());
            data.extend_from_slice(&(entry.contents.len() as u32).to_le_bytes());
            data.extend_from_slice(&entry.contents);

            // Write target directory
            if let Some(target_dir) = &entry.target_dir {
                data.push(1u8);
                let targ = target_dir.to_string_lossy();
                let path_bytes = targ.as_bytes();
                data.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
                data.extend_from_slice(path_bytes);
            } else {
                data.push(0u8);
            }
        }

        // Write number of patches
        data.extend_from_slice(&(self.patches.len() as u32).to_le_bytes());

        // Write patches
        for patch in &self.patches {
            let mut patch_data = Vec::new();
            // Write patch format
            patch_data.extend_from_slice(crate::patch::MAGIC);
            patch_data.push(crate::patch::VERSION);

            // Write filename
            let filename_bytes = patch.filename.as_bytes();
            patch_data.extend_from_slice(&(filename_bytes.len() as u16).to_le_bytes());
            patch_data.extend_from_slice(filename_bytes);

            // Write sections
            patch_data.extend_from_slice(&(patch.sections.len() as u32).to_le_bytes());
            let mut last_end = 0;

            for section in &patch.sections {
                let relative_offset = section.start - last_end;
                write_varint(&mut patch_data, relative_offset as u32)?;
                write_varint(&mut patch_data, section.contents.len() as u32)?;
                patch_data.extend_from_slice(&section.contents);
                last_end = section.end;
            }

            // Write patch size and data
            data.extend_from_slice(&(patch_data.len() as u32).to_le_bytes());
            data.extend_from_slice(&patch_data);
        }

        // Write files to remove
        data.extend_from_slice(&(self.files_to_remove.len() as u32).to_le_bytes());
        for path in &self.files_to_remove {
            let lossy_path = path.to_string_lossy();
            let path_bytes = lossy_path.as_bytes();
            data.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
            data.extend_from_slice(path_bytes);
        }

        // Write files to empty
        data.extend_from_slice(&(self.files_to_empty.len() as u32).to_le_bytes());
        for path in &self.files_to_empty {
            let lossy_path = path.to_string_lossy();
            let path_bytes = lossy_path.as_bytes();
            data.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
            data.extend_from_slice(path_bytes);
        }

        // Compress and write data
        let compressed = encode_all(&data[..], 21)?;
        file.write_all(&compressed)?;

        if unsafe { libc::geteuid() } == 0 {
            // We're running as root (via sudo)
            if let Ok((sudo_user, _)) = get_real_user() {
                // Get the passwd entry for the SUDO_USER
                let username = CString::new(sudo_user.1).unwrap();
                let passwd = unsafe { libc::getpwnam(username.as_ptr()) };
                if !passwd.is_null() {
                    unsafe {
                        let uid = (*passwd).pw_uid;
                        let gid = (*passwd).pw_gid;
                        chown(path, Some(uid), Some(gid))?;
                        let mode = 0o644; // rw-r--r--
                        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
                    }
                }
            }
        } else {
            // We're running as normal user
            if let Ok((uid, gid)) = get_real_user() {
                let mode = 0o644; // rw-r--r--
                fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
                chown(path, Some(uid.0), Some(gid))?;
            }
        }

        Ok(())
    }

    pub fn load_package(path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;

        if magic != MAGIC {
            return Err("Invalid package file format".into());
        }

        let mut version = [0u8];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err("Unsupported package version".into());
        }

        // Read package name
        let mut name_len = [0u8; 2];
        file.read_exact(&mut name_len)?;
        let name_len = u16::from_le_bytes(name_len) as usize;

        let mut name_bytes = vec![0u8; name_len];
        file.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)?;

        // Read package version
        let mut version_len = [0u8; 2];
        file.read_exact(&mut version_len)?;
        let version_len = u16::from_le_bytes(version_len) as usize;

        let mut version_bytes = vec![0u8; version_len];
        file.read_exact(&mut version_bytes)?;
        let version = String::from_utf8(version_bytes)?;

        // TODO: dependency stuff here

        let mut package = Package::new();
        package.name = name.clone();
        package.version = version.clone();

        let mut compressed = Vec::new();
        file.read_to_end(&mut compressed)?;
        let data = decode_all(&compressed[..])?;
        let mut cursor = std::io::Cursor::new(data);

        package.name = name;
        package.version = version;

        // Read requires_root flag
        let mut requires_root = [0u8];
        cursor.read_exact(&mut requires_root)?;
        package.requires_root = requires_root[0] != 0;

        // Read files
        let mut num_files = [0u8; 4];
        cursor.read_exact(&mut num_files)?;
        let num_files = u32::from_le_bytes(num_files);

        for _ in 0..num_files {
            let mut path_len = [0u8; 2];
            cursor.read_exact(&mut path_len)?;
            let path_len = u16::from_le_bytes(path_len) as usize;

            let mut path_bytes = vec![0u8; path_len];
            cursor.read_exact(&mut path_bytes)?;
            let path = PathBuf::from(String::from_utf8(path_bytes)?);

            let mut perms = [0u8; 4];
            cursor.read_exact(&mut perms)?;
            let permissions = u32::from_le_bytes(perms);

            let mut content_len = [0u8; 4];
            cursor.read_exact(&mut content_len)?;
            let content_len = u32::from_le_bytes(content_len) as usize;

            let mut contents = vec![0u8; content_len];
            cursor.read_exact(&mut contents)?;

            let mut target_dir_flag = [0u8; 1];
            cursor.read_exact(&mut target_dir_flag)?;
            let target_dir = if target_dir_flag[0] != 0 {
                let mut path_len = [0u8; 2];
                cursor.read_exact(&mut path_len)?;
                let path_len = u16::from_le_bytes(path_len) as usize;

                let mut path_bytes = vec![0u8; path_len];
                cursor.read_exact(&mut path_bytes)?;
                Some(PathBuf::from(String::from_utf8(path_bytes)?))
            } else {
                None
            };

            package.add_file(path, permissions, contents, target_dir);
        }

        // Read patches
        let mut num_patches = [0u8; 4];
        cursor.read_exact(&mut num_patches)?;
        let num_patches = u32::from_le_bytes(num_patches);

        for _ in 0..num_patches {
            let mut patch_len = [0u8; 4];
            cursor.read_exact(&mut patch_len)?;
            let patch_len = u32::from_le_bytes(patch_len) as usize;

            let mut patch_data = vec![0u8; patch_len];
            cursor.read_exact(&mut patch_data)?;

            // Read patch from memory buffer
            let mut patch_cursor = std::io::Cursor::new(patch_data);
            let mut patch_magic = [0u8; 4];
            patch_cursor.read_exact(&mut patch_magic)?;

            if patch_magic != MAGIC {
                return Err("Invalid patch format in package".into());
            }

            let mut patch_version = [0u8];
            patch_cursor.read_exact(&mut patch_version)?;
            if patch_version[0] != VERSION {
                return Err("Unsupported patch version in package".into());
            }

            let mut filename_len = [0u8; 2];
            patch_cursor.read_exact(&mut filename_len)?;
            let filename_len = u16::from_le_bytes(filename_len) as usize;

            let mut filename_bytes = vec![0u8; filename_len];
            patch_cursor.read_exact(&mut filename_bytes)?;
            let filename = String::from_utf8(filename_bytes)?;

            let mut patch = Patch::new(filename);

            let mut num_sections = [0u8; 4];
            patch_cursor.read_exact(&mut num_sections)?;
            let num_sections = u32::from_le_bytes(num_sections);

            let mut current_pos = 0;
            for _ in 0..num_sections {
                let relative_offset = read_varint(&mut patch_cursor)? as usize;
                let length = read_varint(&mut patch_cursor)? as usize;

                let start = current_pos + relative_offset;
                let mut contents = vec![0u8; length];
                patch_cursor.read_exact(&mut contents)?;

                patch.add_section(start, start + length, contents);
                current_pos = start + length;
            }

            package.add_patch(patch);
        }

        // Read files to remove
        let mut num_removes = [0u8; 4];
        cursor.read_exact(&mut num_removes)?;
        let num_removes = u32::from_le_bytes(num_removes);

        for _ in 0..num_removes {
            let mut path_len = [0u8; 2];
            cursor.read_exact(&mut path_len)?;
            let path_len = u16::from_le_bytes(path_len) as usize;

            let mut path_bytes = vec![0u8; path_len];
            cursor.read_exact(&mut path_bytes)?;
            let path = PathBuf::from(String::from_utf8(path_bytes)?);

            package.mark_for_removal(path);
        }

        // Read files to empty
        let mut num_empties = [0u8; 4];
        cursor.read_exact(&mut num_empties)?;
        let num_empties = u32::from_le_bytes(num_empties);

        for _ in 0..num_empties {
            let mut path_len = [0u8; 2];
            cursor.read_exact(&mut path_len)?;
            let path_len = u16::from_le_bytes(path_len) as usize;

            let mut path_bytes = vec![0u8; path_len];
            cursor.read_exact(&mut path_bytes)?;
            let path = PathBuf::from(String::from_utf8(path_bytes)?);

            package.mark_for_empty(path);
        }

        Ok(package)
    }

    pub fn install(
        &self,
        target_dir: Option<&Path>,
        cache: &mut Cache,
    ) -> Result<(), Box<dyn Error>> {
        // Check if root is required and we're not root
        if self.requires_root && !is_root() {
            return Err("This package requires root privileges to install".into());
        }

        // Double check if package is already installed
        if cache.has_package(&self.name) {
            return Err(format!("Package {} is already installed", self.name).into());
        }

        // Create package state for tracking changes
        let mut package_state = PackageState {
            installed_files: Vec::new(),
            removed_files: HashMap::new(),
            emptied_files: HashMap::new(),
            patched_files: HashMap::new(),
            version: self.version.clone(),
        };

        // Create a rollback closure for handling errors
        let mut rollback_actions: Vec<Box<dyn FnOnce() -> Result<(), Box<dyn Error>>>> = Vec::new();

        // Remove files marked for removal
        for path in &self.files_to_remove {
            let full_path = if let Some(target) = target_dir {
                target.join(path)
            } else {
                PathBuf::from(path)
            };

            if full_path.exists() {
                let contents = fs::read(&full_path)?;
                let metadata = fs::metadata(&full_path)?;
                let permissions = metadata.permissions().mode();

                package_state.removed_files.insert(
                    full_path.to_string_lossy().into_owned(),
                    FileState {
                        content: Some(contents.clone()),
                        permissions: Some(permissions),
                    },
                );

                let path_clone = full_path.clone();
                let contents_clone = contents.clone();
                rollback_actions.push(Box::new(move || {
                    let mut file = File::create(&path_clone)?;
                    file.write_all(&contents_clone)?;
                    fs::set_permissions(&path_clone, fs::Permissions::from_mode(permissions))?;
                    Ok(())
                }));

                fs::remove_file(full_path)?;
            }
        }

        // Empty files marked for emptying
        for path in &self.files_to_empty {
            let full_path = if let Some(target) = target_dir {
                target.join(path)
            } else {
                PathBuf::from(path)
            };

            if full_path.exists() {
                let contents = fs::read(&full_path)?;
                let metadata = fs::metadata(&full_path)?;
                let permissions = metadata.permissions().mode();

                package_state.emptied_files.insert(
                    full_path.to_string_lossy().into_owned(),
                    FileState {
                        content: Some(contents.clone()),
                        permissions: Some(permissions),
                    },
                );

                let path_clone = full_path.clone();
                let contents_clone = contents.clone();
                rollback_actions.push(Box::new(move || {
                    let mut file = File::create(&path_clone)?;
                    file.write_all(&contents_clone)?;
                    fs::set_permissions(&path_clone, fs::Permissions::from_mode(permissions))?;
                    Ok(())
                }));

                File::create(full_path)?;
            }
        }

        // Install new files
        for (_, entry) in &self.files {
            let final_target = if let Some(custom_dir) = &entry.target_dir {
                custom_dir.clone()
            } else if entry.permissions & 0o111 != 0 {
                PathBuf::from("/usr/bin")
            } else if let Some(target) = target_dir {
                target.to_path_buf()
            } else {
                PathBuf::from("/usr/local")
            };
            let target_path = final_target.join(&entry.path);
            if let Some(parent) = target_path.parent() {
                match fs::create_dir_all(parent) {
                    Ok(_) => {},
                    Err(e) => println!("{}", e),
                }
            }

            package_state
                .installed_files
                .push(target_path.to_string_lossy().into_owned());
            let path_clone = target_path.clone();
            rollback_actions.push(Box::new(move || {
                if path_clone.exists() {
                    fs::remove_file(path_clone)?;
                }
                Ok(())
            }));
            
            let mut file = File::create(&target_path)?;
            file.write_all(&entry.contents)?;
            fs::set_permissions(&target_path, fs::Permissions::from_mode(entry.permissions))?;
        }

        // Apply patches
        for patch in &self.patches {
            let target_path = if let Some(target) = target_dir {
                target.join(&patch.filename)
            } else {
                PathBuf::from(&patch.filename)
            };

            if target_path.exists() {
                let contents = fs::read(&target_path)?;
                let metadata = fs::metadata(&target_path)?;
                let permissions = metadata.permissions().mode();

                package_state.patched_files.insert(
                    patch.filename.clone(),
                    FileState {
                        content: Some(contents.clone()),
                        permissions: Some(permissions),
                    },
                );

                let path_clone = target_path.clone();
                let contents_clone = contents.clone();
                rollback_actions.push(Box::new(move || {
                    let mut file = File::create(&path_clone)?;
                    file.write_all(&contents_clone)?;
                    fs::set_permissions(&path_clone, fs::Permissions::from_mode(permissions))?;
                    Ok(())
                }));
            }

            if let Some(target) = target_dir {
                patch.apply(target.to_str().unwrap())?;
            } else {
                patch.apply("/")?;
            }
        }

        // If we got here, installation was successful
        cache.add(self.name.clone(), package_state);
        if let Err(e) = cache.save() {
            // If we can't save the cache, roll back all changes
            for action in rollback_actions.into_iter().rev() {
                if let Err(e) = action() {
                    eprintln!("Error during rollback: {}", e);
                }
            }
            return Err(format!("Failed to save cache: {}", e).into());
        }

        Ok(())
    }
}
