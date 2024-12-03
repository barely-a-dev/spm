use crate::helpers::are_patches_compatible;
use spm_lib::db::{Cache, FileState, PackageState};
use spm_lib::lock::Lock;
use spm_lib::package::Package;
use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{
    error::Error,
    fs::{self, File},
    path::Path,
    process::exit,
};

pub fn handle_install_package(
    package_path: &str,
    target_dir: Option<&str>,
    cache: &mut Cache,
    skip_compat_check: bool,
) -> Result<(), Box<dyn Error>> {
    let package = Package::load_package(Path::new(package_path))?;

    let pkg_files = crate::helpers::parse_files(&package.files);

    // Check compatibility with installed packages
    if !skip_compat_check {
        for pkg in cache.pkgs() {
            let state: PackageState = pkg.1.clone();
            let ip: (Vec<String>, HashMap<String, FileState>) =
                (state.installed_files.clone(), state.patched_files.clone());

            // Check for file conflicts
            for installed_file in &ip.0 {
                if pkg_files.contains_key(&PathBuf::from(installed_file.trim())) {
                    print!(
                    "Warning: File '{}' is installed by package '{}'. \
                Do you want to install anyways without uninstalling the first, uninstall the first then install this, or do nothing (i/U/n): ",
                    installed_file, pkg.0
                );
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;

                    match response.trim().get(0..1) {
                        Some("i") => break,
                        Some("n") => exit(2),
                        _ => {
                            handle_uninstall_package(&pkg.0.clone(), &mut cache.clone())?;
                            break;
                        }
                    }
                }
            }

            // Check for patch conflicts
            for patch in &package.patches {
                let fin = env::current_dir()
                    .expect("Failed to get current dir")
                    .join(patch.filename.clone());
                let patch_path = target_dir.unwrap_or(fin.to_str().unwrap_or(""));
                if let Some(existing_state) = ip.1.get(patch_path) {
                    // If the file was previously patched, check if the patches are compatible
                    if let Some(original_content) = &existing_state.content {
                        if !are_patches_compatible(original_content, &patch) {
                            // Ask for user permission
                            print!(
                                "Warning: File '{}' was previously patched by package '{}'. \
                               Do you want to proceed? (y/N): ",
                                patch_path, pkg.0
                            );
                            io::stdout().flush()?;

                            let mut response = String::new();
                            io::stdin().read_line(&mut response)?;

                            if !response.trim().eq_ignore_ascii_case("y") {
                                return Err("Installation cancelled by user".into());
                            }
                        }
                    }
                }
            }
        }
    }

    // If all checks pass, proceed with installation
    package.install(target_dir.map(Path::new), cache)?;
    println!("Package installed successfully");
    Ok(())
}

pub fn handle_uninstall_package(
    package_name: &str,
    cache: &mut Cache,
) -> Result<(), Box<dyn Error>> {
    let _lock = Lock::new("cache")?;
    let _bin_lock = Lock::new("bin")?;

    if let Some(state) = cache.get_package(package_name) {
        println!("Uninstalling package {}...", package_name);

        // Restore emptied files
        for (path, state) in &state.emptied_files {
            if let Some(content) = &state.content {
                if let Some(perms) = state.permissions {
                    let mut file = File::create(path)?;
                    file.write_all(content)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(perms))?;
                    println!("Restored emptied file: {}", path);
                }
            }
        }

        // Restore patched files
        for (path, state) in &state.patched_files {
            if let Some(content) = &state.content {
                if let Some(perms) = state.permissions {
                    let mut file = File::create(path)?;
                    file.write_all(content)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(perms))?;
                    println!("Restored patched file: {}", path);
                }
            }
        }

        // Restore removed files
        for (path, state) in &state.removed_files {
            if let Some(content) = &state.content {
                if let Some(perms) = state.permissions {
                    let mut file = File::create(path)?;
                    file.write_all(content)?;
                    fs::set_permissions(path, fs::Permissions::from_mode(perms))?;
                    println!("Restored removed file: {}", path);
                }
            }
        }

        // Remove installed files
        for file in &state.installed_files {
            if let Err(e) = fs::remove_file(file) {
                eprintln!("Warning: Failed to remove {}: {}", file, e);
            } else {
                println!("Removed installed file: {}", file);
            }
        }

        // Remove package from cache
        cache.remove(package_name);
        cache.save()?;

        println!("Package {} uninstalled successfully", package_name);
        Ok(())
    } else {
        Err(format!("Package {} is not installed", package_name).into())
    }
}
