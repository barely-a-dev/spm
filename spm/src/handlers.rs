
use spm_lib::db::Cache;
use spm_lib::lock::Lock;
use spm_lib::package::Package;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::{
    error::Error,
    fs::{self, File},
    path::Path,
};

pub fn handle_install_package(
    package_path: &str,
    target_dir: Option<&str>,
    cache: &mut Cache,
) -> Result<(), Box<dyn Error>> {
    let package = Package::load_package(Path::new(package_path))?;
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
