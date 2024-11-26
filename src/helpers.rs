use crate::db::Cache;
use crate::db::Database;
use crate::handlers::*;
use crate::lock::Lock;
use crate::patch::Patch;
use crate::Config;
use std::env;
use std::io::Read;
use std::io::Write;
use std::time::Duration;
use std::{
    error::Error,
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
};

// Helper functions for varint encoding/decoding
pub fn write_varint<W: Write>(writer: &mut W, mut value: u32) -> Result<(), Box<dyn Error>> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }

    Ok(())
}

pub fn read_varint<R: Read>(reader: &mut R) -> Result<u32, Box<dyn Error>> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8];
        reader.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7F) as u32) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

pub fn get_real_user() -> Result<((u32, String), u32), Box<dyn Error>> {
    unsafe {
        let uid = libc::getuid();
        let user = env::var("SUDO_USER").unwrap_or("user".to_string());
        let gid = libc::getgid();
        Ok(((uid, user), gid))
    }
}

pub fn parse_name_and_version(filename: &str) -> (String, Option<String>) {
    let patterns = ["-v", "_v", "v"];

    for pattern in patterns {
        if let Some(idx) = filename.to_lowercase().find(pattern) {
            let name = filename[..idx].to_string();
            let version_part = &filename[idx + pattern.len()..];

            // Find where the version number ends
            if let Some(end_idx) = version_part.find(|c: char| !c.is_numeric() && c != '.') {
                let version = &version_part[..end_idx];
                if !version.is_empty() {
                    return (name, Some(version.to_string()));
                }
            } else if version_part.chars().all(|c| c.is_numeric() || c == '.') {
                return (name, Some(version_part.to_string()));
            }
        }
    }

    (filename.to_string(), None)
}

pub fn remove_ver(filename: &str) -> String {
    return parse_name_and_version(filename).0;
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn require_root(operation: &str) {
    if !is_root() {
        eprintln!(
            "Root privileges required for {}. Please run with sudo.",
            operation
        );
        process::exit(1);
    }
}

pub fn get_matches(
    matches: clap::ArgMatches,
    config: &mut Config,
    database: &mut Database,
    cache: &mut Cache,
) {
    if matches.contains_id("dev-pub") {
        require_root("publishing from source");
        let dir = matches
            .get_one::<String>("dev-pub")
            .map(|s| PathBuf::from(s))
            .unwrap_or(env::current_dir().expect("Failed to get current directory"));
        if let Err(e) = handle_dev_pub(dir, config, &database) {
            eprintln!("Failed to publish: {}", e);
            process::exit(1);
        }
    } else if let Some(mut files) = matches.get_many::<String>("install-patch") {
        require_root("installing patches");
        let dir = files.next().expect("Directory argument required");
        let patch_file = files.next().expect("Patch file argument required");

        let patch = match Patch::load_patch(Path::new(patch_file)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to load patch: {}", e);
                process::exit(1);
            }
        };

        if let Err(e) = patch.apply(dir) {
            eprintln!("Failed to apply patch: {}", e);
            process::exit(1);
        }
        println!("Patch applied successfully");
    } else if let Some(mut files) = matches.get_many::<String>("create-patch") {
        let old_file = files.next().expect("Old file argument required");
        let new_file = files.next().expect("New file argument required");
        let output_patch = files.next().expect("Output patch file argument required");

        println!("Creating patch from {} to {}", old_file, new_file);
        match Patch::create_patch_from_files(Path::new(old_file), Path::new(new_file)) {
            Ok(patch) => match patch.save_patch(Path::new(output_patch)) {
                Ok(_) => println!("Patch created successfully: {}", output_patch),
                Err(e) => {
                    eprintln!("Failed to save patch: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Failed to create patch: {}", e);
                process::exit(1);
            }
        }
    } else if let Some(patch_file) = matches.get_one::<String>("verify-patch") {
        match Patch::load_patch(Path::new(patch_file)) {
            Ok(patch) => {
                println!("Patch file is valid:");
                println!("Target file: {}", patch.filename);
                println!("Number of sections: {}", patch.sections.len());
                for (i, section) in patch.sections.iter().enumerate() {
                    println!(
                        "Section {}: bytes {}-{} ({} bytes)",
                        i + 1,
                        section.start,
                        section.end,
                        section.contents.len()
                    );
                }
            }
            Err(e) => {
                eprintln!("Invalid patch file: {}", e);
                process::exit(1);
            }
        }
    } else if let Some(mut args) = matches.get_many::<String>("package-dir") {
        let dir = args.next().expect("Package directory argument required");
        let output = args.next().expect("Output file argument required");
        let allow_large = matches.get_flag("allow-large");

        if let Err(e) = handle_package_dir(dir, output, allow_large) {
            eprintln!("Failed to create package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("package-file") {
        let input_file = args.next().expect("Input file argument required");
        let output_file = args.next().expect("Output file argument required");
        let allow_large = matches.get_flag("allow-large");

        if let Err(e) = handle_package_file(input_file, output_file, allow_large, false) {
            eprintln!("Failed to package file: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("verify-package") {
        let package_path = args.next().expect("Package file argument required");

        if let Err(e) = handle_verify_package(package_path) {
            eprintln!("Failed to verify package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("install-package") {
        require_root("installing packages");
        let _lock = Lock::new("db");
        let _cache_lock = Lock::new("cache");
        let _bin_lock = Lock::new("bin");
        let package_path = args.next().expect("Package file argument required");
        let target_dir = args.next().map(|s| s.as_str()); // Convert to Option<&str>

        if let Err(e) = handle_install_package(package_path, target_dir, cache) {
            eprintln!("Failed to install package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("config") {
        require_root("updating config");
        let key = args.next().expect("Key argument required");
        let value = args.next().expect("Value argument required");

        match key.as_str() {
            "net_enabled" | "source_repo" | "github_token" => {
                if let Err(e) = config.set(key, value.to_string()) {
                    eprintln!("Failed to set config: {}", e);
                    process::exit(1);
                }
                println!("Configuration updated successfully");
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown configuration key: {}", key);
                process::exit(1);
            }
        }
    } else if matches.contains_id("search") {
        require_root("searching");
        let query = matches.get_one::<String>("search");
        match query {
            Some(q) => {
                // First try exact match
                if let Some(package) = database.exact_search(q.to_string()) {
                    println!("Found exact match: {}", package);
                } else {
                    // Try similar matches
                    match database.search(q.to_string()) {
                        Some(matches) => {
                            println!("Found similar packages:");
                            for package in matches {
                                println!("  {}", package);
                            }
                        }
                        None => println!("No matching packages found"),
                    }
                }
            }
            None => {
                // List all packages
                match database.list_all() {
                    Some(packages) => {
                        println!("Available packages:");
                        for package in packages {
                            println!("  {}", package);
                        }
                    }
                    None => println!("No packages found in database"),
                }
            }
        }
    } else if matches.contains_id("install") {
        require_root("installing packages");
        let _lock = Lock::new("db").expect("Failed to lock");
        let _cache_lock = Lock::new("cache").expect("Failed to lock");
        let _bin_lock = Lock::new("bin").expect("Failed to lock");

        if let Some(packages) = matches.get_many::<String>("install") {
            let client = reqwest::blocking::Client::new();
            let mut success_count = 0;
            let total_packages = packages.len();

            for package in packages {
                if package.starts_with("./") || package.ends_with(".spm") {
                    // Local package installation
                    match handle_install_package(package, None, cache) {
                        Ok(_) => {
                            println!("Successfully installed local package: {}", package);
                            success_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to install local package {}: {}", package, e);
                        }
                    }
                } else {
                    // Remote package installation
                    if !config
                        .get("net_enabled")
                        .unwrap_or("".to_string())
                        .parse::<bool>()
                        .unwrap_or(false)
                    {
                        eprintln!(
                            "Package installation from database requires net_enabled=true in configuration"
                        );
                        process::exit(1);
                    }

                    match download_and_install_package(package, database, cache, &client) {
                        Ok(_) => {
                            success_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to install package {}: {}", package, e);
                        }
                    }
                }
            }

            println!(
                "\nInstallation complete: {}/{} packages installed successfully",
                success_count, total_packages
            );
            if success_count != total_packages {
                process::exit(1);
            }
        }
    } else if matches.contains_id("update") {
        require_root("installing updates");
        let _lock = Lock::new("db").expect("Failed to lock");
        let _cache_lock = Lock::new("cache").expect("Failed to lock");
        let _bin_lock = Lock::new("bin").expect("Failed to lock");

        // Verify network is enabled
        if !config
            .get("net_enabled")
            .unwrap_or("".to_string())
            .parse::<bool>()
            .unwrap_or(false)
        {
            eprintln!("Updates require net_enabled=true in configuration");
            process::exit(1);
        }

        println!("Checking for updates...");
        let updates = database.check_updates(cache);
        if updates.is_empty() {
            println!("All packages are up to date!");
            return;
        }

        let client = reqwest::blocking::Client::new();

        // Change this section to check if there are any values provided
        if let Some(packages) = matches.get_many::<String>("update").filter(|p| p.len() > 0) {
            // Update specific packages
            let packages: Vec<String> = packages.map(|s| s.to_string()).collect();
            println!("pg: {:#?}", packages);
            let mut updated = false;

            for (name, current, latest) in &updates {
                println!("{:#?}", updates);
                let package_name = name.trim_end_matches(".spm");
                if packages.contains(&package_name.to_string()) {
                    println!("Updating {}: {} -> {}", package_name, current, latest);

                    match download_and_install_package(name, database, cache, &client) {
                        Ok(_) => {
                            println!("Successfully updated {}", package_name);
                            updated = true;
                        }
                        Err(e) => {
                            eprintln!("Failed to update {}: {}", package_name, e);
                        }
                    }
                }
            }

            if !updated {
                println!("No updates available for specified packages");
            }
        } else {
            // Update all packages
            println!("Updates available:");
            for (name, current, latest) in &updates {
                println!(
                    "{}: {} -> {}",
                    name.trim_end_matches(".spm"),
                    current,
                    latest
                );
            }

            println!("\nInstalling updates...");
            let mut success_count = 0;
            let total_updates = updates.len();

            for (name, _, _) in updates {
                match download_and_install_package(&name, database, cache, &client) {
                    Ok(_) => {
                        success_count += 1;
                    }
                    Err(e) => {
                        eprintln!("Failed to update {}: {}", name.trim_end_matches(".spm"), e);
                    }
                }
            }

            println!(
                "\nUpdate complete: {}/{} packages updated successfully",
                success_count, total_updates
            );
            if success_count != total_updates {
                process::exit(1);
            }
        }
    } else if matches.get_flag("update-db") {
        require_root("updating the database");
        if !config
            .get("net_enabled")
            .unwrap_or("".to_string())
            .parse::<bool>()
            .unwrap_or(false)
        {
            eprintln!("Database update requires net_enabled=true in configuration");
            process::exit(1);
        }
        println!("Updating package database...");
        database.update_db().expect("Failed to update database.");
        println!("Database updated successfully");
        process::exit(0);
    } else if let Some(package_file) = matches.get_one::<String>("publish") {
        if let Err(e) = handle_publish_package(package_file, &database, config) {
            eprintln!("Failed to publish package: {}", e);
            process::exit(1);
        }
    } else if let Some(package_file) = matches.get_one::<String>("unpublish") {
        if let Err(e) = handle_remove_package(package_file, &database, config) {
            eprintln!("Failed to remove package: {}", e);
            process::exit(1);
        }
    } else if let Some(package) = matches.get_one::<String>("uninstall") {
        require_root("uninstalling packages");
        if let Err(e) = handle_uninstall_package(package, cache) {
            eprintln!("Failed to uninstall package: {}", e);
            process::exit(1);
        }
    } else if matches.contains_id("do-nothing") {
        let def = &"5000".to_string();
        let len = matches.get_one::<String>("do-nothing").unwrap_or(def);
        std::thread::sleep(Duration::from_millis(len.parse::<u64>().unwrap_or(5000)));
    } else if matches.contains_id("lock-test") {
        let _lock = Lock::new("db").expect("Failed to lock");
    } else if matches.contains_id("list") {
        match matches.get_one::<String>("list") {
            Some(package) => {
                // List files for specific package
                if let Some((files, _)) = cache.get_installed_files(package.to_string()) {
                    println!("Files installed by package {}:", package);
                    for file in files {
                        // Now we iterate over the Vec<String> inside the Some()
                        println!("  {}", file);
                    }
                } else {
                    eprintln!("Package {} is not installed", package);
                    process::exit(1);
                }
            }
            None => {
                // List all installed packages and their files
                let installed = cache.list_installed();
                if installed.is_empty() {
                    println!("No packages installed");
                } else {
                    println!("Installed packages:");
                    for package in installed {
                        println!("\n{}:", package);
                        if let Some((files, _)) = cache.get_installed_files(package.clone()) {
                            for file in files {
                                println!("  {}", file);
                            }
                        }
                    }
                }
            }
        }
    } else {
        println!("Use -h or --help for usage information.");
    }
}

// Helper function to download and install a package
fn download_and_install_package(
    package_name: &str,
    database: &Database,
    cache: &mut Cache,
    client: &reqwest::blocking::Client,
) -> Result<(), Box<dyn Error>> {
    let parts: Vec<&str> = database.src().split('/').collect();
    let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

    println!("Downloading package {}...", package_name);

    // Construct URL based on source type
    let url = if database.src().contains("github.com") {
        format!(
            "https://raw.githubusercontent.com/{}/{}/main/{}",
            owner, repo, package_name.trim_end_matches(".spm")
        )
    } else {
        format!("{}/{}", database.src(), package_name)
    };

    // Download package
    let response = client.get(&url).header("User-Agent", "spm-client").send()?;

    if !response.status().is_success() {
        return Err(format!("Failed to download package: HTTP {}", response.status()).into());
    }

    // Save to temporary file
    let temp_path = format!("/tmp/{}", package_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o666)
        .open(&temp_path)?;

    let content = response.bytes()?;
    file.write_all(&content)?;

    // Install downloaded package
    handle_install_package(&temp_path, None, cache)?;

    // Clean up
    if let Err(e) = fs::remove_file(&temp_path) {
        eprintln!("Warning: Failed to remove temporary file: {}", e);
    }

    println!("Package {} installed successfully", package_name);
    Ok(())
}
