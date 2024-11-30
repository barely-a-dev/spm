use spm_lib::db::Cache;
use spm_lib::db::Database;
use crate::handlers::*;
use spm_lib::lock::Lock;
use spm_lib::patch::Patch;
use spm_lib::config::Config;
use std::io::Write;
use std::process::exit;
use std::{
    error::Error,
    fs::{self},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process,
};
use spm_lib::helpers::prefer_root;

pub fn require_root(operation: &str) {
    if !spm_lib::helpers::is_root() {
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
if let Some(mut files) = matches.get_many::<String>("install-patch") {
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
    } else if let Some(mut args) = matches.get_many::<String>("install-package") {
        let (_, _cache_lock, _bin_lock, _) =
            prefer_root("install a package", matches.get_flag("force-op"), false, true, true, false);

        let package_path = args.next().expect("Package file argument required");
        let target_dir = args.next().map(|s| s.as_str()); // Convert to Option<&str>

        if let Err(e) = handle_install_package(package_path, target_dir, cache) {
            eprintln!("Failed to install package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("config") {
        require_root("updating config");
        let _conf_lock = Lock::new("conf").expect("Failed to lock config file");
        let key = args.next().expect("Key argument required");

        // Collect all remaining arguments into a vector
        let values: Vec<String> = args.map(|s| s.to_string()).collect();
        if values.is_empty() {
            panic!("At least one value is required");
        }

        // Format the values as a string representation of an array
        let value = format!(
            "[{}]",
            values
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(",")
        );

        match key.as_str() {
            "net_enabled" | "src_repo" | "github_token" | "extra_repos" => {
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
        let (_lock, _cache_lock, _bin_lock, _) =
            prefer_root("install packages", matches.get_flag("force-op"), true, true, true, false);

        if let Some(packages) = matches.get_many::<String>("install") {
            let (packages, vers) = split_values(packages);
            let client = reqwest::blocking::Client::new();
            let mut success_count = 0;
            let total_packages = packages.len();

            for i in 0..packages.len() {
                let package = packages[i].as_str();
                if package.starts_with("./") || package.ends_with(".spm") {
                    // Local package installation
                    match handle_install_package(package, None, cache) {
                        Ok(_) => {
                            println!("Successfully installed local package: {}", package);
                            success_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to install local package {}: {}", package, e);
                            if e.to_string().contains("File exists") {
                                println!("You probably installed the package with another package manager already.");
                            }
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

                    let package = packages[i].as_str();
                    let version = vers.get(i).cloned();

                    match download_and_install_package(package, database, cache, &version, &client)
                    {
                        Ok(_) => {
                            success_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to install package {}: {}", package, e);
                            if e.to_string().contains("File exists") {
                                println!("You probably installed the package with another package manager already.");
                            }
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
        let (_lock, _cache_lock, _bin_lock, _) =
            prefer_root("update packages", matches.get_flag("force-op"), true, true, true, false);

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

                    println!("Removing {} v{}", package_name, current);
                    match handle_uninstall_package(package_name, cache) {
                        Ok(_) => {
                            println!("Successfully removed outdated package {}", package_name);
                        }
                        Err(e) => {
                            println!("Failed to remove {} before update: {e}", package_name);
                            exit(1);
                        }
                    }

                    match download_and_install_package(
                        name,
                        database,
                        cache,
                        &database.get_recent(&name),
                        &client,
                    ) {
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
                match download_and_install_package(
                    &name,
                    database,
                    cache,
                    &database.get_recent(&name),
                    &client,
                ) {
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
        let _lock = Lock::new("db").expect("Failed to lock database");
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
    } else if let Some(packages) = matches.get_many::<String>("uninstall") {
        let (_lock, _cache_lock, _bin_lock, _) =
            prefer_root("uninstall packages", matches.get_flag("force-op"), true, true, true, false);

        for package in packages {
            if let Err(e) = handle_uninstall_package(package, cache) {
                eprintln!("Failed to uninstall package: {}", e);
                process::exit(1);
            }
        }
    } else if matches.contains_id("list") {
        match cache.package_count() {
            0 => {
                println!("No packages installed.");
                exit(1)
            }
            1 => println!("1 package installed."),
            f => println!("{f} packages installed."),
        }

        match matches.get_one::<String>("list") {
            Some(package) => {
                // List files for specific package
                if let Some(files) = cache.get_installed_files(package.to_string()) {
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
                        if let Some(files) = cache.get_installed_files(package.clone()) {
                            for file in files {
                                println!("  {}", file);
                            }
                        }
                    }
                }
            }
        }
    } else if matches.get_flag("statistics") {
        // TODO  
    } else {
        println!("Use -h or --help for usage information.");
    }
}

fn split_values(values: clap::parser::ValuesRef<'_, String>) -> (Vec<String>, Vec<String>) {
    let values: Vec<&String> = values.collect();
    let values: Vec<String> = values.iter().cloned().cloned().collect(); // Why does this need two cloned calls to work??
    let mut before_amp = Vec::new();
    let mut after_amp = Vec::new();
    let mut found_amp = false;

    for value in values {
        if value == "&" {
            found_amp = true;
            continue;
        }

        if found_amp {
            after_amp.push(value);
        } else {
            before_amp.push(value);
        }
    }

    (before_amp, after_amp)
}

fn download(
    database: &Database,
    package_name: &str,
    output_name: &str,
    req_ver: &Option<String>,
    client_op: Option<&reqwest::blocking::Client>,
) -> Result<(), Box<dyn Error>> {
    let client = if client_op.is_none() {
        &reqwest::blocking::Client::new()
    } else {
        client_op.unwrap()
    };

    let parts: Vec<&str> = database.src().split('/').collect();
    let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);
    println!("{:#?}", database);

    if database.exact_search(package_name.to_string()).is_none() {
        println!("Package {} not found.", package_name);
        exit(1);
    }

    let version = if let Some(v) = req_ver {
        v
    } else {
        &match database.get_recent(package_name) {
            Some(v) => v,
            None => {
                println!("Failed to get recent version. Try updating the database.");
                exit(1)
            }
        }
    };
    let version = version.as_str();

    println!("Downloading package {}...", package_name);

    // Construct URL based on source type
    let url = if database.src().contains("github.com") {
        format!(
            "https://raw.githubusercontent.com/{}/{}/main/{}",
            owner,
            repo,
            package_name.trim_end_matches(".spm").to_string() + "%26" + version
        )
    } else {
        format!("{}/{}", database.src(), package_name)
    };

    // Download package
    print!("{}", url);
    let response = client.get(&url).header("User-Agent", "spm-client").send()?;

    if !response.status().is_success() {
        return Err(format!("Failed to download package: HTTP {}", response.status()).into());
    }

    // Save to temporary file
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o666)
        .open(&output_name)?;

    let content = response.bytes()?;
    file.write_all(&content)?;
    Ok(())
}

// Helper function to download and install a package
fn download_and_install_package(
    package_name: &str,
    database: &Database,
    cache: &mut Cache,
    ver: &Option<String>,
    client: &reqwest::blocking::Client,
) -> Result<(), Box<dyn Error>> {
    // Check if package is already installed
    if cache.has_package(package_name) {
        return Err(format!("Package {} is already installed", package_name).into());
    }

    // Create temporary file path
    let temp_path = format!("/tmp/{}", package_name);

    // Download the package using the download function
    download(database, package_name, &temp_path, ver, Some(client))?;

    // Install downloaded package
    handle_install_package(&temp_path, None, cache)?;

    // Clean up
    if let Err(e) = fs::remove_file(&temp_path) {
        eprintln!("Warning: Failed to remove temporary file: {}", e);
    }

    println!("Package {} installed successfully", package_name);
    Ok(())
}