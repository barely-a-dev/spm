use crate::conversion::detect_file_type;
use crate::db::Cache;
use crate::db::Database;
use crate::handlers::*;
use crate::lock::Lock;
use crate::patch::Patch;
use crate::Config;
use anyhow;
use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::io::stdin;
use std::io::Read;
use std::io::Write;
//use std::time::Duration;
use crate::conversion::*;
use crate::Security;
use std::process::exit;
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
    let ver = matches.get_one::<String>("version").cloned();
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
    } else if matches.get_flag("reset-token") {
        require_root("resetting your token");
        Security::reset_token().expect("Failed to reset token");
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

        if let Err(e) = handle_package_dir(dir, output, allow_large, ver) {
            eprintln!("Failed to create package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("package-file") {
        let input_file = args.next().expect("Input file argument required");
        let output_file = args.next().expect("Output file argument required");
        let allow_large = matches.get_flag("allow-large");

        if let Err(e) = handle_package_file(input_file, output_file, allow_large, false, ver) {
            eprintln!("Failed to package file: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("mass-package") {
        let input_dir = args.next().expect("Input directory argument required");
        let output_dir = args.next().expect("Output directory argument required");
        let allow_large = matches.get_flag("allow-large");

        // Create output directory if it doesn't exist
        if let Err(e) = fs::create_dir_all(output_dir) {
            eprintln!("Failed to create output directory: {}", e);
            process::exit(1);
        }

        println!("Processing files from {} to {}", input_dir, output_dir);

        // Collect all files
        let files: Vec<PathBuf> = walkdir::WalkDir::new(input_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|entry| entry.path().to_path_buf())
            .collect();

        let total_count = files.len();
        println!("Found {} files to process", total_count);

        // Create main progress bar
        let pb = ProgressBar::new(total_count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)\n{wide_msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Create atomic counter for successful operations
        let success_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pb = std::sync::Arc::new(pb);

        // Determine number of threads
        let num_threads = num_cpus::get().max(1);
        let chunk_size = (files.len() + num_threads - 1) / num_threads;

        // Process files in parallel
        let results: Vec<_> = files
            .chunks(chunk_size)
            .map(|chunk| {
                let pb = pb.clone();
                let output_dir = output_dir.to_string();
                let chunk = chunk.to_vec();
                let success_count = success_count.clone();
                let allow_large = allow_large;
                let ver = ver.clone();

                std::thread::spawn(move || {
                    for file_path in chunk {
                        let input_file = file_path.to_string_lossy().to_string();
                        let file_name = file_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();

                        let output_file = Path::new(&output_dir)
                            .join(format!("{}.spm", file_name))
                            .to_string_lossy()
                            .to_string();

                        pb.set_message(format!("Processing: {}", file_name));

                        match handle_package_file_atomic(
                            &input_file,
                            &output_file,
                            allow_large,
                            false,
                            &ver,
                        ) {
                            Ok(_) => {
                                success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("\nFailed to package {}: {}", file_name, e);
                                if !matches!(
                                    e.to_string().as_str(),
                                    "File is larger than 100MB. Use -L to package anyway"
                                ) {
                                    println!("Press Enter to continue or Ctrl+C to abort...");
                                    let mut buf = String::new();
                                    if stdin().read_line(&mut buf).is_err() {
                                        eprintln!("Failed to read input, aborting...");
                                        process::exit(1);
                                    }
                                }
                            }
                        }

                        pb.inc(1);
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in results {
            handle.join().unwrap();
        }

        let final_success_count = success_count.load(std::sync::atomic::Ordering::Relaxed);

        pb.finish_and_clear();
        println!(
            "Complete: {}/{} files packaged successfully",
            final_success_count, total_count
        );

        if final_success_count != total_count {
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("verify-package") {
        let package_path = args.next().expect("Package file argument required");

        if let Err(e) = handle_verify_package(package_path) {
            eprintln!("Failed to verify package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("install-package") {
        let (_, _cache_lock, _bin_lock) =
            prefer_root("install a package", &matches, false, true, true);

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
        let (_lock, _cache_lock, _bin_lock) =
            prefer_root("install packages", &matches, true, true, true);

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

                    match download_and_install_package(package, database, cache, &version, &client) {
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
    } else if let Some(mut a) = matches.get_many::<String>("fetch") {
        let package: Option<&String> = a.next();
        let output_dir: Option<&String> = a.next();
        let req_ver: Option<String> = a.next().cloned();
        if let (Some(p), Some(o)) = (package, output_dir) {
            download(&database, p, o, &req_ver, None).expect("Failed to download package.");
        }
    } else if matches.contains_id("update") {
        let (_lock, _cache_lock, _bin_lock) =
            prefer_root("update packages", &matches, true, true, true);

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

                    match download_and_install_package(name, database, cache, &database.get_recent(&name), &client) {
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
                match download_and_install_package(&name, database, cache, &database.get_recent(&name), &client) {
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
    } else if let Some(packages) = matches.get_many::<String>("uninstall") {
        let (_lock, _cache_lock, _bin_lock) =
            prefer_root("uninstall packages", &matches, true, true, true);

        for package in packages
        {
            if let Err(e) = handle_uninstall_package(package, cache) {
                eprintln!("Failed to uninstall package: {}", e);
                process::exit(1);
            }
        }
    // } else if matches.contains_id("do-nothing") {
    //     let def = &"5000".to_string();
    //     let len = matches.get_one::<String>("do-nothing").unwrap_or(def);
    //     std::thread::sleep(Duration::from_millis(len.parse::<u64>().unwrap_or(5000)));
    // } else if matches.get_flag("lock-test") {
    //     let _lock = Lock::new("db").expect("Failed to lock");
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
    } else if let Some(mut args) = matches.get_many::<String>("convert-file") {
        let input_file = args.next().expect("Input file argument required");
        let output_file = args.next().expect("Output file argument required");

        println!("Attempting to convert...");

        if let Err(e) = convert(input_file, output_file) {
            eprintln!("Failed to convert file: {}", e);
            process::exit(1);
        }
        println!("File converted successfully");
    } else if let Some(output) = matches.get_one::<String>("mirror-repo") {
        let (_lock, _, _) = prefer_root("install packages", &matches, true, false, false);
        database.update_db().expect("Failed to update databse");
        let packages = database
            .list_all()
            .expect("Failed to retrieve package list");

        for pack in packages {
            for ver in database.get_vers(&pack)
            {
                let mut current_out = output.clone();
                current_out.push_str(&pack);
                match download(database, &pack, &current_out, &Some(ver), None) {
                    Ok(_) => println!("Successfully mirrored package {pack}"),
                    Err(e) => eprintln!("Failed to download {pack}: {e}"),
                }
            }
        }
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

fn prompt_non_root_confirmation(force_op: bool, operation: &str) -> bool {
    if force_op {
        println!("Proceeding...");
        return true;
    }

    print!("You aren't root! Are you sure you want to proceed? Attempting to {operation} can cause errors and corruptions. (y/N): ");
    std::io::stdout().flush().unwrap(); // Ensure prompt is displayed immediately

    let mut input = String::new();
    match stdin().read_line(&mut input) {
        Ok(_) => {
            let input = input.trim().to_lowercase();
            if input == "y" || input == "yes" {
                println!("Proceeding...");
                true
            } else {
                println!("Aborting...");
                false
            }
        }
        Err(_) => {
            eprintln!("Failed to read input, aborting...");
            false
        }
    }
}

fn prefer_root(
    operation: &str,
    matches: &clap::ArgMatches,
    lock_db: bool,
    lock_cache: bool,
    lock_bin: bool,
) -> (Option<Lock>, Option<Lock>, Option<Lock>) {
    let mut db_lock = None;
    let mut cache_lock = None;
    let mut bin_lock = None;

    if !is_root() {
        if !prompt_non_root_confirmation(matches.get_flag("force-op"), operation) {
            std::process::exit(1);
        }
    } else {
        // Only create locks that are requested
        if lock_db {
            db_lock = Some(Lock::new("db").expect("Failed to lock database"));
        }

        if lock_cache {
            cache_lock = Some(Lock::new("cache").expect("Failed to lock cache"));
        }

        if lock_bin {
            bin_lock = Some(Lock::new("bin").expect("Failed to lock binary"));
        }
    }

    (db_lock, cache_lock, bin_lock)
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

fn convert(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    match detect_file_type(input)? {
        Some(file_type) => match file_type.as_str() {
            "deb" => convert_deb_to_spm(Path::new(input), Path::new(output))?,
            "rpm" =>
            /*convert_rpm_to_spm(Path::new(input), Path::new(output))?*/
            {
                println!("RPM conversion is not supported at this time.");
            }
            "tar.gz" => convert_targz_to_spm(Path::new(input), Path::new(output))?,
            "zip" => convert_zip_to_spm(Path::new(input), Path::new(output))?,
            "tar.bz2" => convert_tarbz2_to_spm(Path::new(input), Path::new(output))?,
            _ => return Err(format!("Unsupported file type: {}", file_type).into()),
        },
        None => return Err("Unable to detect file type".into()),
    }
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

pub fn get_token() -> String {
    println!("GitHub personal access token required for publishing.");
    println!("Create one at https://github.com/settings/tokens");
    println!("Token must have 'repo' scope permissions.");
    println!("This token will be saved for future use.");
    let token = rpassword::prompt_password("Enter token: ").expect("Failed to read token");
    let token = token.trim().to_string();

    let password = rpassword::prompt_password("Create your password: ")
        .expect("Failed to read password, aborting. Your GH token was not stored");

    Security::encrypt_and_save_token(token.clone(), &password).expect("Failed to save token");
    token
}

pub fn validate_token(token: &String) -> anyhow::Result<&str> {
    // Check if empty or too short
    if token.is_empty() || token.len() < 40 {
        return Err(anyhow::Error::msg("Token is too short"));
    }

    // Check prefix
    if !token.starts_with("github_pat_") {
        return Err(anyhow::Error::msg("Token must start with 'github_pat_'"));
    }

    // Check for valid characters (GitHub tokens use base58)
    let valid_chars = token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');

    if !valid_chars {
        return Err(anyhow::Error::msg("Token contains invalid characters"));
    }

    // Check length (GitHub fine-grained PATs are typically longer than 40 chars)
    if token.len() < 40 {
        return Err(anyhow::Error::msg("Token length is invalid"));
    }

    Ok("Valid token")
}

pub fn format_f(filename: &str, ver: &Option<String>) -> String {
    remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
        .trim_end_matches(".spm")
        .to_owned()
        + "%26"
        + ver.as_ref().unwrap()
}
