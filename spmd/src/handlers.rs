use crate::helpers as shelp;
use crate::helpers::parse_name_and_version;
use crate::PackageConfig;
use base64::engine::general_purpose;
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Response;
use reqwest::StatusCode;
use serde_json::Value;
use spm_lib::config::Config;
use spm_lib::db;
use spm_lib::lock::Lock;
use spm_lib::package::Package;
use spm_lib::security::Security;
use std::collections::HashMap;
use std::io::stdin;
use std::os::unix::fs::PermissionsExt;
use std::{
    error::Error,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{self, exit},
};
use uuid::Uuid;

pub fn package_exes(input_dir: &str, output_file: &str, allow_large: bool, custom_name: Option<String>, ver: Option<String>) -> Result<(), Box<dyn Error>> {
    let mut package = Package::new();
    
    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {wide_msg}")
            .unwrap()
    );

    // Scan directory for executables
    pb.set_message("Scanning for executables...");
    
    let files: Vec<PathBuf> = walkdir::WalkDir::new(input_dir)
    .max_depth(1)
    .follow_links(true)
    .into_iter()
    .filter_map(|e| e.ok())
    .filter(|e| {
        if let Ok(metadata) = e.metadata() {
            // Check if it's a regular file and is executable
            metadata.is_file() && (metadata.permissions().mode() & 0o111 != 0)
        } else {
            false
        }
    })
    .map(|entry| entry.path().to_path_buf())
    .collect();

    if files.is_empty() {
        return Err("No executable files found in directory".into());
    }

    pb.set_message(format!("Found {} executable files", files.len()));

    // Process each executable
    for file_path in files {
        let metadata = fs::metadata(&file_path)?;
        
        // Check file size if needed
        if !allow_large && metadata.len() > 100_000_000 {
            return Err(format!("File {} is larger than 100MB. Use -L to package anyway", file_path.display()).into());
        }

        let contents = fs::read(&file_path)?;
        let permissions = metadata.permissions().mode();
        
        // Use just the file name as the relative path
        let relative_path = PathBuf::from(file_path.file_name().ok_or("Invalid file name")?);

        // Check if file requires root permissions
        if file_path.starts_with("/usr/bin")
            || file_path.starts_with("/usr/sbin")
            || permissions & 0o4000 != 0
            || permissions & 0o2000 != 0
        {
            package.requires_root = true;
        }

        // All executables go to /usr/bin
        let target_dir = Some(PathBuf::from("/usr/bin"));

        pb.set_message(format!("Adding {} to package...", relative_path.display()));
        package.add_file(relative_path, permissions, contents, target_dir);
    }

    // Set package name
    if let Some(name) = custom_name {
        package.name = name;
    } else {
        // Use directory name as package name if no custom name provided
        package.name = PathBuf::from(input_dir)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();
    }

    // Set package version
    if let Some(version) = ver {
        package.version = version;
    } else {
        // If no version specified, try to extract from output file name or use default
        let (_, file_version) = parse_name_and_version(output_file);
        package.version = file_version.unwrap_or_else(|| "1.0.0".to_string());
    }

    // Save the package
    pb.set_message("Saving package file...");
    package.save_package(Path::new(output_file))?;

    pb.finish_with_message(format!("Package created successfully: {}", output_file));
    Ok(())
}

pub fn mass_package(input_dir: &str, output_dir: &str, allow_large: bool, custom_name: &Option<String>, ver: &Option<String>) { // (More args need to be references due to using ops that repeat)
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
            let custom_name = custom_name.clone();

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
                        &custom_name,
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
}

pub fn handle_package_file(
    input_file: &str,
    output_file: &str,
    allow_large: bool,
    allow_empty_ver: bool,
    custom_name: Option<String>,
    ver: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let file_path = Path::new(input_file);
    let mut package = Package::new();

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{prefix:.bold.dim} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {wide_msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Stage 1: Check file (0-10%)
    pb.set_prefix("Checking");
    pb.set_position(0);

    if !file_path.exists() {
        return Err("Input file does not exist".into());
    }

    // Get file metadata
    let metadata = fs::metadata(file_path)?;

    // Check file size if needed
    if !allow_large && metadata.len() > 100_000_000 {
        return Err("File is larger than 100MB. Use -L to package anyway".into());
    }

    pb.set_position(10);

    // Stage 2: Read file (10-50%)
    pb.set_prefix("Reading");
    pb.set_message("Reading file contents...");

    let contents = fs::read(file_path)?;
    let permissions = metadata.permissions().mode();

    pb.set_position(50);

    // Stage 3: Process file (50-80%)
    pb.set_prefix("Processing");
    pb.set_message("Adding file to package...");

    // Use just the file name as the relative path
    let relative_path = PathBuf::from(file_path.file_name().ok_or("Invalid file name")?);

    // Check if file requires root permissions
    if file_path.starts_with("/usr/bin")
        || file_path.starts_with("/usr/sbin")
        || permissions & 0o4000 != 0
        || permissions & 0o2000 != 0
    {
        package.requires_root = true;
    }

    let target_dir = if permissions & 0o111 != 0 {
        Some(PathBuf::from("/usr/bin"))
    } else {
        None
    };

    package.add_file(relative_path.clone(), permissions, contents, target_dir);

    pb.set_position(80);

    // Name is just the filename for single-file packages
    let name = relative_path.display().to_string();
    let (parsed_name, parsed_version) = parse_name_and_version(&name);

    // Always set a name - use the parsed name or the full filename if parsing failed, custom name if it exists.
    package.name = match custom_name {
        None => {
            if parsed_name.is_empty() {
                name.clone()
            } else {
                parsed_name
            }
        }
        Some(n) => n,
    };

    // Handle versioning
    if ver.is_some() {
        package.version = ver.unwrap_or("0.0.0".to_string());
    } else if !allow_empty_ver {
        if let Some(version) = parsed_version {
            package.version = version;
        } else {
            let (_, versionp) = parse_name_and_version(output_file);
            if let Some(v) = versionp {
                package.version = v;
            } else {
                println!("No version found. Please enter the package version:");
                let mut buf = "".to_string();
                stdin().read_line(&mut buf)?;
                package.version = buf.to_string();
            }
        }
    }

    package.version = package.version.trim().to_string();

    // Stage 4: Save package (80-100%)
    pb.set_prefix("Saving");
    pb.set_message("Writing package file...");

    package.save_package(Path::new(output_file))?;

    pb.set_position(100);
    pb.finish_with_message(format!("Package created successfully: {}", output_file));

    Ok(())
}

// Less logging in atomic ver for less ugly output
pub fn handle_package_file_atomic(
    input_file: &str,
    output_file: &str,
    allow_large: bool,
    allow_empty_ver: bool,
    custom_name: &Option<String>,
    ver: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    let file_path = Path::new(input_file);
    let mut package = Package::new();

    // Basic checks
    if !file_path.exists() {
        return Err("Input file does not exist".into());
    }

    // Get file metadata
    let metadata = fs::metadata(file_path)?;

    // Check file size if needed
    if !allow_large && metadata.len() > 100_000_000 {
        return Err("File is larger than 100MB. Use -L to package anyway".into());
    }

    let contents = fs::read(file_path)?;
    let permissions = metadata.permissions().mode();

    // Use just the file name as the relative path
    let relative_path = PathBuf::from(file_path.file_name().ok_or("Invalid file name")?);

    // Check if file requires root permissions
    if file_path.starts_with("/usr/bin")
        || file_path.starts_with("/usr/sbin")
        || permissions & 0o4000 != 0
        || permissions & 0o2000 != 0
    {
        package.requires_root = true;
    }

    let target_dir = if permissions & 0o111 != 0 {
        Some(PathBuf::from("/usr/bin"))
    } else {
        None
    };

    package.add_file(relative_path.clone(), permissions, contents, target_dir);

    // Name is just the filename for single-file packages
    let name = relative_path.display().to_string();
    let (parsed_name, parsed_version) = parse_name_and_version(&name);

    // Always set a name - use the parsed name or the full filename if parsing failed, custom name if it exists.
    package.name = match custom_name {
        None => {
            if parsed_name.is_empty() {
                name.clone()
            } else {
                parsed_name
            }
        }
        Some(n) => n.to_string(),
    };

    // Handle versioning
    if ver.is_some() {
        package.version = ver.clone().unwrap_or("0.0.0".to_string());
    } else if !allow_empty_ver {
        if let Some(version) = parsed_version {
            package.version = version;
        } else {
            let (_, versionp) = parse_name_and_version(output_file);
            if let Some(v) = versionp {
                package.version = v;
            } else {
                println!("No version found. Please enter the package version:");
                let mut buf = "".to_string();
                stdin().read_line(&mut buf)?;
                package.version = buf.to_string();
            }
        }
    }

    package.version = package.version.trim().to_string();

    package.save_package(Path::new(output_file))?;
    Ok(())
}

pub fn handle_package_dir(
    package_dir: &str,
    output_file: &str,
    allow_large: bool,
    ver: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let dir_path = Path::new(package_dir);
    let mut package = Package::new();

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{prefix:.bold.dim} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {wide_msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Stage 1: Load configuration (5%)
    pb.set_prefix("Loading config");
    pb.set_position(0);

    let config_path = dir_path.join("pkg.toml");
    let config = if config_path.exists() {
        pb.set_message("Reading package configuration...");
        let config_str = fs::read_to_string(&config_path)?;
        toml::from_str::<PackageConfig>(&config_str)?
    } else {
        PackageConfig {
            name: None,
            version: None,
            file_permissions: None,
            files_to_remove: None,
            files_to_empty: None,
            install_dirs: None,
        }
    };

    pb.set_position(5);

    // Stage 2: Count files (10%)
    pb.set_prefix("Scanning");
    pb.set_message("Counting files...");

    let total_files: u64 = walkdir::WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64;

    pb.set_position(10);

    // Stage 3: Process files (10-80%)
    pb.set_prefix("Processing");
    let files_progress_step = 70.0 / total_files as f64;
    let mut current_progress = 10;

    for entry in walkdir::WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        // Skip if file is a symlink
        if path.is_symlink() {
            current_progress = (current_progress as f64 + files_progress_step) as u64;
            pb.set_position(current_progress);
            continue;
        }

        let relative_path = match path.strip_prefix(dir_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: Skipping file {}: {}", path.display(), e);
                continue;
            }
        };

        let message = format!("Processing {}...", relative_path.display());
        pb.set_message(message.clone());

        // Skip pkg.toml and binary files over 100MB
        if relative_path == Path::new("pkg.toml") {
            current_progress = (current_progress as f64 + files_progress_step) as u64;
            pb.set_position(current_progress);
            continue;
        }

        // Get file metadata with better error handling
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "Warning: Cannot read metadata for {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
        };

        // Skip files larger than 100MB
        if !allow_large && metadata.len() > 100_000_000 {
            eprintln!(
                "Warning: Skipping large file {}: {} bytes",
                path.display(),
                metadata.len()
            );
            continue;
        }

        pb.set_message(format!("{} Reading file contents...", &message));

        // Read file contents with timeout protection
        let contents = match std::fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: Cannot read file {}: {}", path.display(), e);
                continue;
            }
        };

        let mut permissions = metadata.permissions().mode();

        if let Some(ref perm_map) = config.file_permissions {
            if let Some(&configured_perms) =
                perm_map.get(&relative_path.to_string_lossy().to_string())
            {
                permissions = configured_perms;
            }
        }

        if path.starts_with("/usr/bin")
            || path.starts_with("/usr/sbin")
            || permissions & 0o4000 != 0
            || permissions & 0o2000 != 0
        {
            package.requires_root = true;
        }

        let target_dir = if permissions & 0o111 != 0 {
            Some(PathBuf::from("/usr/bin"))
        } else {
            None
        };

        package.add_file(
            PathBuf::from(relative_path.file_name().ok_or("Invalid file name")?),
            permissions,
            contents,
            target_dir,
        );

        current_progress = (current_progress as f64 + files_progress_step) as u64;
        pb.set_position(current_progress);
    }

    // Stage 4: Process configuration entries (80-90%)
    pb.set_prefix("Configuring");
    pb.set_position(80);

    if let Some(removes) = config.files_to_remove {
        pb.set_message("Processing files to remove...");
        for path in removes {
            package.mark_for_removal(PathBuf::from(path));
        }
    }

    if let Some(empties) = config.files_to_empty {
        pb.set_message("Processing files to empty...");
        for path in empties {
            package.mark_for_empty(PathBuf::from(path));
        }
    }

    if let Some(name) = config.name {
        package.name = name;
    } else {
        // Ask for package details if no config file
        println!("No pkg.toml found. Enter package name:");
        let mut name = String::new();
        std::io::stdin().read_line(&mut name)?;
        package.name = name.trim().to_string();
    }

    if let Some(version) = config.version {
        package.version = version;
    } else if let Some(version) = ver {
        package.version = version;
    } else {
        println!("Enter package version (e.g. 1.0.0):");
        let mut version = String::new();
        std::io::stdin().read_line(&mut version)?;
        package.version = version.trim().to_string();
    }

    package.version = package.version.trim().to_string();

    if let Some(install_dirs) = &config.install_dirs {
        for (file_path, target_dir) in install_dirs {
            if let Some(entry) = package.files.get_mut(Path::new(file_path)) {
                entry.target_dir = Some(PathBuf::from(target_dir));
            }
        }
    }

    pb.set_position(90);

    // Stage 5: Save package (90-100%)
    pb.set_prefix("Saving");
    pb.set_message("Writing package file...");
    package.save_package(Path::new(output_file))?;

    pb.set_position(100);
    pb.finish_with_message(format!("Package created successfully: {}", output_file));

    Ok(())
}

pub fn handle_verify_package(package_path: &str) -> Result<(), Box<dyn Error>> {
    let package = Package::load_package(Path::new(package_path))?;

    println!("Package is valid:");
    println!("Requires root: {}", package.requires_root);
    println!("Number of files: {}", package.files.len());
    println!("Number of patches: {}", package.patches.len());
    println!("Files to remove: {}", package.files_to_remove.len());

    for (path, entry) in &package.files {
        println!(
            "File: {} (permissions: {:o}) (install dir: {})",
            path.display(),
            entry.permissions,
            entry
                .target_dir
                .clone()
                .unwrap_or("default".into())
                .display()
        );
    }

    Ok(())
}

pub fn handle_publish_package(
    package_path: &str,
    database: &db::Database,
    config: &mut Config,
) -> Result<(), Box<dyn Error>> {
    // First verify the package is valid
    let _package = Package::load_package(Path::new(package_path)).expect("Invalid package");

    let (valid, missing, found) = database.search_for_deps(_package.dependencies);

    if !valid {
        println!("Missing dependencies not found in DB. Proceeding, but note that your package may not be able to be installed until those packages are available.");
        println!("Missing packages:\n\t{:#?}", missing);
        println!("Found packages:\n\t{:#?}", found);
    }

    let mut tokenfile = dirs::home_dir().expect("Failed to get home directory");
    tokenfile.push(".spm.token.encrypted");

    let token = if tokenfile.exists() {
        match config.get_github_token() {
            Some(token) => token,
            None => shelp::get_token(),
        }
    } else {
        shelp::get_token()
    };

    let client = reqwest::blocking::Client::new();

    // Get repo info from database src
    let src = database.src();
    let parts: Vec<&str> = src.split('/').collect();
    if parts.len() < 2 {
        return Err("Invalid repository format in database".into());
    }
    let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

    // First get authenticated user info
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "spm-client")
        .send()?;

    if !user_response.status().is_success() {
        println!("Token: {}", token);
        return Err(
            "Unable to get user information. Try to reset your token using spm --rtok".into(),
        );
    }

    let user_info: Value = user_response.json()?;
    let username = user_info["login"]
        .as_str()
        .ok_or("Unable to get username")?;

    let permission_url = format!(
        "https://api.github.com/repos/{}/{}/collaborators/{}/permission",
        owner, repo, username
    );

    let permission_response = client
        .get(&permission_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "spm-client")
        .send()?;

    if !permission_response.status().is_success() {
        return Err("Unable to verify repository permissions".into());
    }

    let permission_info: Value = permission_response.json()?;
    let permission_level = permission_info["permission"].as_str().unwrap_or("none");

    // Read package file contents
    let file_contents = fs::read(package_path)?;
    let filename = Path::new(package_path)
        .file_name()
        .ok_or("Invalid package filename")?
        .to_str()
        .ok_or("Invalid UTF-8 in filename")?;

    let (filename, mut ver) =
        shelp::parse_name_and_version(filename.split('/').last().unwrap_or("unnamed_f"));

    if ver.is_none() {
        ver = Some(_package.version);
    }

    // Encode contents as base64
    let encoded_contents = general_purpose::STANDARD.encode(&file_contents);

    match permission_level {
        "admin" | "write" => {
            // Direct publish flow
            let upload_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner,
                repo,
                shelp::format_f(&filename, database, &ver)
            );
            println!("Up: {}", upload_url);

            // Check if file exists
            let check_response = client
                .get(&upload_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()?;

            let mut commit_data = HashMap::new();
            commit_data.insert(
                "message",
                format!(
                    "{{SPM_PUB_SYS}} Publish package {} v{} by {}",
                    filename,
                    ver.clone().unwrap_or("UNKNOWN".to_string()),
                    username
                ),
            );
            commit_data.insert("content", encoded_contents);

            if check_response.status().is_success() {
                let existing: Value = check_response.json()?;
                if let Some(sha) = existing["sha"].as_str() {
                    commit_data.insert("sha", sha.to_string());
                }
            }

            let response = client
                .put(&upload_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&commit_data)
                .send()?;
            let stat = response.status();

            if !stat.is_success() {
                let error_body = &response.text()?;
                if error_body.contains("too large") {
                    println!("Error contains too large. Please directly contact SPM's maintainer to publish packages over 50MB in size. Packages over 100MB can not yet be published as, well, I can't afford a server so I have to rely on GH.");
                    exit(1);
                }
                return Err(format!("Failed to publish package: {} - {}", stat, error_body).into());
            } else {
                // Upload the recent version file
                let ver_upload_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}.ver",
                    owner,
                    repo,
                    shelp::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
                        .trim_end_matches(".spm")
                );

                let ver_content = ver.unwrap_or("UNKNOWN".to_string());
                let encoded_ver = general_purpose::STANDARD.encode(ver_content.as_bytes());

                let mut ver_commit_data = HashMap::new();
                ver_commit_data.insert(
                    "message",
                    format!(
                        "{{SPM_PUB_SYS}} Update recent version for {} to {} by {}",
                        filename, ver_content, username
                    ),
                );
                ver_commit_data.insert("content", encoded_ver);

                // Check if version file exists
                let ver_check = client
                    .get(&ver_upload_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .send()?;

                if ver_check.status().is_success() {
                    let existing: Value = ver_check.json()?;
                    if let Some(sha) = existing["sha"].as_str() {
                        ver_commit_data.insert("sha", sha.to_string());
                    }
                }

                let ver_response = client
                    .put(&ver_upload_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .json(&ver_commit_data)
                    .send()?;

                if ver_response.status().is_success() {
                    println!("Package and version file published successfully!");
                } else {
                    return Err(format!(
                        "Failed to publish version file: {}",
                        ver_response.status()
                    )
                    .into());
                }
                Ok(())
            }
        }
        "read" | "pull" => {
            // Create pull request flow for publishing
            let branch_name = format!("package-publish-{}", Uuid::new_v4());

            // Get default branch ref
            let branch_url = format!(
                "https://api.github.com/repos/{}/{}/git/ref/heads/main",
                owner, repo
            );

            let branch_response = client
                .get(&branch_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()?;

            let branch_info: Value = branch_response.json()?;
            let base_sha = branch_info["object"]["sha"]
                .as_str()
                .ok_or("Could not get base branch SHA")?;

            // Create new branch
            let create_ref_url =
                format!("https://api.github.com/repos/{}/{}/git/refs", owner, repo);
            let mut ref_data = HashMap::new();
            ref_data.insert("ref", format!("refs/heads/{}", branch_name));
            ref_data.insert("sha", base_sha.to_string());

            let _create_branch_response = client
                .post(&create_ref_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&ref_data)
                .send()?;

            // Create commits for both package and version files
            let upload_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner,
                repo,
                shelp::format_f(&filename, database, &ver)
            );

            let mut commit_data = HashMap::new();
            commit_data.insert(
                "message",
                format!(
                    "{{SPM_PUB_SYS}} Publish package {} v{} by {}",
                    filename,
                    ver.clone().unwrap_or("UNKNOWN".to_string()),
                    username
                ),
            );
            commit_data.insert("content", encoded_contents);
            commit_data.insert("branch", branch_name.clone());

            let _commit_response = client
                .put(&upload_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&commit_data)
                .send()?;

            // Add version file to the same PR
            let ver_upload_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}.ver",
                owner,
                repo,
                shelp::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
                    .trim_end_matches(".spm")
            );

            let ver_content = ver.clone().unwrap_or("UNKNOWN".to_string());
            let encoded_ver = general_purpose::STANDARD.encode(ver_content.as_bytes());

            let mut ver_commit_data = HashMap::new();
            ver_commit_data.insert(
                "message",
                format!(
                    "{{SPM_PUB_SYS}} Add recent version file for {} v{} by {}",
                    filename, ver_content, username
                ),
            );
            ver_commit_data.insert("content", encoded_ver);
            ver_commit_data.insert("branch", branch_name.clone());

            let _ver_commit_response = client
                .put(&ver_upload_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&ver_commit_data)
                .send()?;

            // Create pull request
            let pr_url = format!("https://api.github.com/repos/{}/{}/pulls", owner, repo);

            let mut pr_data = HashMap::new();
            pr_data.insert(
                "title",
                format!(
                    "{{SPM_PUB_SYS}} Publish package: {} v{} by {}",
                    filename,
                    ver.clone().unwrap_or("UNKNOWN".to_string()),
                    username
                ),
            );
            pr_data.insert("head", branch_name);
            pr_data.insert("base", "main".to_string());
            pr_data.insert(
            "body",
            format!(
                "Automated pull request for package publication\nPackage: {}\nVersion: {}\nSubmitted by: {}",
            filename,
            ver.unwrap_or("UNKNOWN".to_string()),
            username
        ),
    );

            let pr_response = client
                .post(&pr_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&pr_data)
                .send()?;

            if pr_response.status().is_success() {
                let pr_info: Value = pr_response.json()?;
                println!("Pull request created successfully!");
                println!("PR URL: {}", pr_info["html_url"].as_str().unwrap_or(""));
                Ok(())
            } else {
                Err("Failed to create pull request".into())
            }
        }
        _ => Err("You don't have permission to publish to this repository".into()),
    }
}

pub fn handle_remove_package(
    package_name: &str,
    database: &db::Database,
    vers: Option<Vec<String>>,
    config: &mut Config,
) -> Result<(), Box<dyn Error>> {
    let token = match config.get_github_token() {
        Some(token) => token,
        None => {
            println!("GitHub personal access token required for removing packages.");
            println!("Create one at https://github.com/settings/tokens");
            println!("Token must have 'repo' scope permissions.");
            println!("This token will be saved for future use.");
            let token = rpassword::prompt_password("Enter token: ")?;
            let token = token.trim().to_string();

            let password = rpassword::prompt_password("Create your password: ")
                .expect("Failed to read password, aborting. Your GH token was not stored.");

            Security::encrypt_and_save_token(token.clone(), &password)?;
            token
        }
    };

    let client = reqwest::blocking::Client::new();

    // Get repo info from database src
    let src = database.src();
    let parts: Vec<&str> = src.split('/').collect();
    if parts.len() < 2 {
        return Err("Invalid repository format in database".into());
    }
    let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

    // Get authenticated user info
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "spm-client")
        .send()?;

    if !user_response.status().is_success() {
        return Err("Unable to get user information".into());
    }

    let user_info: Value = user_response.json()?;
    let username = user_info["login"]
        .as_str()
        .ok_or("Unable to get username")?;

    // Check user permissions
    let permission_url = format!(
        "https://api.github.com/repos/{}/{}/collaborators/{}/permission",
        owner, repo, username
    );

    let permission_response = client
        .get(&permission_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "spm-client")
        .send()?;

    if !permission_response.status().is_success() {
        return Err("Unable to verify repository permissions".into());
    }

    let permission_info: Value = permission_response.json()?;
    let permission_level = permission_info["permission"].as_str().unwrap_or("none");

    // Construct file path
    let file_path = format!("{}", package_name);

    let vs: Vec<String> = if let Some(ves) = vers {
        ves
    } else {
        database.get_vers(&file_path)
    };

    match permission_level {
        "admin" | "write" => {
            let mut errs: Vec<&str> = vec![];
            let mut delete_response_succ: bool = true;
            let mut delete_response: Option<Response> = None;

            for version in vs {
                // Direct removal flow
                let file_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}",
                    owner,
                    repo,
                    shelp::format_f(&file_path, database, &Some(version)),
                );

                // Get file SHA
                let file_response = client
                    .get(&file_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .send()?;

                if !file_response.status().is_success() {
                    errs.push("Package not found in repository".into());
                    continue;
                }

                let file_info: Value = file_response.json()?;
                let file_sha = file_info["sha"].as_str().ok_or("Unable to get file SHA")?;

                // Delete file
                let mut delete_data = HashMap::new();
                delete_data.insert(
                    "message",
                    format!(
                        "{{SPM_REM_SYS}} Remove package {} by {}",
                        package_name, username
                    ),
                );
                delete_data.insert("sha", file_sha.to_string());

                let loc_delete_response = client
                    .delete(&file_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .json(&delete_data)
                    .send()?;
                delete_response_succ =
                    delete_response_succ && loc_delete_response.status().is_success();
                delete_response = Some(loc_delete_response);
            }

            if errs.len() > 0 {
                println!("Errors occurred during deletions:");
                for err in errs {
                    println!("\t{err}");
                }
            }

            if delete_response_succ {
                // Also delete the version file
                let ver_file_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}.ver",
                    owner, repo, package_name
                );

                // Try to get and delete the version file if it exists
                if let Ok(ver_response) = client
                    .get(&ver_file_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .send()
                {
                    if ver_response.status().is_success() {
                        let ver_info: Value = ver_response.json()?;
                        if let Some(ver_sha) = ver_info["sha"].as_str() {
                            let mut ver_delete_data = HashMap::new();
                            ver_delete_data.insert(
                                "message",
                                format!(
                                    "{{SPM_REM_SYS}} Remove version file for {} by {}",
                                    package_name, username
                                ),
                            );
                            ver_delete_data.insert("sha", ver_sha.to_string());

                            let _ver_delete_response = client
                                .delete(&ver_file_url)
                                .header("Authorization", format!("token {}", token))
                                .header("User-Agent", "spm-client")
                                .json(&ver_delete_data)
                                .send()?;
                        }
                    }
                }

                println!("Package and version file removed successfully!");
                Ok(())
            } else {
                Err(format!(
                    "Failed to remove package: {}",
                    delete_response
                        .map(|s| s.status())
                        .unwrap_or(StatusCode::from_u16(593).unwrap_or_default())
                )
                .into())
            }
        }
        "read" | "pull" => {
            // Create pull request flow for removal
            let branch_name = format!("package-remove-{}", Uuid::new_v4());

            // Get default branch ref
            let branch_url = format!(
                "https://api.github.com/repos/{}/{}/git/ref/heads/main",
                owner, repo
            );

            let branch_response = client
                .get(&branch_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()?;

            let branch_info: Value = branch_response.json()?;
            let base_sha = branch_info["object"]["sha"]
                .as_str()
                .ok_or("Could not get base branch SHA")?;

            // Create new branch
            let create_ref_url =
                format!("https://api.github.com/repos/{}/{}/git/refs", owner, repo);
            let mut ref_data = HashMap::new();
            ref_data.insert("ref", format!("refs/heads/{}", branch_name));
            ref_data.insert("sha", base_sha.to_string());

            let _create_branch_response = client
                .post(&create_ref_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&ref_data)
                .send()?;

            // Delete package files for all versions
            for version in vs.iter() {
                let formatted_path = shelp::format_f(&file_path, database, &Some(version.clone()));
                let file_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}",
                    owner, repo, formatted_path
                );

                // Try to get file SHA
                if let Ok(file_response) = client
                    .get(&file_url)
                    .header("Authorization", format!("token {}", token))
                    .header("User-Agent", "spm-client")
                    .send()
                {
                    if file_response.status().is_success() {
                        let file_info: Value = file_response.json()?;
                        if let Some(file_sha) = file_info["sha"].as_str() {
                            // Delete package file
                            let mut delete_data = HashMap::new();
                            delete_data.insert(
                                "message",
                                format!(
                                    "{{SPM_REM_SYS}} Remove package {} version {} by {}",
                                    package_name, version, username
                                ),
                            );
                            delete_data.insert("sha", file_sha.to_string());
                            delete_data.insert("branch", branch_name.clone());

                            let delete_response = client
                                .delete(&file_url)
                                .header("Authorization", format!("token {}", token))
                                .header("User-Agent", "spm-client")
                                .json(&delete_data)
                                .send()?;
                            if !delete_response.status().is_success()
                            {
                                println!("An error occurred. Status: HTTP {}", delete_response.status());
                            }
                        }
                    }
                }
            }

            // Try to delete version file if it exists
            let ver_file_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}.ver",
                owner, repo, package_name
            );

            if let Ok(ver_response) = client
                .get(&ver_file_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()
            {
                if ver_response.status().is_success() {
                    let ver_info: Value = ver_response.json()?;
                    if let Some(ver_sha) = ver_info["sha"].as_str() {
                        let mut ver_delete_data = HashMap::new();
                        ver_delete_data.insert(
                            "message",
                            format!(
                                "{{SPM_REM_SYS}} Remove version file for {} by {}",
                                package_name, username
                            ),
                        );
                        ver_delete_data.insert("sha", ver_sha.to_string());
                        ver_delete_data.insert("branch", branch_name.clone());

                        let _ver_delete_response = client
                            .delete(&ver_file_url)
                            .header("Authorization", format!("token {}", token))
                            .header("User-Agent", "spm-client")
                            .json(&ver_delete_data)
                            .send()?;
                    }
                }
            }

            // Create pull request
            let pr_url = format!("https://api.github.com/repos/{}/{}/pulls", owner, repo);

            let versions_str = vs.join(", ");
            let mut pr_data = HashMap::new();
            pr_data.insert(
                "title",
                format!(
                    "{{SPM_REM_SYS}} Remove package: {} by {}",
                    package_name, username
                ),
            );
            pr_data.insert("head", branch_name);
            pr_data.insert("base", "main".to_string());
            pr_data.insert(
        "body",
        format!(
            "Automated pull request for package removal\nPackage: {}\nVersions: {}\nRequested by: {}",
            package_name, versions_str, username
        ),
    );

            let pr_response = client
                .post(&pr_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&pr_data)
                .send()?;

            if pr_response.status().is_success() {
                let pr_info: Value = pr_response.json()?;
                println!("Pull request for package removal created successfully!");
                println!("PR URL: {}", pr_info["html_url"].as_str().unwrap_or(""));
                Ok(())
            } else {
                Err("Failed to create pull request for package removal".into())
            }
        }
        _ => Err("You don't have permission to remove packages from this repository".into()),
    }
}

pub fn handle_dev_pub(
    dir: PathBuf,
    config: &mut Config,
    database: &db::Database,
    custom_name: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let _lock = Lock::new("build")?;
    // Check if directory exists
    if !dir.exists() || !dir.is_dir() {
        return Err("Invalid project directory".into());
    }

    let mut package_name = None;
    let mut package_version = None;
    let mut build_command = None;
    let mut output_file = None;

    // Detect build system and configuration
    if dir.join("Cargo.toml").exists() {
        // Rust project
        let cargo_toml = fs::read_to_string(dir.join("Cargo.toml"))?;
        let cargo_doc: toml::Value = toml::from_str(&cargo_toml)?;

        if let Some(package) = cargo_doc.get("package") {
            package_name = package
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from);
            package_version = package
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from);
        }

        build_command = Some(vec!["cargo", "build", "--release"]);
        output_file = package_name
            .as_ref()
            .map(|name| dir.join("target/release").join(name));
    } else if dir.join("package.json").exists() {
        // Node.js project
        let package_json = fs::read_to_string(dir.join("package.json"))?;
        let pkg_doc: serde_json::Value = serde_json::from_str(&package_json)?;

        package_name = pkg_doc
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from);
        package_version = pkg_doc
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);

        if let Some(scripts) = pkg_doc.get("scripts") {
            if scripts.get("build").is_some() {
                build_command = Some(vec!["npm", "run", "build"]);
                output_file = Some(
                    dir.join("dist")
                        .join(package_name.as_ref().unwrap_or(&"main".to_string())),
                );
            }
        }
    } else if dir.join("CMakeLists.txt").exists() {
        // CMake project
        let cmake_lists = fs::read_to_string(dir.join("CMakeLists.txt"))?;

        // Try to extract project name and version from CMakeLists.txt
        if let Some(proj_line) = cmake_lists
            .lines()
            .find(|l| l.trim().starts_with("project("))
        {
            let parts: Vec<&str> = proj_line.split_whitespace().collect();
            if parts.len() > 1 {
                package_name = Some(parts[1].trim_matches(|c| c == '(' || c == ')').to_string());
            }
            if parts.len() > 2 {
                package_version = Some(parts[2].trim_matches(|c| c == '(' || c == ')').to_string());
            }
        }

        // Create build directory and run cmake + make
        fs::create_dir_all(dir.join("build"))?;
        build_command = Some(vec!["sh", "-c", "cd build && cmake .. && make"]);
        output_file = package_name
            .as_ref()
            .map(|name| dir.join("build").join(name));
    } else if dir.join("meson.build").exists() {
        // Meson project
        let meson_build = fs::read_to_string(dir.join("meson.build"))?;

        // Try to extract project name and version from meson.build
        if let Some(proj_line) = meson_build
            .lines()
            .find(|l| l.trim().starts_with("project("))
        {
            let parts: Vec<&str> = proj_line.split('\'').collect();
            if parts.len() > 1 {
                package_name = Some(parts[1].to_string());
            }
            if parts.len() > 3 {
                package_version = Some(parts[3].to_string());
            }
        }

        fs::create_dir_all(dir.join("build"))?;
        build_command = Some(vec!["sh", "-c", "meson setup build && cd build && ninja"]);
        output_file = package_name
            .as_ref()
            .map(|name| dir.join("build").join(name));
    } else if dir.join("configure.ac").exists() || dir.join("configure").exists() {
        // Autotools project
        if dir.join("configure.ac").exists() {
            let configure_ac = fs::read_to_string(dir.join("configure.ac"))?;

            // Try to extract package info from configure.ac
            if let Some(line) = configure_ac
                .lines()
                .find(|l| l.trim().starts_with("AC_INIT"))
            {
                let parts: Vec<&str> = line.split('[').collect();
                if parts.len() > 2 {
                    package_name =
                        Some(parts[1].trim_matches(|c| c == '[' || c == ']').to_string());
                    package_version =
                        Some(parts[2].trim_matches(|c| c == '[' || c == ']').to_string());
                }
            }

            build_command = Some(vec!["sh", "-c", "autoreconf -i && ./configure && make"]);
        } else {
            build_command = Some(vec!["sh", "-c", "./configure && make"]);
        }

        output_file = package_name.as_ref().map(|name| dir.join(name));
    } else if dir.join("Makefile").exists() {
        // Simple Makefile project
        let makefile = fs::read_to_string(dir.join("Makefile"))?;

        // Try to find the output binary name from the Makefile
        if let Some(line) = makefile
            .lines()
            .find(|l| l.trim().starts_with("TARGET") || l.trim().starts_with("NAME"))
        {
            if let Some(name) = line.split('=').nth(1) {
                package_name = Some(name.trim().to_string());
            }
        }

        build_command = Some(vec!["make"]);
        output_file = package_name.as_ref().map(|name| dir.join(name));
    }

    if build_command.is_none() {
        return Err("Unsupported or unrecognized project type".into());
    }

    // Execute build command
    let status = std::process::Command::new(build_command.clone().unwrap()[0])
        .args(&build_command.unwrap()[1..])
        .current_dir(&dir)
        .status()?;

    if !status.success() {
        return Err("Build failed".into());
    }

    // Create temporary package file
    let temp_dir = std::env::temp_dir();
    let package_file = temp_dir.join(format!(
        "{}.spm",
        package_name.as_ref().unwrap_or(&"unnamed".to_string())
    ));

    if package_file.exists() {
        println!("Package file exists, erasing...");
        fs::remove_file(&package_file).expect(
            "Failed to erase existing package file. Result may be corrupt or creation may fail.",
        );
    }

    if let Some(output) = output_file {
        if output.exists() {
            if let Ok((uid, gid)) = spm_lib::helpers::get_real_user() {
                // Create temp file with proper ownership
                if let Ok(file) = File::create(&package_file) {
                    drop(file); // Close the file handle

                    // Set proper permissions
                    fs::set_permissions(&package_file, fs::Permissions::from_mode(0o644))?;

                    // Set proper ownership
                    std::os::unix::fs::chown(&package_file, Some(uid.0), Some(gid))?;
                }
            }

            // Package the built file
            handle_package_file(
                output.to_str().unwrap(),
                package_file.to_str().unwrap(),
                true, // allow large in case
                true, // Sets the version below, so this and | is fine.
                custom_name, //                                               |
                None, //                                                <-
            )?;

            let mut pack = Package::load_package(&package_file)
                .expect("Failed to load package, may be invalid");
            pack.version = package_version.unwrap_or("UNKNOWN".to_string());
            pack.name = package_name.unwrap_or("unnamed".to_string());
            println!(
                "Successfully set up package {} v{}.",
                pack.name, pack.version
            );

            // Remove and recreate with proper permissions + ver/name
            let _ = fs::remove_file(&package_file);
            pack.save_package(&package_file)?;

            // Ensure the file is readable before publishing
            fs::set_permissions(&package_file, fs::Permissions::from_mode(0o644))?;

            let publish_result =
                handle_publish_package(package_file.to_str().unwrap(), database, config);

            // Clean up temp file regardless of publish result
            let _ = fs::remove_file(&package_file);

            // Now handle the publish result
            publish_result?;

            println!("Successfully built and published package");
            Ok(())
        } else {
            Err("Build output file not found".into())
        }
    } else {
        Err("Could not determine output file location".into())
    }
}
