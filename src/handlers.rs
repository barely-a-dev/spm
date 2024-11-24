use crate::db;
use crate::helpers;
use crate::helpers::parse_name_and_version;
use crate::Config;
use crate::Package;
use crate::PackageConfig;
use base64::engine::general_purpose;
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn handle_package_file(
    input_file: &str,
    output_file: &str,
    allow_large: bool,
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

    // Name is just the filename for single-file packages, ask for package version unless in name
    let name = relative_path.display().to_string();
    let (parsed_name, parsed_version) = parse_name_and_version(&name);
    package.name = parsed_name;

    // Only ask for version if we couldn't parse it from the filename
    if let Some(version) = parsed_version {
        package.version = version;
    } else {
        let (_, versionp) = parse_name_and_version(output_file);
        if let Some(version) = versionp {
            package.version = version;
        } else {
            println!("Enter package version (e.g. 1.0.0):");
            let mut version = String::new();
            std::io::stdin().read_line(&mut version)?;
            package.version = version.trim().to_string();
        }
    }

    // Stage 4: Save package (80-100%)
    pb.set_prefix("Saving");
    pb.set_message("Writing package file...");
    package.save_package(Path::new(output_file))?;

    pb.set_position(100);
    pb.finish_with_message(format!("Package created successfully: {}", output_file));

    Ok(())
}

pub fn handle_package_dir(
    package_dir: &str,
    output_file: &str,
    allow_large: bool,
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
    } else {
        println!("Enter package version (e.g. 1.0.0):");
        let mut version = String::new();
        std::io::stdin().read_line(&mut version)?;
        package.version = version.trim().to_string();
    }

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

pub fn handle_install_package(
    package_path: &str,
    target_dir: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let package = Package::load_package(Path::new(package_path))?;
    package.install(target_dir.map(Path::new))?;
    println!("Package installed successfully");
    Ok(())
}

pub fn handle_publish_package(
    package_path: &str,
    database: &db::Database,
    config: &mut Config,
) -> Result<(), Box<dyn Error>> {
    // First verify the package is valid
    let _package = Package::load_package(Path::new(package_path)).expect("Invalid package");

    let token = match config.get_github_token() {
        Some(token) => token,
        None => {
            println!("GitHub personal access token required for publishing.");
            println!("Create one at https://github.com/settings/tokens");
            println!("Token must have 'repo' scope permissions.");
            println!("This token will be saved for future use.");
            let token = rpassword::prompt_password("Enter token: ")?;
            let token = token.trim().to_string();
            config.set_github_token(token.clone())?;
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

    // First get authenticated user info
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

    let (filename, ver) =
        helpers::parse_name_and_version(filename.split('/').last().unwrap_or("unnamed_f"));

    // Encode contents as base64
    let encoded_contents = general_purpose::STANDARD.encode(&file_contents);

    match permission_level {
        "admin" | "write" => {
            // Direct publish flow
            let upload_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner,
                repo,
                helpers::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
            );

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

            if response.status().is_success() {
                // Upload the version file
                let ver_upload_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}.ver",
                    owner,
                    repo,
                    helpers::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
                );

                let ver_content = ver.unwrap_or("UNKNOWN".to_string());
                let encoded_ver = general_purpose::STANDARD.encode(ver_content.as_bytes());

                let mut ver_commit_data = HashMap::new();
                ver_commit_data.insert(
                    "message",
                    format!(
                        "{{SPM_PUB_SYS}} Update version for {} to {} by {}",
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
            } else {
                Err(format!("Failed to publish package: {}", response.status()).into())
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
                helpers::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
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
                helpers::remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
            );

            let ver_content = ver.clone().unwrap_or("UNKNOWN".to_string());
            let encoded_ver = general_purpose::STANDARD.encode(ver_content.as_bytes());

            let mut ver_commit_data = HashMap::new();
            ver_commit_data.insert(
                "message",
                format!(
                    "{{SPM_PUB_SYS}} Add version file for {} v{} by {}",
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
            config.set_github_token(token.clone())?;
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
    let file_path = format!("{}.spm", package_name);

    match permission_level {
        "admin" | "write" => {
            // Direct removal flow
            let file_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner, repo, file_path
            );

            // Get file SHA
            let file_response = client
                .get(&file_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()?;

            if !file_response.status().is_success() {
                return Err("Package not found in repository".into());
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

            let delete_response = client
                .delete(&file_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&delete_data)
                .send()?;

            // In the "admin" | "write" => match arm, after the successful delete_response check:
            if delete_response.status().is_success() {
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
                Err(format!("Failed to remove package: {}", delete_response.status()).into())
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

            // Delete both package and version files
            let file_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner, repo, file_path
            );

            let file_response = client
                .get(&file_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .send()?;

            if !file_response.status().is_success() {
                return Err("Package not found in repository".into());
            }

            let file_info: Value = file_response.json()?;
            let file_sha = file_info["sha"].as_str().ok_or("Unable to get file SHA")?;

            // Delete package file
            let mut delete_data = HashMap::new();
            delete_data.insert(
                "message",
                format!(
                    "{{SPM_REM_SYS}} Remove package {} by {}",
                    package_name, username
                ),
            );
            delete_data.insert("sha", file_sha.to_string());
            delete_data.insert("branch", branch_name.clone());

            let _delete_response = client
                .delete(&file_url)
                .header("Authorization", format!("token {}", token))
                .header("User-Agent", "spm-client")
                .json(&delete_data)
                .send()?;

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
                    "Automated pull request for package removal\nPackage: {}\nRequested by: {}",
                    package_name, username
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
