mod db;
mod handlers;
mod helpers;
mod package;
mod patch;

use clap::{Arg, ArgAction, Command as ClapCommand};
use handlers::*;
use helpers::require_root;
use package::Package;
use patch::Patch;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process,
};

#[derive(Deserialize)]
struct PackageConfig {
    name: Option<String>,
    version: Option<String>,
    file_permissions: Option<HashMap<String, u32>>,
    files_to_remove: Option<Vec<String>>,
    files_to_empty: Option<Vec<String>>,
    install_dirs: Option<HashMap<String, String>>,
}

#[derive(Debug)]
struct Config {
    settings: HashMap<String, String>,
    path: PathBuf,
}

impl Config {
    fn load() -> Result<Self, Box<dyn Error>> {
        let mut path = dirs::home_dir().ok_or("Cannot find home directory")?;
        path.push(".spm.conf");

        let mut settings = HashMap::new();
        if !path.exists() {
            let mut file = File::create(&path)?;
            file.write_all(b"net_enabled=false\n")?;
            settings.insert("net_enabled".to_string(), "false".to_string());
        } else {
            let contents = fs::read_to_string(&path)?;
            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    settings.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        Ok(Config { settings, path })
    }

    fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn Error>> {
        self.settings.insert(key.to_string(), value);
        self.save()?;
        Ok(())
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let mut contents = String::new();
        for (key, value) in &self.settings {
            contents.push_str(&format!("{}={}\n", key, value));
        }
        fs::write(&self.path, contents)?;
        Ok(())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.settings.get(key).clone().cloned()
    }
    fn set_github_token(&mut self, token: String) -> Result<(), Box<dyn Error>> {
        // TODO:  validate the token format here
        self.set("github_token", token)
    }

    fn get_github_token(&self) -> Option<String> {
        self.get("github_token")
    }
}

fn main() {
    let mut config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            process::exit(1);
        }
    };
    let mut database = if let Some(s) = config.get("src_repo") {
        db::Database::from_src(s).unwrap_or(db::Database::new())
    } else {
        db::Database::new()
    };
    database.load().expect("Failed to load database");
    let matches = ClapCommand::new("SPM")
        .version("1.")
        .author("Nobody")
        .about("A simple package and patch manager")
        .arg(
            Arg::new("install-patch")
                .short('p')
                .long("install-patch")
                .help("Install a patch file to a specified directory")
                .num_args(2)
                .value_names(["TARGET_DIR", "PATCH_FILE"]),
        )
        .arg(
            Arg::new("create-patch")
                .short('c')
                .long("create-patch")
                .help("Create a patch file from two versions of a file")
                .num_args(3)
                .value_names(["OLD_FILE", "NEW_FILE", "OUTPUT_PATCH"]),
        )
        .arg(
            Arg::new("verify-patch")
                .short('v')
                .long("verify-patch")
                .help("Verify a patch file's validity")
                .num_args(1)
                .value_name("PATCH_FILE"),
        )
        .arg(
            Arg::new("package-dir")
                .short('P')
                .long("package-dir")
                .help("Package the contents of a directory into a .spm package")
                .num_args(2)
                .value_names(["SOURCE_DIR", "OUTPUT_FILE"]),
        )
        .arg(
            Arg::new("package-file")
                .short('f')
                .long("package-file")
                .help("Package a single file into a .spm package")
                .num_args(2)
                .value_names(["SOURCE_FILE", "OUTPUT_FILE"]),
        )
        .arg(
            Arg::new("verify-package")
                .short('V')
                .long("verify-package")
                .help("Verify a package's validity")
                .num_args(1)
                .value_name("PACKAGE_FILE"),
        )
        .arg(
            Arg::new("install-package")
                .short('i')
                .long("install-package")
                .help(
                    "Install a local package. Deprecated: only use if -I/--install isn't working.",
                )
                .num_args(1..=2)
                .value_names(["PACKAGE_FILE", "TARGET_DIR"]),
        )
        .arg(
            Arg::new("config")
                .short('C')
                .long("config")
                .help("Set a configuration option")
                .num_args(2)
                .value_names(["KEY", "VALUE"]),
        )
        .arg(
            Arg::new("update-db")
                .short('u')
                .long("update-db")
                .help("Update package database (requires net_enabled=true)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("search")
                .short('s')
                .long("search")
                .help("Search for packages in the database")
                .num_args(0..=1)
                .value_name("QUERY"),
        )
        .arg(
            Arg::new("install")
                .short('I')
                .long("install")
                .help("Install a package from the database or local file")
                .num_args(1)
                .value_name("PACKAGE"),
        )
        .arg(
            Arg::new("update")
                .short('U')
                .long("update")
                .help("Check for and install package updates")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allow-large")
                .short('L')
                .long("allow-large")
                .help("Allow packaging of files larger than 100 MB")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("publish")
                .short('b')
                .long("publish")
                .help("Publish a package to the configured repository")
                .num_args(1)
                .value_name("PACKAGE_FILE"),
        )
        .arg(
            Arg::new("unpublish")
                .short('r')
                .long("remove")
                .help("Remove a package from the configured repository")
                .num_args(1)
                .value_name("PACKAGE_FILE"),
        )
        .disable_version_flag(true)
        .get_matches();

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

        if let Err(e) = handle_package_file(input_file, output_file, allow_large) {
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
        let package_path = args.next().expect("Package file argument required");
        let target_dir = args.next().map(|s| s.as_str()); // Convert to Option<&str>

        if let Err(e) = handle_install_package(package_path, target_dir) {
            eprintln!("Failed to install package: {}", e);
            process::exit(1);
        }
    } else if let Some(mut args) = matches.get_many::<String>("config") {
        let key = args.next().expect("Key argument required");
        let value = args.next().expect("Value argument required");

        match key.as_str() {
            "net_enabled" | "source_repo" => {
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
    } else if let Some(package) = matches.get_one::<String>("install") {
        require_root("installing packages");
        if package.starts_with("./") || package.ends_with(".spm") {
            // Local package installation
            if let Err(e) = handle_install_package(package, None) {
                eprintln!("Failed to install local package: {}", e);
                process::exit(1);
            }
        } else {
            // Database package installation
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

            // First verify package exists
            if let Some(exact_package) = database.exact_search(package.to_string()) {
                let client = reqwest::blocking::Client::new();
                let parts: Vec<&str> = database.src().split('/').collect();
                let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

                // Download package from GitHub
                println!("Downloading package {}...", exact_package);
                let url = if database.src().contains("github.com") {
                    format!(
                        "https://raw.githubusercontent.com/{}/{}/main/{}",
                        owner, repo, exact_package
                    )
                } else {
                    // MAYBEDO: Custom sources outside of GH
                    format!("{}/{}", database.src(), exact_package)
                };

                match client.get(&url).header("User-Agent", "spm-client").send() {
                    Ok(response) => {
                        if response.status().is_success() {
                            // Save to temporary file
                            let temp_path = format!("/tmp/{}", exact_package);
                            if let Ok(mut file) = File::create(&temp_path) {
                                if let Ok(content) = response.bytes() {
                                    if let Err(e) = file.write_all(&content) {
                                        eprintln!("Failed to write package file: {}", e);
                                        process::exit(1);
                                    }
                                    // Install downloaded package
                                    if let Err(e) = handle_install_package(&temp_path, None) {
                                        eprintln!("Failed to install package: {}", e);
                                        process::exit(1);
                                    }
                                    // Clean up
                                    let _ = fs::remove_file(&temp_path);
                                    println!("Package {} installed successfully", exact_package);
                                }
                            }
                        } else {
                            eprintln!("Failed to download package: HTTP {}", response.status());
                            process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to download package: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                eprintln!("Package not found in database");
                process::exit(1);
            }
        }
    } else if matches.get_flag("update") {
        require_root("installing patches");
        println!("Checking for updates...");
        let updates = database.check_updates();

        if updates.is_empty() {
            println!("All packages are up to date!");
        } else {
            println!("Updates available:");
            for (name, current, latest) in &updates {
                println!("{}: {} -> {}", name, current, latest);
            }

            println!("\nInstalling updates...");
            for (name, _, _) in updates {
                match handle_install_package(&name, None) {
                    Ok(_) => println!("Updated {}", name),
                    Err(e) => eprintln!("Failed to update {}: {}", name, e),
                }
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
        if let Err(e) = handle_publish_package(package_file, &database, &mut config) {
            eprintln!("Failed to publish package: {}", e);
            process::exit(1);
        }
    } else if let Some(package_file) = matches.get_one::<String>("unpublish") {
        if let Err(e) = handle_remove_package(package_file, &database, &mut config) {
            eprintln!("Failed to remove package: {}", e);
            process::exit(1);
        }
    } else {
        println!("Use -h or --help for usage information.");
    }
}
