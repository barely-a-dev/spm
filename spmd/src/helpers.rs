use spm_lib::db::Database;
use crate::handlers::*;
use spm_lib::patch::Patch;
use spm_lib::config::Config;
use spm_lib::security::Security;
use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::io::stdin;
use std::io::Write;
use std::process::exit;
use std::{
    error::Error,
    fs::{self},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
};
use spm_lib::helpers::prefer_root;

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
    } else if let Some(mut a) = matches.get_many::<String>("fetch") {
        let package: Option<&String> = a.next();
        let output_dir: Option<&String> = a.next();
        let req_ver: Option<String> = a.next().cloned();
        if let (Some(p), Some(o)) = (package, output_dir) {
            download(&database, p, o, &req_ver, None).expect("Failed to download package.");
        }
    } else if let Some(package_file) = matches.get_one::<String>("publish") {
        let (_, _, _, _token_lock) =
            prefer_root("publish a package", matches.get_flag("force-op"), false, false, false, true);
        if let Err(e) = handle_publish_package(package_file, &database, config) {
            eprintln!("Failed to publish package: {}", e);
            process::exit(1);
        }
    } else if let Some(info) = matches.get_many::<String>("unpublish") {
        let (_, _, _, _token_lock) =
            prefer_root("unpublish packages", matches.get_flag("force-op"), false, false, false, true);
        let (packages, vers) = split_values(info);
        let mut pas_vers: Option<Vec<String>> = None;
        if vers.len() > 0 {
            pas_vers = Some(vers);
        }
        if let Err(e) = handle_remove_package(
            packages.get(0).expect("You must provide one package name"),
            &database,
            pas_vers,
            config,
        ) {
            eprintln!("Failed to remove package: {}", e);
            process::exit(1);
        }
    } else if let Some(output) = matches.get_one::<String>("mirror-repo") {
        let (_lock, _, _, _) =
            prefer_root("mirror the repository", matches.get_flag("force-op"), true, false, false, false);
        database.update_db().expect("Failed to update databse");
        let packages = database
            .list_all()
            .expect("Failed to retrieve package list");

        for pack in packages {
            for ver in database.get_vers(&pack) {
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

pub fn format_f(filename: &str, database: &Database, ver: &Option<String>) -> String {
    remove_ver(filename.split('/').last().unwrap_or("unnamed_f"))
        .trim_end_matches(".spm")
        .to_owned()
        + "%26"
        + ver
            .as_ref()
            .unwrap_or(&database.get_recent(filename).unwrap_or("None".into()))
}
