mod db;
mod handlers;
mod helpers;
mod lock;
mod package;
mod patch;

use crate::lock::Lock;
use clap::{Arg, ArgAction, Command as ClapCommand};
use db::Cache;
use package::Package;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::{error::Error, fs, path::PathBuf, process};

#[derive(Deserialize)]
struct PackageConfig {
    name: Option<String>,
    version: Option<String>,
    file_permissions: Option<HashMap<String, u32>>,
    files_to_remove: Option<Vec<String>>,
    files_to_empty: Option<Vec<String>>,
    install_dirs: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
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
        let _lock = Lock::new("conf")?;

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
    let mut cache = Cache::load();
    database.load().expect("Failed to load database");
    let matches = ClapCommand::new("SPM")
        .version("2.5.18")
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
        .arg(
            Arg::new("dev-pub")
                .short('q')
                .long("dev-pub")
                .help("Detect the program type in either . or PROJ_DIR, build it, and publish the output")
                .num_args(0..=1)
                .value_name("PROJ_DIR"),
        )
        .arg(
            Arg::new("uninstall")
                .short('R')
                .long("uninstall")
                .help("Uninstall a package and remove its files")
                .num_args(1)
                .value_name("PACKAGE"),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List installed packages and their files. Optionally specify a package name")
                .num_args(0..=1)
                .value_name("PACKAGE"),
        )
        // .arg(
        //     Arg::new("do-nothing")
        //         .long("wait")
        //         .help("DEBUG FUNCTION")
        //         .num_args(0..=1)
        //         .value_name("WAIT_LEN")
        // )
        // .arg(
        //     Arg::new("lock-test")
        //         .long("lock")
        //         .help("DEBUG FUNCTION")
        //         .action(ArgAction::SetTrue)
        // )
        .disable_version_flag(true)
        .arg(
            Arg::new("print_ver")
                .long("version")
                .help("Print the current version")
                .action(ArgAction::Version)
        )
        .get_matches();

    helpers::get_matches(matches, &mut config, &mut database, &mut cache);
}
