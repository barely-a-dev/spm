mod config;
mod conversion;
mod db;
mod handlers;
mod helpers;
mod lock;
mod package;
mod patch;
mod security;

use crate::config::{Config, PackageConfig};
use clap::{Arg, ArgAction, Command as ClapCommand};
use db::Cache;
use package::Package;
use security::Security;
use std::process;

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
        .version("3.14.26")
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
                .long("install-pack")
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
                .num_args(1..)
                .value_name("PACKAGE"),
        )
        .arg(
            Arg::new("fetch")
                .short('F')
                .long("fetch")
                .help("Fetch a package from the database")
                .num_args(2)
                .value_names(["PACKAGE_NAME", "OUTPUT_FILE"]),
        )
        .arg(
            Arg::new("update")
                .short('U')
                .long("update")
                .help("Check for and install package updates")
                .num_args(0..)
                .value_name("PACKAGE_NAME")
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
        .arg(
            Arg::new("statistics")
                .short('S')
                .long("stats")
                .help("List installed packages and their files. Optionally specify a package name")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("mass-package")
                .short('m')
                .long("mass-pack")
                .help("Package every file in IN_DIR into its own package, placing the package files in OUT_DIR")
                .num_args(2)
                .value_names(["IN_DIR", "OUT_DIR"])
        )
        .arg(
            Arg::new("version")
                .short('1')
                .long("ver")
                .help("Use this version during package creation instead of asking for it or using the ver in the filename")
                .num_args(1)
                .value_name("VERSION")
        )
        .arg(
            Arg::new("convert-file")
                .short('n')
                .long("convert")
                .help("Convert another package manager's package file to an SPM package")
                .num_args(2)
                .value_names(["IN_FILE", "OUT_FILE"])
        )
        .arg(
            Arg::new("mirror-repo")
                .long("mirror")
                .help("Mirrors the contents of the entire current package repository into the specified directory")
                .num_args(1)
                .value_name("OUTPUT_DIR")
        )
        .arg(
            Arg::new("reset-token")
                .long("rtok")
                .help("Reset your token")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("force-op")
                .short('o')
                .long("force")
                .help("Force a dangerous operation without user input, such as installing packages without root")
                .action(ArgAction::SetTrue)
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
