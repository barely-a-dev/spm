mod handlers;
mod helpers;
use spm_lib::config::Config;
use clap::{Arg, ArgAction, Command as ClapCommand};
use spm_lib::db::Cache;
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
        spm_lib::db::Database::from_src(s).unwrap_or(spm_lib::db::Database::new())
    } else {
        spm_lib::db::Database::new()
    };
    for src in config.get_many("extra_repos")
    {
        database.srcs_mut().push(src);
    }
    let mut cache = Cache::load();
    database.load().expect("Failed to load database");
    let matches = ClapCommand::new("SPM")
        .version("3.15.29")
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
            Arg::new("update")
                .short('U')
                .long("update")
                .help("Check for and install package updates")
                .num_args(0..)
                .value_name("PACKAGE_NAME")
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
