use crate::lock::Lock;
use base64::Engine;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

pub struct Database {
    src: String,
    entries: HashMap<String, String>,
}

impl Database {
    pub fn new() -> Self {
        Self {
            src: "https://github.com/barely-a-dev/spm_repo".to_string(),
            entries: HashMap::new(),
        }
    }

    pub fn from_src(src: String) -> Option<Self> {
        if !reqwest::blocking::get(&src).is_ok() {
            return None;
        }
        Some(Self {
            src,
            entries: HashMap::new(),
        })
    }
    pub fn load(&mut self) -> Result<(), Box<dyn Error>> {
        let path = PathBuf::from("/var/lib/spm/spm.db");

        if !path.exists() {
            File::create(&path)?;
            self.update_db()?;
        } else {
            let contents = fs::read_to_string(&path)?;
            for line in contents.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 {
                    self.entries
                        .insert(parts[0].to_string(), parts[1].to_string());
                }
            }
        }
        Ok(())
    }

    pub fn search(&self, query: String) -> Option<Vec<String>> {
        let query = query.to_lowercase();
        let matches: Vec<String> = self
            .entries
            .keys()
            .filter(|key| {
                let key_lower = key.to_lowercase();
                key_lower.contains(&query) || query.contains(&key_lower)
            })
            .cloned()
            .collect();

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    pub fn list_all(&self) -> Option<Vec<String>> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.keys().cloned().collect())
        }
    }

    pub fn update_db(&mut self) -> Result<(), Box<dyn Error>> {
        let _lock = Lock::new("db")?;
        let client = reqwest::blocking::Client::new();
        let parts: Vec<&str> = self.src.split('/').collect();
        let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);
        let api_url = format!("https://api.github.com/repos/{}/{}/contents", owner, repo);

        let response = client
            .get(&api_url)
            .header("User-Agent", "spm-client")
            .send()?;

        let content: Value = response.json()?;

        // Clear existing entries
        self.entries.clear();

        // Parse the JSON response and extract file names
        if let Some(files) = content.as_array() {
            for file in files {
                if let Some(name) = file["name"].as_str() {
                    let package_name = name.trim_end_matches(".spm");

                    // Get version from .ver file
                    let ver_url = format!(
                        "https://api.github.com/repos/{}/{}/contents/{}.ver",
                        owner, repo, package_name
                    );

                    if let Ok(ver_response) = client
                        .get(&ver_url)
                        .header("User-Agent", "spm-client")
                        .send()
                    {
                        if let Ok(ver_content) = ver_response.json::<Value>() {
                            if let Some(content) = ver_content["content"].as_str() {
                                // GitHub API returns base64 encoded content
                                if let Ok(decoded) = base64::engine::general_purpose::STANDARD
                                    .decode(content.replace('\n', ""))
                                {
                                    if let Ok(version) = String::from_utf8(decoded) {
                                        let version = version.trim();
                                        self.entries
                                            .insert(package_name.to_string(), version.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Save to disk
        let path = PathBuf::from("/var/lib/spm/spm.db");

        let mut file = File::create(&path)?;
        for (name, version) in &self.entries {
            writeln!(file, "{}:{}", name, version)?;
        }

        Ok(())
    }

    pub fn exact_search(&self, query: String) -> Option<String> {
        self.entries.get(&query).map(|_| query)
    }
    pub fn check_updates(&self, cache: &Cache) -> Vec<(String, String, String)> {
        // Returns (name, current_version, available_version)
        let mut updates = Vec::new();
        let client = reqwest::blocking::Client::new();

        for (package, _) in &self.entries {
            let current_version = cache.get_version(package.to_string()).unwrap_or("fail".to_string());
            let b = current_version.parse::<bool>();
            if b.is_err() || b.unwrap() {
                let parts: Vec<&str> = self.src.split('/').collect();
                //println!("DEBUG: {:#?}", parts);
                let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

                // Get version from .ver file
                let ver_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/{}.ver",
                    owner, repo, package
                );

                //println!("DEBUG: {}", ver_url);

                if let Ok(ver_response) = client
                    .get(&ver_url)
                    .header("User-Agent", "spm-client")
                    .send()
                {
                    //println!("DEBUG: ver_response success");
                    if let Ok(ver_content) = ver_response.json::<Value>() {
                        //println!("DEBUG: ver_cont success");
                        if let Some(content) = ver_content["content"].as_str() {
                            //println!("DEBUG: got cont");
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD
                                .decode(content.replace('\n', ""))
                            {
                                //println!("DEBUG: decoded");
                                if let Ok(latest_version) = String::from_utf8(decoded) {
                                    //println!("DEBUG: got ver full");
                                    let latest_version = latest_version.trim();
                                    if latest_version != current_version {
                                        //println!("DEBUG: {}!={}", latest_version, current_version);
                                        updates.push((
                                            format!("{}.spm", package), // Add .spm extension
                                            current_version.clone(),
                                            latest_version.to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        updates
    }
    pub fn src(&self) -> &String {
        &self.src
    }
}

#[derive(Clone)]
pub struct FileState {
    pub content: Option<Vec<u8>>, // Original content of the file
    pub permissions: Option<u32>, // Original permissions
}

pub struct PackageState {
    pub installed_files: Vec<String>, // Files installed by the package
    pub removed_files: HashMap<String, FileState>, // Files removed by the package
    pub emptied_files: HashMap<String, FileState>, // Files emptied by the package
    pub patched_files: HashMap<String, FileState>, // Original state of patched files
    pub version: String,              // Package version
}

pub struct Cache {
    packages: HashMap<String, PackageState>,
}

impl Cache {
    pub fn load() -> Self {
        let mut cache = Cache {
            packages: HashMap::new(),
        };

        let path = PathBuf::from("/var/cache/spm/spm.cache");
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                for line in contents.lines() {
                    if let Some((package_info, state_info)) = line.split_once('=') {
                        let parts: Vec<&str> = package_info.split('&').collect();
                        let package_name = parts[0].to_string();
                        let version = parts[1].to_string();

                        let mut state = PackageState {
                            installed_files: Vec::new(),
                            removed_files: HashMap::new(),
                            emptied_files: HashMap::new(),
                            patched_files: HashMap::new(),
                            version,
                        };

                        // Parse sections separated by semicolons
                        for section in state_info.split(';') {
                            if section.is_empty() {
                                continue;
                            }

                            let (section_type, data) = section.split_once(':').unwrap_or(("", ""));
                            match section_type {
                                "installed" => {
                                    state.installed_files = parse_file_list(data);
                                }
                                "removed" => {
                                    state.removed_files = parse_file_states(data);
                                }
                                "emptied" => {
                                    state.emptied_files = parse_file_states(data);
                                }
                                "patched" => {
                                    state.patched_files = parse_file_states(data);
                                }
                                _ => {}
                            }
                        }

                        cache.packages.insert(package_name, state);
                    }
                }
            }
        }
        cache
    }

    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let _lock = Lock::new("cache")?;
        let path = PathBuf::from("/var/cache/spm/spm.cache");
        let mut file = File::create(&path)?;

        for (package_name, state) in &self.packages {
            // Write package name and version
            write!(file, "{}&{}=", package_name, state.version)?;

            // Write installed files
            if !state.installed_files.is_empty() {
                write!(file, "installed:")?;
                write_file_list(&mut file, &state.installed_files)?;
                write!(file, ";")?;
            }

            // Write removed files
            if !state.removed_files.is_empty() {
                write!(file, "removed:")?;
                write_file_states(&mut file, &state.removed_files)?;
                write!(file, ";")?;
            }

            // Write emptied files
            if !state.emptied_files.is_empty() {
                write!(file, "emptied:")?;
                write_file_states(&mut file, &state.emptied_files)?;
                write!(file, ";")?;
            }

            // Write patched files
            if !state.patched_files.is_empty() {
                write!(file, "patched:")?;
                write_file_states(&mut file, &state.patched_files)?;
                write!(file, ";")?;
            }

            writeln!(file)?;
        }

        Ok(())
    }

    // pub fn add_file_state(
    //     &mut self,
    //     package: &str,
    //     file_path: String,
    //     state_type: &str,
    //     content: Option<Vec<u8>>,
    //     permissions: Option<u32>,
    // ) {
    //     let package_state =
    //         self.packages
    //             .entry(package.to_string())
    //             .or_insert_with(|| PackageState {
    //                 installed_files: Vec::new(),
    //                 removed_files: HashMap::new(),
    //                 emptied_files: HashMap::new(),
    //                 patched_files: HashMap::new(),
    //                 version: "0.0.0".to_string(),
    //             });

    //     let file_state = FileState {
    //         content,
    //         permissions,
    //     };

    //     match state_type {
    //         "removed" => {
    //             package_state.removed_files.insert(file_path, file_state);
    //         }
    //         "emptied" => {
    //             package_state.emptied_files.insert(file_path, file_state);
    //         }
    //         "patched" => {
    //             package_state.patched_files.insert(file_path, file_state);
    //         }
    //         _ => {}
    //     }
    // }

    // Get package state by name
    pub fn get_package(&self, package_name: &str) -> Option<&PackageState> {
        self.packages.get(package_name)
    }

    // Update package version
    // pub fn set_package_version(&mut self, package_name: &str, version: String) {
    //     if let Some(package_state) = self.packages.get_mut(package_name) {
    //         package_state.version = version;
    //     }
    // }

    // // Add an installed file to a package
    // pub fn add_installed_file(&mut self, package_name: &str, file_path: String) {
    //     let package_state = self
    //         .packages
    //         .entry(package_name.to_string())
    //         .or_insert_with(|| PackageState {
    //             installed_files: Vec::new(),
    //             removed_files: HashMap::new(),
    //             emptied_files: HashMap::new(),
    //             patched_files: HashMap::new(),
    //             version: "0.0.0".to_string(),
    //         });

    //     if !package_state.installed_files.contains(&file_path) {
    //         package_state.installed_files.push(file_path);
    //     }
    // }

    // Remove a package and its state from the cache
    // pub fn remove_package(&mut self, package_name: &str) {
    //     self.packages.remove(package_name);
    // }

    // Check if a package exists in the cache
    pub fn has_package(&self, package_name: &str) -> bool {
        self.packages.contains_key(package_name)
    }

    // Get all package names in the cache
    pub fn list_installed(&self) -> Vec<String> {
        self.packages.keys().cloned().collect()
    }

    // Clear all package states
    // pub fn clear(&mut self) {
    //     self.packages.clear();
    // }

    // Get the number of tracked packages
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    pub fn get_version(&self, name: String) -> Option<String> {
        return self.get_package(&name).map(|s| s.version.clone());
    }

    pub fn get_installed_files(&self, name: String) -> Option<Vec<String>> {
        return self.get_package(&name).map(|s| s.installed_files.clone());
    }

    pub fn add(&mut self, name: String, state: PackageState) {
        self.packages.insert(name, state);
    }

    pub fn remove(&mut self, name: &str) -> Option<PackageState> {
        self.packages.remove(name)
    }
}

// Helper functions for serialization/deserialization
fn parse_file_list(data: &str) -> Vec<String> {
    data.trim_matches(|c| c == '[' || c == ']')
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect()
}

fn parse_file_states(data: &str) -> HashMap<String, FileState> {
    let mut states = HashMap::new();
    if data.is_empty() {
        return states;
    }

    // Remove the outer brackets
    let content = data.trim_matches(|c| c == '[' || c == ']');

    // Split by semicolon to get individual file entries
    for entry in content.split(';') {
        if entry.is_empty() {
            continue;
        }

        // Find the position of the opening brace
        if let Some(brace_pos) = entry.find('{') {
            let path = entry[..brace_pos].to_string();
            let state_data = &entry[brace_pos + 1..entry.len() - 1];

            // Split the content and permissions
            let parts: Vec<&str> = state_data.split(',').collect();

            let content = if !parts[0].is_empty() {
                base64::engine::general_purpose::STANDARD
                    .decode(parts[0])
                    .ok()
            } else {
                None
            };

            let permissions = if parts.len() > 1 && !parts[1].is_empty() {
                parts[1].parse().ok()
            } else {
                None
            };

            states.insert(
                path,
                FileState {
                    content,
                    permissions,
                },
            );
        }
    }

    states
}

fn write_file_list(file: &mut File, files: &[String]) -> Result<(), Box<dyn Error>> {
    write!(file, "[")?;
    for (i, path) in files.iter().enumerate() {
        if i > 0 {
            write!(file, ",")?;
        }
        write!(file, "\"{}\"", path)?;
    }
    write!(file, "]")?;
    Ok(())
}

fn write_file_states(
    file: &mut File,
    states: &HashMap<String, FileState>,
) -> Result<(), Box<dyn Error>> {
    write!(file, "[")?;
    for (i, (path, state)) in states.iter().enumerate() {
        if i > 0 {
            write!(file, ";")?;
        }
        write!(file, "{}{{", path)?;
        if let Some(content) = &state.content {
            write!(
                file,
                "{},",
                base64::engine::general_purpose::STANDARD.encode(content)
            )?;
        } else {
            write!(file, ",")?;
        }
        if let Some(perms) = state.permissions {
            write!(file, "{}", perms)?;
        }
        write!(file, "}}")?;
    }
    write!(file, "]")?;
    Ok(())
}
