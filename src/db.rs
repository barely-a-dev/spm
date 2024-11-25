use base64::Engine;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use crate::lock::Lock;

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
    // TODO: Fix? I can't tell if it's broken or not.
    pub fn check_updates(&self) -> Vec<(String, String, String)> {
        // Returns (name, current_version, available_version)
        let mut updates = Vec::new();
        let client = reqwest::blocking::Client::new();

        for (package, current_version) in &self.entries {
            let parts: Vec<&str> = self.src.split('/').collect();
            let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

            // Get version from .ver file
            let ver_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}.ver",
                owner, repo, package
            );

            if let Ok(ver_response) = client
                .get(&ver_url)
                .header("User-Agent", "spm-client")
                .send()
            {
                if let Ok(ver_content) = ver_response.json::<Value>() {
                    if let Some(content) = ver_content["content"].as_str() {
                        if let Ok(decoded) = base64::engine::general_purpose::STANDARD
                            .decode(content.replace('\n', ""))
                        {
                            if let Ok(latest_version) = String::from_utf8(decoded) {
                                let latest_version = latest_version.trim();
                                if latest_version != current_version {
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
        updates
    }
    pub fn src(&self) -> &String {
        &self.src
    }
}

pub struct Cache {
    installed_packages: HashMap<String, Vec<String>>, // Hashmap key is pkg names, Vec is installed files
}
// TODO: make it store not just installed files and remove them, but also removed files and their contents, emptied files and theirs, files before patches to restore them
impl Cache {
    pub fn load() -> Self {
        let mut cache = Cache {
            installed_packages: HashMap::new(),
        };

        let path = PathBuf::from("/var/cache/spm/spm.cache");
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                for line in contents.lines() {
                    if let Some((package, files_str)) = line.split_once('=') {
                        // Remove the brackets and split by commas
                        let files_str = files_str.trim_start_matches('[').trim_end_matches(']');
                        let files: Vec<String> = files_str
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').to_string())
                            .collect();

                        cache.installed_packages.insert(package.to_string(), files);
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

        for (package, files) in &self.installed_packages {
            let files_str = files
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ");

            writeln!(file, "{}=[{}]", package, files_str)?;
        }
        Ok(())
    }

    pub fn add(&mut self, (package, files): (String, Vec<String>)) {
        self.installed_packages.insert(package, files);
    }

    pub fn get_installed_files(&self, pack: String) -> Option<Vec<String>> {
        self.installed_packages
            .get(&pack)
            .cloned()
    }

    pub fn remove(&mut self, package: &str) -> Option<Vec<String>> {
        self.installed_packages.remove(package)
    }

    pub fn list_installed(&self) -> Vec<String> {
        self.installed_packages.keys().cloned().collect()
    }
}
