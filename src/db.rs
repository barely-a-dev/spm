use base64::Engine;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;

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
        let mut path = dirs::home_dir().ok_or("Cannot find home directory")?;
        path.push(".spm.db");

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
                        owner,
                        repo,
                        package_name
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
        let mut path = dirs::home_dir().ok_or("Cannot find home directory")?;
        path.push(".spm.db");

        let mut file = File::create(&path)?;
        for (name, version) in &self.entries {
            writeln!(file, "{}:{}", name, version)?;
        }

        Ok(())
    }

    pub fn exact_search(&self, query: String) -> Option<String> {
        // Remove the unused variable by directly cloning the query
        self.entries.get(&query).map(|_| query)
    }

    pub fn check_updates(&self) -> Vec<(String, String, String)> {
        // Returns (name, current_version, available_version)
        let mut updates = Vec::new();
        let client = reqwest::blocking::Client::new();

        for (package, current_version) in &self.entries {
            let parts: Vec<&str> = self.src.split('/').collect();
            let (owner, repo) = (parts[parts.len() - 2], parts[parts.len() - 1]);

            let api_url = format!(
                "https://api.github.com/repos/{}/{}/contents/{}.spm",
                owner, repo, package
            );

            if let Ok(response) = client
                .get(&api_url)
                .header("User-Agent", "spm-client")
                .send()
            {
                if let Ok(content) = response.json::<Value>() {
                    if let Some(latest_version) = content["version"].as_str() {
                        if latest_version != current_version {
                            updates.push((
                                package.clone(),
                                current_version.clone(),
                                latest_version.to_string(),
                            ));
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
