use crate::lock::Lock;
use crate::security::Security;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::process::exit;
use std::{error::Error, path::PathBuf};

#[derive(Deserialize)]
pub struct PackageConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub file_permissions: Option<HashMap<String, u32>>,
    pub files_to_remove: Option<Vec<String>>,
    pub files_to_empty: Option<Vec<String>>,
    pub install_dirs: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct Config {
    settings: HashMap<String, String>,
    path: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn Error>> {
        let mut path = dirs::home_dir().ok_or("Cannot find home directory")?;
        path.push(".spm.conf");

        let mut settings = HashMap::new();
        if !path.exists() {
            let mut file = File::create(&path)?;
            file.write_all(b"net_enabled=true\n")?;
            settings.insert("net_enabled".to_string(), "true".to_string());
        } else {
            let contents = fs::read_to_string(&path)?;
            for line in contents.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    settings.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }
        let mut new = Config { settings, path };
        new.update();
        Ok(new)
    }

    pub fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn Error>> {
        self.settings.insert(key.to_string(), value);
        self.save()?;
        Ok(())
    }

    pub fn update(&mut self) {
        if let Some(token) = self.get_github_token_dep() {
            _ = self.settings.remove("github_token");
            match self.save() {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Failed to save new config file without token: {e}. Please run the program as root.");
                    exit(1)
                }
            }
            println!("The program was recently updated to store GH tokens in a more secure manner. You must now set a password for your token.");
            let password = rpassword::prompt_password("Create your password: ").expect("Failed to read token password, aborting. Your GH token was removed from the configuration");
            Security::encrypt_and_save_token(token, &password).expect("Failed to save token");
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        let _lock = Lock::new("conf")?;

        let mut contents = String::new();
        for (key, value) in &self.settings {
            contents.push_str(&format!("{}={}\n", key, value));
        }
        fs::write(&self.path, contents)?;

        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.settings.get(key).clone().cloned()
    }

    pub fn get_github_token_dep(&self) -> Option<String> {
        self.get("github_token")
    }

    pub fn get_github_token(&self) -> Option<String> {
        for i in 0..3 {
            if let Some(token) = Self::get_token_internal(3 - i) {
                return Some(token);
            }
        }
        None
    }
    pub fn get_token_internal(attempts_remaining: u8) -> Option<String> {
        let password = rpassword::prompt_password("Enter your token password: ")
            .expect("Failed to read password, aborting.");
        match Security::read_encrypted_token(&password) {
            Ok(s) => {
                println!("Valid token found");
                Some(s)
            }
            Err(e) => {
                eprintln!(
                    "Failed to read encrypted token: {e}. {} attempts remaining.",
                    attempts_remaining - 1
                );
                None
            }
        }
    }
}
