use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::fs;
use std::path::PathBuf;

use crate::helpers;

pub struct Security {}

impl Security {
    pub fn encrypt_and_save_token(token: String, key: &str) -> std::io::Result<()> {
        let mc = new_magic_crypt!(key, 256);
        let encrypted = mc.encrypt_str_to_base64(token);
        fs::write(
            PathBuf::from("~/.spm.token.encrypted")
                .canonicalize()
                .unwrap_or("/root/.spm.token.encrypted".into()),
            encrypted,
        )?;
        Ok(())
    }

    pub fn read_encrypted_token(key: &str) -> std::io::Result<String> {
        let mc = new_magic_crypt!(key, 256);
        let encrypted = fs::read_to_string(
            PathBuf::from("~/.spm.token.encrypted")
                .canonicalize()
                .unwrap_or("/root/.spm.token.encrypted".into()),
        );

        match encrypted {
            Ok(encrypted_str) => match mc.decrypt_base64_to_string(&encrypted_str) {
                Ok(decrypted) => Ok(decrypted),
                Err(_) => {
                    println!("Failed to decrypt token. Password might be incorrect.");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Failed to decrypt token",
                    ))
                }
            },
            Err(_) => {
                println!("Github token file not found. Please set your token:");
                let token = rpassword::prompt_password("Enter token: ")?;
                let token = token.trim().to_string();

                match helpers::validate_token(&token) {
                    Ok(_) => {
                        let password = rpassword::prompt_password("Create your password: ")
                            .map_err(|e| {
                                std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("Failed to read password: {}", e),
                                )
                            })?;

                        Security::encrypt_and_save_token(token.clone(), &password)?;
                        Ok(token)
                    }
                    Err(e) => {
                        println!("Invalid token: {}", e);
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Invalid token format",
                        ))
                    }
                }
            }
        }
    }

    pub fn reset_token() {
        let tokenfile = PathBuf::from(
            PathBuf::from("~/.spm.token.encrypted")
                .canonicalize()
                .unwrap_or("/root/.spm.token.encrypted".into()),
        )
        .canonicalize()
        .unwrap_or("/root/.spm.token.encrypted".into());

        fs::remove_file(tokenfile).expect("Failed to remove existing token file.");
        let password = rpassword::prompt_password("Create your password: ").expect("Failed to read token password, aborting. Your GH token was removed from the configuration");
        let token =
            rpassword::prompt_password("Enter your token: ").expect("Failed to read token.");
        Security::encrypt_and_save_token(token, &password).expect("Failed to save token");
    }
}
