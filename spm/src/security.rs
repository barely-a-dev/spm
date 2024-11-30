use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::fs;

use spm_lib::lock::Lock;

pub struct Security {}

impl Security {
    pub fn encrypt_and_save_token(token: String, key: &str) -> std::io::Result<()> {
        let _lock = Lock::new("token_enc").expect("Failed to lock token file");
        let mc = new_magic_crypt!(key, 256);
        let encrypted = mc.encrypt_str_to_base64(token);
        let mut tokenfile = dirs::home_dir().expect("Failed to get home directory");
        tokenfile.push(".spm.token.encrypted");
        fs::write(
            tokenfile,
            encrypted,
        )?;
        Ok(())
    }

    pub fn read_encrypted_token(key: &str) -> std::io::Result<String> {
        let mc = new_magic_crypt!(key, 256);
        let mut tokenfile = dirs::home_dir().expect("Failed to get home directory");
        tokenfile.push(".spm.token.encrypted");
        let encrypted = fs::read_to_string(
            tokenfile
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

                match crate::helpers::validate_token(&token) {
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

    pub fn reset_token() -> Result<(), Box<dyn std::error::Error>> {
        let mut tokenfile = dirs::home_dir().expect("Failed to get home directory");
        tokenfile.push(".spm.token.encrypted");

        // Only try to remove the file if it exists
        if tokenfile.exists() {
            fs::remove_file(&tokenfile)?;
        }

        let token = rpassword::prompt_password("Enter your token: ")?;
        let token = token.trim().to_string();

        match crate::helpers::validate_token(&token) {
            Ok(_) => {
                let password = rpassword::prompt_password("Create your password: ")?;
                Security::encrypt_and_save_token(token, &password)?;
                Ok(())
            }
            Err(e) => {
                println!("Invalid token: {}", e);
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid token format",
                )))
            }
        }
    }
}
