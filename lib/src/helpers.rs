use std::error::Error;
use std::io::Read;
use std::io::Write;
use base64::Engine;
use std::env;
use std::collections::HashMap;
use crate::db::FileState;
use std::fs::File;

pub fn get_real_user() -> Result<((u32, String), u32), Box<dyn Error>> {
    unsafe {
        let uid = libc::getuid();
        let user = env::var("SUDO_USER").unwrap_or("user".to_string());
        let gid = libc::getgid();
        Ok(((uid, user), gid))
    }
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn write_varint<W: Write>(writer: &mut W, mut value: u32) -> Result<(), Box<dyn Error>> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }

    Ok(())
}

pub fn read_varint<R: Read>(reader: &mut R) -> Result<u32, Box<dyn Error>> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8];
        reader.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7F) as u32) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

// Helper functions for serialization/deserialization
pub fn parse_file_list(data: &str) -> Vec<String> {
    data.trim_matches(|c| c == '[' || c == ']')
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .collect()
}

pub fn parse_file_states(data: &str) -> HashMap<String, FileState> {
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

pub fn write_file_list(file: &mut File, files: &[String]) -> Result<(), Box<dyn Error>> {
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

pub fn write_file_states(
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
