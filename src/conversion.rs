use ar::Archive;
use std::io::Read;
use std::path::Path;
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;
use crate::package::Package;
use std::path::PathBuf;
use std::fs::File;
use std::error::Error;
use flate2::read::GzDecoder;
use rpm::Package as RPMPackage;

pub fn convert_deb_to_spm(deb_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut package = Package::new();
    let deb_file = File::open(deb_path)?;
    let mut archive = Archive::new(deb_file);

    // Process control.tar.xz and data.tar.xz from .deb
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry?;
        match entry.header().identifier() {
            b"control.tar.xz" => {
                let mut control_data = Vec::new();
                entry.read_to_end(&mut control_data)?;
                process_control_data(&mut package, &control_data)?;
            }
            b"data.tar.xz" => {
                let mut package_data = Vec::new();
                entry.read_to_end(&mut package_data)?;
                process_package_data(&mut package, &package_data)?;
            }
            _ => continue,
        }
    }

    // Save as SPM package
    package.save_package(output_path)?;
    Ok(())
}

fn process_control_data(package: &mut Package, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let decoder = XzDecoder::new(data);
    let mut archive = TarArchive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().path()?.to_string_lossy() == "./control" {
            let mut control_content = String::new();
            entry.read_to_string(&mut control_content)?;
            
            // Parse control file for package metadata
            for line in control_content.lines() {
                if line.starts_with("Package: ") {
                    package.name = line[9..].trim().to_string();
                } else if line.starts_with("Version: ") {
                    package.version = line[9..].trim().to_string();
                }
            }
        }
    }
    Ok(())
}

fn process_package_data(package: &mut Package, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let decoder = XzDecoder::new(data);
    let mut archive = TarArchive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let mode = entry.header().mode()?;
        
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        // Skip directories
        if entry.header().entry_type().is_dir() {
            continue;
        }

        package.add_file(
            entry.path()?.strip_prefix(".")?.to_path_buf(),
            mode as u32,
            contents,
            None
        );
    }
    Ok(())
}

// Convert RPM to SPM
pub fn _convert_rpm_to_spm(rpm_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut package = Package::new();
    let rpm_package = RPMPackage::open(&rpm_path)?;

    // Extract metadata
    package.name = rpm_package.metadata.get_name().unwrap().to_string();
    package.version = rpm_package.metadata.get_version().unwrap().to_string();

    // Process payload (TODO: is raw data of file in u8 bytes (entry = byte))
    for _entry in rpm_package.content {
        
    }

    // Save as SPM package
    package.save_package(output_path)?;
    Ok(())
}

// Convert tar.gz to SPM
pub fn convert_targz_to_spm(targz_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut package = Package::new();
    let file = File::open(targz_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = TarArchive::new(gz);

    // Try to get name/version from filename
    if let Some(filename) = targz_path.file_name() {
        let filename = filename.to_string_lossy();
        if let Some(name_end) = filename.find(".tar.gz") {
            let name = &filename[..name_end];
            // Simple version extraction, could be made more sophisticated
            if let Some(ver_idx) = name.rfind('-') {
                package.name = name[..ver_idx].to_string();
                package.version = name[ver_idx + 1..].to_string();
            } else {
                package.name = name.to_string();
                package.version = "1.0.0".to_string();
            }
        }
    }

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mode = entry.header().mode()?;
        
        // Skip directories
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        package.add_file(
            path,
            mode as u32,
            contents,
            None
        );
    }

    package.save_package(output_path)?;
    Ok(())
}

// Convert ZIP to SPM
pub fn convert_zip_to_spm(zip_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut package = Package::new();
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // Try to get name/version from filename
    if let Some(filename) = zip_path.file_name() {
        let filename = filename.to_string_lossy();
        if let Some(name_end) = filename.find(".zip") {
            let name = &filename[..name_end];
            if let Some(ver_idx) = name.rfind('-') {
                package.name = name[..ver_idx].to_string();
                package.version = name[ver_idx + 1..].to_string();
            } else {
                package.name = name.to_string();
                package.version = "1.0.0".to_string();
            }
        }
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }

        let path = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        // Use a default mode of 644 for files from ZIP since ZIP doesn't store Unix permissions
        let mode = 0o644;

        package.add_file(
            path,
            mode,
            contents,
            None
        );
    }

    package.save_package(output_path)?;
    Ok(())
}

pub fn detect_file_type(path: &str) -> anyhow::Result<Option<String>> {
    // First try magic numbers
    if let Some(file_type) = detect_file_type_a(path)? {
        return Ok(Some(file_type));
    }

    // Fallback to extension checking
    let path = PathBuf::from(path);
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            "deb" => return Ok(Some("deb".to_string())),
            "rpm" => return Ok(Some("rpm".to_string())),
            "zip" => return Ok(Some("zip".to_string())),
            "gz" => {
                // Check if it's a tar.gz
                if path.to_str()
                    .map(|s| s.to_lowercase().ends_with(".tar.gz"))
                    .unwrap_or(false) 
                {
                    return Ok(Some("tar.gz".to_string()));
                }
            }
            _ => {}
        }
    }
    
    Ok(None)
}

pub fn detect_file_type_a(path: &str) -> anyhow::Result<Option<String>>
{
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 8]; // We'll read first 8 bytes
    
    // Read the first few bytes of the file
    let bytes_read = file.read(&mut buffer)?;
    if bytes_read < 4 {
        return Ok(None);
    }

    // Check for deb package
    // Debian packages start with "!<arch>" signature
    if bytes_read >= 7 && &buffer[0..7] == b"!<arch>" {
        return Ok(Some("deb".to_string()));
    }

    // Check for RPM package
    // RPM files start with 0xED 0xAB 0xEE 0xDB
    if bytes_read >= 4 && buffer[0] == 0xED && buffer[1] == 0xAB && 
       buffer[2] == 0xEE && buffer[3] == 0xDB {
        return Ok(Some("rpm".to_string()));
    }

    // Check for gzip (including tar.gz)
    // Gzip files start with 0x1F 0x8B
    if bytes_read >= 2 && buffer[0] == 0x1F && buffer[1] == 0x8B {
        return Ok(Some("tar.gz".to_string()));
    }

    // Check for ZIP
    // ZIP files start with "PK\x03\x04"
    if bytes_read >= 4 && buffer[0] == 0x50 && buffer[1] == 0x4B && 
       buffer[2] == 0x03 && buffer[3] == 0x04 {
        return Ok(Some("zip".to_string()));
    }

    Ok(None)
}
 