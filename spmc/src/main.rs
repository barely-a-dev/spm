use ar::Archive;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use rpm::Package as RPMPackage;
use spm_lib::package::Package as SPMPackage;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;

fn main() {
    println!("Starting SPM conversion process...");
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);

    if args.len() < 1 {
        eprintln!("ERROR: You must pass at least one argument.");
        exit(1);
    }

    for arg in args {
        let file = PathBuf::from(arg.clone());
        if file.exists() {
            let out = arg.clone() + ".spm";
            println!("Processing file: {}", arg);
            if let Err(e) = convert(&arg, &out) {
                eprintln!("ERROR: Failed to convert file '{}'. Reason: {}", arg, e);
            } else {
                println!("Successfully converted '{}' to '{}'.", arg, out);
            }
        } else {
            eprintln!("ERROR: '{}' does not exist. Please provide a valid file path.", arg);
        }
    }
}

fn convert(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    println!("Detecting file type for '{}'.", input);
    match detect_file_type(input)? {
        Some(file_type) => {
            println!("Detected file type: '{}'.", file_type);
            match file_type.as_str() {
                "deb" => {
                    println!("Starting conversion from DEB to SPM...");
                    convert_deb_to_spm(Path::new(input), Path::new(output))?;
                }
                "rpm" => {
                    println!("RPM conversion is not supported at this time.");
                }
                "tar.gz" => {
                    println!("Starting conversion from TAR.GZ to SPM...");
                    convert_targz_to_spm(Path::new(input), Path::new(output))?;
                }
                "zip" => {
                    println!("Starting conversion from ZIP to SPM...");
                    convert_zip_to_spm(Path::new(input), Path::new(output))?;
                }
                "tar.bz2" => {
                    println!("Starting conversion from TAR.BZ2 to SPM...");
                    convert_tarbz2_to_spm(Path::new(input), Path::new(output))?;
                }
                "tar.xz" => {
                    println!("Starting conversion from TAR.XZ to SPM...");
                    convert_tarxz_to_spm(Path::new(input), Path::new(output))?;
                }
                _ => {
                    eprintln!("ERROR: Unsupported file type: '{}'.", file_type);
                    return Err(format!("Unsupported file type: {}", file_type).into());
                }
            }
        }
        None => {
            eprintln!("ERROR: Unable to detect file type for '{}'.", input);
            return Err("Unable to detect file type".into());
        }
    }
    println!("Finished processing '{}'.", input);
    Ok(())
}

pub fn convert_deb_to_spm(deb_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("Opening DEB file: '{}'.", deb_path.display());
    let mut package = SPMPackage::new();
    let deb_file = File::open(deb_path)?;
    let mut archive = Archive::new(deb_file);

    println!("Extracting DEB contents...");
    while let Some(entry) = archive.next_entry() {
        let mut entry = entry?;
        match entry.header().identifier() {
            b"control.tar.xz" => {
                println!("Processing 'control.tar.xz'...");
                let mut control_data = Vec::new();
                entry.read_to_end(&mut control_data)?;
                process_control_data(&mut package, &control_data)?;
            }
            b"data.tar.xz" => {
                println!("Processing 'data.tar.xz'...");
                let mut package_data = Vec::new();
                entry.read_to_end(&mut package_data)?;
                process_package_data(&mut package, &package_data)?;
            }
            _ => {
                println!("Skipping unknown entry: '{}'.", String::from_utf8_lossy(entry.header().identifier()));
                continue;
            }
        }
    }

    println!("Saving SPM package to '{}'.", output_path.display());
    package.save_package(output_path)?;
    println!("DEB to SPM conversion completed successfully.");
    Ok(())
}

fn process_control_data(package: &mut SPMPackage, data: &[u8]) -> Result<(), Box<dyn Error>> {
    println!("Processing control data for metadata extraction...");

    let decoder = XzDecoder::new(data);
    let mut archive = TarArchive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.header().path()?.to_string_lossy().to_string();

        println!("Examining entry in control data: {}", entry_path);

        if entry_path == "./control" {
            let mut control_content = String::new();
            entry.read_to_string(&mut control_content)?;

            println!("Parsing control file for package metadata...");
            for line in control_content.lines() {
                if line.starts_with("Package: ") {
                    package.name = line[9..].trim().to_string();
                    println!("Found package name: {}", package.name);
                } else if line.starts_with("Version: ") {
                    package.version = line[9..].trim().to_string();
                    println!("Found package version: {}", package.version);
                }
            }
        }
    }

    println!("Control data processing completed successfully.");
    Ok(())
}

fn process_package_data(package: &mut SPMPackage, data: &[u8]) -> Result<(), Box<dyn Error>> {
    println!("Processing package data...");

    let decoder = XzDecoder::new(data);
    let mut archive = TarArchive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_string_lossy().to_string();
        let mode = entry.header().mode()?;

        println!("Processing file: {} (mode: {:o})", entry_path, mode);

        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        // Skip directories
        if entry.header().entry_type().is_dir() {
            println!("Skipping directory: {}", entry_path);
            continue;
        }

        package.add_file(
            entry.path()?.strip_prefix(".")?.to_path_buf(),
            mode as u32,
            contents,
            None,
        );
    }

    println!("Package data processing completed successfully.");
    Ok(())
}

pub fn _convert_rpm_to_spm(rpm_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut package = SPMPackage::new();
    let rpm_package = RPMPackage::open(&rpm_path)?;

    // Extract metadata
    package.name = rpm_package.metadata.get_name().unwrap().to_string();
    package.version = rpm_package.metadata.get_version().unwrap().to_string();

    // Process payload (TODO: is raw data of file in u8 bytes (entry = byte))

    // Save as SPM package
    package.save_package(output_path)?;
    Ok(())
}

pub fn convert_zip_to_spm(zip_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("Converting zip file: {}", zip_path.display());

    let mut package = SPMPackage::new();
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

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
            println!("Detected package name: {}, version: {}", package.name, package.version);
        }
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            println!("Skipping directory in zip: {}", file.name());
            continue;
        }

        let path = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => continue,
        };

        println!("Adding file: {}", path.display());
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let mode = 0o644; // Default mode for ZIP
        package.add_file(path, mode, contents, None);
    }

    println!("Saving package to: {}", output_path.display());
    package.save_package(output_path)?;

    println!("Conversion of zip completed successfully.");
    Ok(())
}

pub fn convert_targz_to_spm(targz_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("Converting tar.gz file: {}", targz_path.display());

    let mut package = SPMPackage::new();
    let file = File::open(targz_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = TarArchive::new(gz);

    if let Some(filename) = targz_path.file_name() {
        let filename = filename.to_string_lossy();
        if let Some(name_end) = filename.find(".tar.gz") {
            let name = &filename[..name_end];
            if let Some(ver_idx) = name.rfind('-') {
                package.name = name[..ver_idx].to_string();
                package.version = name[ver_idx + 1..].to_string();
            } else {
                package.name = name.to_string();
                package.version = "1.0.0".to_string();
            }
            println!("Detected package name: {}, version: {}", package.name, package.version);
        }
    }

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mode = entry.header().mode()?;

        println!("Adding file: {}", path.display());
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        package.add_file(path, mode as u32, contents, None);
    }

    println!("Saving package to: {}", output_path.display());
    package.save_package(output_path)?;

    println!("Conversion of tar.gz completed successfully.");
    Ok(())
}

pub fn convert_tarbz2_to_spm(tarbz2_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("Converting tar.bz2 file: {}", tarbz2_path.display());

    let mut package = SPMPackage::new();
    let file = File::open(tarbz2_path)?;
    let bz = BzDecoder::new(file);
    let mut archive = TarArchive::new(bz);

    if let Some(filename) = tarbz2_path.file_name() {
        let filename = filename.to_string_lossy();
        if let Some(name_end) = filename.find(".tar.bz2") {
            let name = &filename[..name_end];
            if let Some(ver_idx) = name.rfind('-') {
                package.name = name[..ver_idx].to_string();
                package.version = name[ver_idx + 1..].to_string();
            } else {
                package.name = name.to_string();
                package.version = "1.0.0".to_string();
            }
            println!("Detected package name: {}, version: {}", package.name, package.version);
        }
    }

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mode = entry.header().mode()?;

        println!("Adding file: {}", path.display());
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        package.add_file(path, mode as u32, contents, None);
    }

    println!("Saving package to: {}", output_path.display());
    package.save_package(output_path)?;

    println!("Conversion of tar.bz2 completed successfully.");
    Ok(())
}

pub fn convert_tarxz_to_spm(tarxz_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    println!("Converting tar.xz file: {}", tarxz_path.display());

    let mut package = SPMPackage::new();
    let file = File::open(tarxz_path)?;
    let xz = XzDecoder::new(file);
    let mut archive = TarArchive::new(xz);

    if let Some(filename) = tarxz_path.file_name() {
        let filename = filename.to_string_lossy();
        if let Some(name_end) = filename.find(".tar.xz") {
            let name = &filename[..name_end];
            if let Some(ver_idx) = name.rfind('-') {
                package.name = name[..ver_idx].to_string();
                package.version = name[ver_idx + 1..].to_string();
            } else {
                package.name = name.to_string();
                package.version = "1.0.0".to_string();
            }
            println!("Detected package name: {}, version: {}", package.name, package.version);
        }
    }

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mode = entry.header().mode()?;

        println!("Adding file: {}", path.display());
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        package.add_file(path, mode as u32, contents, None);
    }

    println!("Saving package to: {}", output_path.display());
    package.save_package(output_path)?;

    println!("Conversion of tar.xz completed successfully.");
    Ok(())
}

pub fn detect_file_type(path: &str) -> anyhow::Result<Option<String>> {
    println!("Attempting to detect file type of '{}'.", path);
    if let Some(file_type) = detect_file_type_a(path)? {
        println!("File type determined using magic numbers: '{}'.", file_type);
        return Ok(Some(file_type));
    }

    println!("Falling back to file extension-based detection for '{}'.", path);
    let path = PathBuf::from(path);
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            "deb" => return Ok(Some("deb".to_string())),
            "rpm" => return Ok(Some("rpm".to_string())),
            "zip" => return Ok(Some("zip".to_string())),
            "gz" => {
                if path.to_str().map(|s| s.to_lowercase().ends_with(".tar.gz")).unwrap_or(false) {
                    return Ok(Some("tar.gz".to_string()));
                }
            }
            "bz2" => {
                if path.to_str().map(|s| s.to_lowercase().ends_with(".tar.bz2")).unwrap_or(false) {
                    return Ok(Some("tar.bz2".to_string()));
                }
            }
            "xz" => {
                if path.to_str().map(|s| s.to_lowercase().ends_with(".tar.xz")).unwrap_or(false) {
                    return Ok(Some("tar.xz".to_string()));
                }
            }
            _ => {}
        }
    }

    println!("File type detection for '{}' failed.", path.display());
    Ok(None)
}

pub fn detect_file_type_a(path: &str) -> anyhow::Result<Option<String>> {
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
    if bytes_read >= 4
        && buffer[0] == 0xED
        && buffer[1] == 0xAB
        && buffer[2] == 0xEE
        && buffer[3] == 0xDB
    {
        return Ok(Some("rpm".to_string()));
    }

    // Check for gzip (including tar.gz)
    // Gzip files start with 0x1F 0x8B
    if bytes_read >= 2 && buffer[0] == 0x1F && buffer[1] == 0x8B {
        return Ok(Some("tar.gz".to_string()));
    }

    // Check for ZIP
    // ZIP files start with "PK\x03\x04"
    if bytes_read >= 4
        && buffer[0] == 0x50
        && buffer[1] == 0x4B
        && buffer[2] == 0x03
        && buffer[3] == 0x04
    {
        return Ok(Some("zip".to_string()));
    }

    // Check for bzip2 (including tar.bz2)
    // Bzip2 files start with "BZh"
    if bytes_read >= 3 && &buffer[0..3] == b"BZh" {
        return Ok(Some("tar.bz2".to_string()));
    }

    // Check for XZ (including tar.xz)
    // XZ files start with 0xFD '7zXZ'
    if bytes_read >= 6 && buffer[0] == 0xFD && &buffer[1..6] == b"7zXZ\x00" {
        return Ok(Some("tar.xz".to_string()));
    }

    Ok(None)
}