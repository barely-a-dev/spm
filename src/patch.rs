/* Patching module with binary format and compression.

Binary format:
1. Magic number "RPAT" (4 bytes)
2. Format version (1 byte)
3. Filename length (2 bytes, little endian)
4. Filename (UTF-8 bytes)
5. Number of sections (4 bytes, little endian)
6. Compressed sections data using zstd:
   For each section:
   - Relative offset from previous section end (4 bytes, varint)
   - Length of new data (4 bytes, varint)
   - New data bytes
*/

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write, Seek};
use std::path::Path;
use zstd::{encode_all, decode_all};
use crate::helpers::{read_varint, write_varint};

pub const MAGIC: &[u8] = b"RPAT";
pub const VERSION: u8 = 1;
const MIN_SECTION_MERGE_DISTANCE: usize = 16; // Merge sections if gap is smaller than this

pub struct Patch {
    pub filename: String,
    pub sections: Vec<PatchSection>,
}

#[derive(Clone)]
pub struct PatchSection {
    pub start: usize,
    pub end: usize,
    pub contents: Vec<u8>,
}

impl Patch {
    pub fn new(filename: String) -> Self {
        Patch {
            filename,
            sections: Vec::new(),
        }
    }

    pub fn add_section(&mut self, start: usize, end: usize, contents: Vec<u8>) {
        self.sections.push(PatchSection {
            start,
            end,
            contents,
        });
    }

    fn optimize_sections(&mut self) {
        // Sort sections by start position
        self.sections.sort_by_key(|s| s.start);

        // Merge adjacent or near-adjacent sections
        let mut optimized = Vec::new();
        let mut current_section = None;

        for section in self.sections.drain(..) {
            match current_section {
                None => current_section = Some(section),
                Some(ref mut current) => {
                    if section.start <= current.end + MIN_SECTION_MERGE_DISTANCE {
                        // Merge sections
                        let gap_size = section.start - current.end;
                        if gap_size > 0 {
                            // Include bytes from original file in the gap
                            current.contents.extend_from_slice(&vec![0; gap_size]);
                        }
                        current.contents.extend_from_slice(&section.contents);
                        current.end = section.end;
                    } else {
                        optimized.push(current_section.take().unwrap());
                        current_section = Some(section);
                    }
                }
            }
        }
        
        if let Some(last) = current_section {
            optimized.push(last);
        }

        self.sections = optimized;
    }

    pub fn save_patch(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let mut file = File::create(path)?;
        
        // Write header
        file.write_all(MAGIC)?;
        file.write_all(&[VERSION])?;
        
        // Write filename
        let filename_bytes = self.filename.as_bytes();
        file.write_all(&(filename_bytes.len() as u16).to_le_bytes())?;
        file.write_all(filename_bytes)?;
        
        // Prepare sections data
        let mut sections_data = Vec::new();
        let mut last_end = 0;
        
        // Write number of sections
        sections_data.extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        
        for section in &self.sections {
            let relative_offset = section.start - last_end;
            // Write relative offset as varint
            write_varint(&mut sections_data, relative_offset as u32)?;
            // Write length as varint
            write_varint(&mut sections_data, section.contents.len() as u32)?;
            // Write contents
            sections_data.extend_from_slice(&section.contents);
            last_end = section.end;
        }
        
        // Compress sections data
        let compressed = encode_all(&sections_data[..], 21)?; // Level 21 for maximum compression
        
        // Write compressed data
        file.write_all(&compressed)?;
        
        Ok(())
    }

    pub fn load_patch(path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        
        if magic != MAGIC {
            return Err("Invalid patch file format".into());
        }
        
        let mut version = [0u8];
        file.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err("Unsupported patch version".into());
        }
        
        // Read filename
        let mut filename_len = [0u8; 2];
        file.read_exact(&mut filename_len)?;
        let filename_len = u16::from_le_bytes(filename_len) as usize;
        
        let mut filename_bytes = vec![0u8; filename_len];
        file.read_exact(&mut filename_bytes)?;
        let filename = String::from_utf8(filename_bytes)?;
        
        // Read and decompress remaining data
        let mut compressed = Vec::new();
        file.read_to_end(&mut compressed)?;
        let decompressed = decode_all(&compressed[..])?;
        
        let mut patch = Patch::new(filename);
        let mut cursor = std::io::Cursor::new(&decompressed);
        
        // Read number of sections
        let mut num_sections = [0u8; 4];
        cursor.read_exact(&mut num_sections)?;
        let num_sections = u32::from_le_bytes(num_sections);
        
        let mut current_pos = 0;
        
        for _ in 0..num_sections {
            let relative_offset = read_varint(&mut cursor)? as usize;
            let length = read_varint(&mut cursor)? as usize;
            
            let start = current_pos + relative_offset;
            let mut contents = vec![0u8; length];
            cursor.read_exact(&mut contents)?;
            
            patch.add_section(start, start + length, contents);
            current_pos = start + length;
        }
        
        Ok(patch)
    }

    pub fn apply(&self, dir_of_file: &str) -> Result<(), Box<dyn Error>> {
        let file_path = Path::new(dir_of_file).join(&self.filename);
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(&file_path)
            .map_err(|e| format!("Failed to open file {}: {}", file_path.display(), e))?;
        
        let mut original = Vec::new();
        file.read_to_end(&mut original)?;
        
        // Sort sections by start position to ensure correct order
        let mut sorted_sections = self.sections.clone();
        sorted_sections.sort_by_key(|s| s.start);
        
        // Verify sections don't overlap
        for window in sorted_sections.windows(2) {
            if window[0].end > window[1].start {
                return Err("Overlapping patch sections detected".into());
            }
        }
        
        // Apply patches in order
        let mut result = Vec::new();
        let mut current_pos = 0;
        
        for section in sorted_sections {
            if section.start < current_pos {
                return Err("Invalid patch section ordering".into());
            }
            if section.start > original.len() || section.end > original.len() {
                return Err("Patch section extends beyond file bounds".into());
            }
            
            // Copy unchanged bytes before patch
            result.extend_from_slice(&original[current_pos..section.start]);
            // Apply patch
            result.extend_from_slice(&section.contents);
            current_pos = section.end;
        }
        
        // Copy remaining bytes after last patch
        result.extend_from_slice(&original[current_pos..]);
        
        // Write back to file
        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&result)?;
        
        Ok(())
    }

    pub fn create_patch_from_files(old_file_path: &Path, new_file_path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut old_file = File::open(old_file_path)?;
        let mut new_file = File::open(new_file_path)?;

        let mut old_contents = Vec::new();
        let mut new_contents = Vec::new();
        
        old_file.read_to_end(&mut old_contents)?;
        new_file.read_to_end(&mut new_contents)?;

        let filename = old_file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?
            .to_string();

        let mut patch = Patch::new(filename);
        let mut current_diff = Vec::new();
        let mut start_pos = None;

        // Handle case where files have different lengths
        let max_len = old_contents.len().max(new_contents.len());
        
        for i in 0..max_len {
            let old_byte = old_contents.get(i).copied();
            let new_byte = new_contents.get(i).copied();
            
            match (old_byte, new_byte) {
                (Some(o), Some(n)) if o != n => {
                    if start_pos.is_none() {
                        start_pos = Some(i);
                    }
                    current_diff.push(n);
                }
                (None, Some(n)) => {
                    if start_pos.is_none() {
                        start_pos = Some(i);
                    }
                    current_diff.push(n);
                }
                _ => {
                    if let Some(start) = start_pos.take() {
                        if !current_diff.is_empty() {
                            patch.add_section(start, i, current_diff.clone());
                            current_diff.clear();
                        }
                    }
                }
            }
        }

        if let Some(start) = start_pos {
            if !current_diff.is_empty() {
                patch.add_section(start, max_len, current_diff);
            }
        }

        // Optimize sections before saving
        patch.optimize_sections();

        Ok(patch)
    }
}
