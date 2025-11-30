//! ELF Section Info Block
//!
//! This module defines the ELF-specific metadata block that stores information
//! about which sections were included in the signature.

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::utils::MyReader;

/// ELF Section Info Block ID
/// "KSEL" in little-endian (0x4c45534b)
pub const ELF_SECTION_INFO_BLOCK_ID: u32 = 0x4c45_534b;

/// Single section entry
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SectionEntry {
    /// Section name length
    pub name_len: u16,
    /// Section name (UTF-8)
    pub name: String,
    /// Section file offset
    pub file_offset: u64,
    /// Section size
    pub size: u64,
}

impl SectionEntry {
    /// Create a new section entry
    #[must_use]
    pub const fn new(name: String, file_offset: u64, size: u64) -> Self {
        let name_len = name.len() as u16;
        Self {
            name_len,
            name,
            file_offset,
            size,
        }
    }

    /// Serialize to bytes
    pub fn to_u8(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.name_len.to_le_bytes());
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&self.file_offset.to_le_bytes());
        data.extend_from_slice(&self.size.to_le_bytes());
        data
    }

    /// Parse from bytes
    /// # Errors
    /// Returns error if parsing fails
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let name_len = data.read_u16()?;
        let name_bytes = data.get_to(name_len as usize)?;
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|e| format!("Invalid section name: {}", e))?;
        let file_offset = data.read_u64()?;
        let size = data.read_u64()?;
        Ok(Self {
            name_len,
            name,
            file_offset,
            size,
        })
    }

    /// Get byte size of this entry
    pub const fn byte_size(&self) -> usize {
        mem::size_of::<u16>()     // name_len
            + self.name.len()      // name
            + mem::size_of::<u64>() // file_offset
            + mem::size_of::<u64>() // size
    }
}

/// ELF Section Info Block
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElfSectionInfo {
    /// Block size
    pub size: usize,
    /// Block ID
    pub id: u32,
    /// Number of sections
    pub section_count: u32,
    /// Section entries
    pub sections: Vec<SectionEntry>,
}

impl ElfSectionInfo {
    /// Create a new ELF section info block
    pub fn new(sections: Vec<SectionEntry>) -> Self {
        let sections_size: usize = sections.iter().map(|s| s.byte_size()).sum();
        let size = mem::size_of::<u32>()    // id
            + mem::size_of::<u32>()          // section_count
            + sections_size; // sections
        Self {
            size,
            id: ELF_SECTION_INFO_BLOCK_ID,
            section_count: sections.len() as u32,
            sections,
        }
    }

    /// Create from tuples (name, offset, size)
    pub fn from_tuples(entries: Vec<(&str, u64, u64)>) -> Self {
        let sections = entries
            .into_iter()
            .map(|(name, offset, size)| SectionEntry::new(name.to_string(), offset, size))
            .collect();
        Self::new(sections)
    }

    /// Serialize to bytes
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.id.to_le_bytes().to_vec(),
            self.section_count.to_le_bytes().to_vec(),
            self.sections.iter().flat_map(|s| s.to_u8()).collect(),
        ]
        .concat();
        [(self.size as u64).to_le_bytes().to_vec(), content].concat()
    }

    /// Parse from bytes
    /// # Errors
    /// Returns error if parsing fails
    pub fn parse(size: usize, id: u32, data: &mut MyReader) -> Result<Self, String> {
        let section_count = data.read_u32()?;
        let mut sections = Vec::with_capacity(section_count as usize);
        for _ in 0..section_count {
            sections.push(SectionEntry::parse(data)?);
        }
        Ok(Self {
            size,
            id,
            section_count,
            sections,
        })
    }
}
