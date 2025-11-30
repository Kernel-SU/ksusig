//! ELF file format support
//!
//! This module provides ELF file signature support using the goblin crate.

pub mod digest;

use std::fs::read;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use goblin::container::Ctx;
use goblin::elf::header;
use goblin::elf::section_header::{SectionHeader, SHT_NOBITS, SHT_PROGBITS};
use goblin::elf::Elf;
use goblin::error::Error as GoblinError;
use scroll::ctx::{IntoCtx, SizeWith};

use crate::signable::DigestRegion;
use crate::signing_block::algorithms::Algorithms;
use crate::signing_block::SigningBlock;

use self::digest::digest_elf_sections;

/// Default sections to sign
pub const DEFAULT_SIGNED_SECTIONS: &[&str] = &[".text", ".rodata"];

/// KSU signature section name
pub const KSU_SIGN_SECTION: &str = ".ksu_sign";

/// ELF-specific error type
#[derive(Debug)]
pub enum ElfError {
    /// IO-level failure
    Io(std::io::Error),
    /// Parse failure from goblin
    Parse(GoblinError),
    /// Requested section is missing or invalid
    MissingSection(String),
    /// Name table offset overflowed u32
    NameTableOverflow,
    /// Generic validation error
    Value(String),
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {}", err),
            Self::Parse(err) => write!(f, "ELF parse error: {}", err),
            Self::MissingSection(name) => write!(f, "Missing section: {}", name),
            Self::NameTableOverflow => write!(f, "Section name table is too large"),
            Self::Value(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ElfError {}

impl From<std::io::Error> for ElfError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<GoblinError> for ElfError {
    fn from(err: GoblinError) -> Self {
        Self::Parse(err)
    }
}

/// ELF file wrapper that carries parsed data and signing configuration
#[derive(Debug, Clone)]
pub struct ElfFile {
    /// Source path on disk
    pub path: PathBuf,
    /// Raw ELF bytes
    data: Vec<u8>,
    /// Sections to sign
    signed_sections: Vec<String>,
}

impl ElfFile {
    /// Create a new ELF representation from a path
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed
    pub fn new(path: PathBuf) -> Result<Self, ElfError> {
        let data = read(&path)?;
        Elf::parse(&data)?; // validate early
        let signed_sections = DEFAULT_SIGNED_SECTIONS
            .iter()
            .map(|s| s.to_string())
            .collect();
        Ok(Self {
            path,
            data,
            signed_sections,
        })
    }

    /// Update which sections should be signed
    ///
    /// # Errors
    /// Returns an error when the list is empty or contains invalid names
    pub fn set_signed_sections(&mut self, sections: Vec<String>) -> Result<(), ElfError> {
        let filtered: Vec<String> = sections
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if filtered.is_empty() {
            return Err(ElfError::Value(
                "ELF 需要至少指定一个待签名的 section".to_string(),
            ));
        }

        if filtered
            .iter()
            .any(|s| s.eq_ignore_ascii_case(KSU_SIGN_SECTION))
        {
            return Err(ElfError::Value(
                "不能将签名存储 section (.ksu_sign) 参与签名".to_string(),
            ));
        }

        self.signed_sections = filtered;
        Ok(())
    }

    /// Get resolved sections (name, offset, size) for signing
    ///
    /// # Errors
    /// Returns an error if a requested section is missing or malformed
    pub fn resolved_sections(&self) -> Result<Vec<(String, u64, u64)>, ElfError> {
        let elf = self.parse_elf()?;
        self.collect_sections(&elf)
    }

    /// Produce digest regions for debugging or logging
    ///
    /// # Errors
    /// Returns an error if sections are missing
    pub fn digest_regions(&self) -> Result<Vec<DigestRegion>, ElfError> {
        let sections = self.resolved_sections()?;
        Ok(sections
            .into_iter()
            .map(|(name, offset, size)| DigestRegion { name, offset, size })
            .collect())
    }

    /// Calculate digest bytes for the configured sections
    ///
    /// # Errors
    /// Returns an error if digesting fails
    pub fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, ElfError> {
        let sections = self.resolved_sections()?;
        let mut cursor = Cursor::new(&self.data);
        Ok(digest_elf_sections(&mut cursor, &sections, algo)?)
    }

    /// Get existing signing block from `.ksu_sign`, if present
    ///
    /// # Errors
    /// Returns an error if the signing block cannot be parsed
    pub fn get_signing_block(&self) -> Result<Option<SigningBlock>, ElfError> {
        let elf = self.parse_elf()?;
        if let Some(section) = find_section(&elf, KSU_SIGN_SECTION) {
            let start = section.sh_offset as usize;
            let end = start
                .checked_add(section.sh_size as usize)
                .ok_or_else(|| ElfError::Value("签名段大小溢出".to_string()))?;
            if section.sh_size == 0 {
                return Ok(None);
            }
            let bytes = self
                .data
                .get(start..end)
                .ok_or_else(|| ElfError::Value("签名段范围越界".to_string()))?;
            return SigningBlock::from_u8(bytes)
                .map(Some)
                .map_err(|e| ElfError::Value(format!("无法解析签名块: {}", e)));
        }
        Ok(None)
    }

    /// Write ELF file with updated `.ksu_sign` section
    ///
    /// # Errors
    /// Returns an error if writing or layout adjustments fail
    pub fn write_with_signature<W: Write>(
        &self,
        writer: &mut W,
        signing_block: &SigningBlock,
    ) -> Result<(), ElfError> {
        let elf = self.parse_elf()?;
        let ctx = Ctx {
            container: elf.header.container()?,
            le: elf.header.endianness()?,
        };

        let mut section_headers = elf.section_headers.clone();
        let shstrtab_index = elf.header.e_shstrndx as usize;
        let mut shstrtab_bytes = load_shstrtab(&elf, &self.data)?;

        let signing_block_bytes = signing_block.to_u8();

        let mut output = self.data.clone();
        let ksu_align = align_for_container(&ctx);
        let signing_offset = append_aligned(&mut output, &signing_block_bytes, ksu_align);

        let mut maybe_name_offset = existing_name_offset(&elf, KSU_SIGN_SECTION);
        if maybe_name_offset.is_none() {
            maybe_name_offset = Some(shstrtab_bytes.len());
            shstrtab_bytes.extend_from_slice(KSU_SIGN_SECTION.as_bytes());
            shstrtab_bytes.push(0);
        }
        let name_offset = maybe_name_offset.ok_or(ElfError::NameTableOverflow)?;

        let mut moved_shstrtab = false;
        let shstrtab_header = section_headers
            .get(shstrtab_index)
            .ok_or_else(|| ElfError::Value("缺少 section name 表".to_string()))?;
        let shstr_align = usize::try_from(shstrtab_header.sh_addralign)
            .unwrap_or(1)
            .max(1);

        if shstrtab_bytes.len() as u64 != shstrtab_header.sh_size {
            let new_offset = append_aligned(&mut output, &shstrtab_bytes, shstr_align);
            let header = section_headers
                .get_mut(shstrtab_index)
                .ok_or_else(|| ElfError::Value("缺少 section name 表".to_string()))?;
            header.sh_offset = new_offset as u64;
            header.sh_size = shstrtab_bytes.len() as u64;
            moved_shstrtab = true;
        }

        if let Some(index) = find_section_index(&elf, KSU_SIGN_SECTION) {
            let header = section_headers
                .get_mut(index)
                .ok_or_else(|| ElfError::Value("无法更新签名段".to_string()))?;
            header.sh_name =
                u32::try_from(name_offset).map_err(|_| ElfError::NameTableOverflow)? as usize;
            header.sh_type = SHT_PROGBITS;
            header.sh_flags = 0;
            header.sh_offset = signing_offset as u64;
            header.sh_size = signing_block_bytes.len() as u64;
            header.sh_addr = 0;
            header.sh_link = 0;
            header.sh_info = 0;
            header.sh_addralign = ksu_align as u64;
            header.sh_entsize = 0;
        } else {
            section_headers.push(SectionHeader {
                sh_name: u32::try_from(name_offset).map_err(|_| ElfError::NameTableOverflow)?
                    as usize,
                sh_type: SHT_PROGBITS,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: signing_offset as u64,
                sh_size: signing_block_bytes.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: ksu_align as u64,
                sh_entsize: 0,
            });
        }

        let sh_entry_size = SectionHeader::size(ctx);
        let sh_table_offset = align_to(output.len(), sh_entry_size.max(8));
        let total_size = sh_entry_size
            .checked_mul(section_headers.len())
            .ok_or_else(|| ElfError::Value("节头表大小溢出".to_string()))?;
        output.resize(sh_table_offset + total_size, 0);

        for (idx, sh) in section_headers.iter().enumerate() {
            let start = sh_table_offset + idx * sh_entry_size;
            let end = start + sh_entry_size;
            let buffer = output
                .get_mut(start..end)
                .ok_or_else(|| ElfError::Value("无法写入节头表".to_string()))?;
            sh.clone().into_ctx(buffer, ctx);
        }

        let mut header = elf.header;
        header.e_shoff = sh_table_offset as u64;
        header.e_shnum = u16::try_from(section_headers.len())
            .map_err(|_| ElfError::Value("节头表数量溢出".to_string()))?;
        header.e_shentsize = sh_entry_size as u16;
        if moved_shstrtab {
            header.e_shstrndx = shstrtab_index as u16;
        }
        let header_size = header::Header::size_with(&ctx);
        let header_slice = output
            .get_mut(..header_size)
            .ok_or_else(|| ElfError::Value("写入 ELF 头越界".to_string()))?;
        header.into_ctx(header_slice, ctx);

        writer.write_all(&output)?;
        Ok(())
    }

    /// Parse ELF from the in-memory bytes
    ///
    /// # Errors
    /// Propagates goblin parsing errors
    fn parse_elf(&self) -> Result<Elf<'_>, ElfError> {
        Elf::parse(&self.data).map_err(ElfError::from)
    }

    /// Collect requested sections with offsets and sizes
    ///
    /// # Errors
    /// Returns an error if sections are missing or invalid
    fn collect_sections(&self, elf: &Elf<'_>) -> Result<Vec<(String, u64, u64)>, ElfError> {
        let mut sections = Vec::new();
        for name in &self.signed_sections {
            let sh =
                find_section(elf, name).ok_or_else(|| ElfError::MissingSection(name.clone()))?;
            if sh.sh_type == SHT_NOBITS {
                return Err(ElfError::Value(format!(
                    "section {} 为空 (SHT_NOBITS)，无法参与签名",
                    name
                )));
            }
            if sh.sh_size == 0 {
                return Err(ElfError::Value(format!(
                    "section {} 大小为 0，无法参与签名",
                    name
                )));
            }
            sections.push((name.clone(), sh.sh_offset, sh.sh_size));
        }
        sections.sort_by_key(|(_, offset, _)| *offset);
        Ok(sections)
    }
}

/// Align value upwards to `align` boundary
const fn align_to(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

/// Append data to the target buffer with alignment and return the start offset
fn append_aligned(target: &mut Vec<u8>, data: &[u8], align: usize) -> usize {
    let offset = align_to(target.len(), align.max(1));
    if offset > target.len() {
        target.resize(offset, 0);
    }
    let start = target.len();
    target.extend_from_slice(data);
    start
}

/// Derive alignment requirement from ELF class (32-bit vs 64-bit)
///
/// Note: `Container::Big` means 64-bit ELF, `Container::Little` means 32-bit ELF.
/// This naming refers to the address size, not byte order (endianness).
const fn align_for_container(ctx: &Ctx) -> usize {
    match ctx.container {
        goblin::container::Container::Big => 8,    // 64-bit ELF
        goblin::container::Container::Little => 4, // 32-bit ELF
    }
}

/// Load section header string table bytes
///
/// # Errors
/// 返回缺少或越界时的错误
fn load_shstrtab(elf: &Elf<'_>, data: &[u8]) -> Result<Vec<u8>, ElfError> {
    let shstrtab_index = elf.header.e_shstrndx as usize;
    let shstr_hdr = elf
        .section_headers
        .get(shstrtab_index)
        .ok_or_else(|| ElfError::Value("缺少 section name 表".to_string()))?;
    let start = shstr_hdr.sh_offset as usize;
    let end = start
        .checked_add(shstr_hdr.sh_size as usize)
        .ok_or_else(|| ElfError::Value("section name 表大小溢出".to_string()))?;
    let slice = data
        .get(start..end)
        .ok_or_else(|| ElfError::Value("section name 表超出文件范围".to_string()))?;
    Ok(slice.to_vec())
}

/// Find a section by name
fn find_section<'a>(elf: &'a Elf<'_>, name: &str) -> Option<&'a SectionHeader> {
    elf.section_headers.iter().find(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .is_some_and(|n| n == name)
    })
}

/// Find section index by name
fn find_section_index(elf: &Elf<'_>, name: &str) -> Option<usize> {
    elf.section_headers.iter().position(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .is_some_and(|n| n == name)
    })
}

/// Check if section name already exists and return its offset
fn existing_name_offset(elf: &Elf<'_>, name: &str) -> Option<usize> {
    elf.section_headers.iter().find_map(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .and_then(|n| if n == name { Some(sh.sh_name) } else { None })
    })
}
