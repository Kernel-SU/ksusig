//! ELF signing integration tests

use std::io::Write;
use std::path::PathBuf;

use ksusig::{
    file_formats::elf::{ElfFile, DEFAULT_SIGNED_SECTIONS, KSU_SIGN_SECTION},
    signable::{FileFormat, Signable, SignableFile},
    signing_block::algorithms::Algorithms,
    signing_block::elf_section_info::{ElfSectionInfo, SectionEntry, ELF_SECTION_INFO_BLOCK_ID},
    SigningBlock,
};

/// Create a minimal valid ELF64 file with .text and .rodata sections
fn create_minimal_elf() -> Vec<u8> {
    // ELF64 header (64 bytes)
    let mut elf = vec![0u8; 64];

    // ELF magic
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // Class: 64-bit
    elf[4] = 2;
    // Data: little-endian
    elf[5] = 1;
    // Version
    elf[6] = 1;
    // OS/ABI: System V
    elf[7] = 0;
    // Type: executable
    elf[16..18].copy_from_slice(&1u16.to_le_bytes());
    // Machine: x86-64
    elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    // Version
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // Entry point (not used)
    elf[24..32].copy_from_slice(&0u64.to_le_bytes());
    // Program header offset (not used for sections)
    elf[32..40].copy_from_slice(&0u64.to_le_bytes());
    // Section header offset - will be updated later
    elf[40..48].copy_from_slice(&0u64.to_le_bytes());
    // Flags
    elf[48..52].copy_from_slice(&0u32.to_le_bytes());
    // ELF header size
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    // Program header entry size
    elf[54..56].copy_from_slice(&0u16.to_le_bytes());
    // Number of program headers
    elf[56..58].copy_from_slice(&0u16.to_le_bytes());
    // Section header entry size
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    // Number of section headers - will be updated
    elf[60..62].copy_from_slice(&0u16.to_le_bytes());
    // Section name string table index - will be updated
    elf[62..64].copy_from_slice(&0u16.to_le_bytes());

    // Section name string table (.shstrtab)
    let shstrtab = b"\0.text\0.rodata\0.shstrtab\0";
    let shstrtab_offset = elf.len();
    elf.extend_from_slice(shstrtab);

    // .text section content
    let text_offset = elf.len();
    let text_content = b"fake code here for testing purposes";
    elf.extend_from_slice(text_content);

    // .rodata section content
    let rodata_offset = elf.len();
    let rodata_content = b"read only data for testing";
    elf.extend_from_slice(rodata_content);

    // Align to 8 bytes for section headers
    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    let sh_offset = elf.len();

    // Section headers (64 bytes each for ELF64)
    // We need: NULL, .text, .rodata, .shstrtab

    // NULL section header
    let null_sh = [0u8; 64];
    elf.extend_from_slice(&null_sh);

    // .text section header
    let mut text_sh = [0u8; 64];
    text_sh[0..4].copy_from_slice(&1u32.to_le_bytes()); // sh_name (offset in shstrtab)
    text_sh[4..8].copy_from_slice(&1u32.to_le_bytes()); // sh_type: SHT_PROGBITS
    text_sh[8..16].copy_from_slice(&0u64.to_le_bytes()); // sh_flags
    text_sh[16..24].copy_from_slice(&0u64.to_le_bytes()); // sh_addr
    text_sh[24..32].copy_from_slice(&(text_offset as u64).to_le_bytes()); // sh_offset
    text_sh[32..40].copy_from_slice(&(text_content.len() as u64).to_le_bytes()); // sh_size
    text_sh[40..44].copy_from_slice(&0u32.to_le_bytes()); // sh_link
    text_sh[44..48].copy_from_slice(&0u32.to_le_bytes()); // sh_info
    text_sh[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    text_sh[56..64].copy_from_slice(&0u64.to_le_bytes()); // sh_entsize
    elf.extend_from_slice(&text_sh);

    // .rodata section header
    let mut rodata_sh = [0u8; 64];
    rodata_sh[0..4].copy_from_slice(&7u32.to_le_bytes()); // sh_name (offset: ".text\0" = 6 bytes, then ".rodata")
    rodata_sh[4..8].copy_from_slice(&1u32.to_le_bytes()); // sh_type: SHT_PROGBITS
    rodata_sh[8..16].copy_from_slice(&0u64.to_le_bytes()); // sh_flags
    rodata_sh[16..24].copy_from_slice(&0u64.to_le_bytes()); // sh_addr
    rodata_sh[24..32].copy_from_slice(&(rodata_offset as u64).to_le_bytes()); // sh_offset
    rodata_sh[32..40].copy_from_slice(&(rodata_content.len() as u64).to_le_bytes()); // sh_size
    rodata_sh[40..44].copy_from_slice(&0u32.to_le_bytes()); // sh_link
    rodata_sh[44..48].copy_from_slice(&0u32.to_le_bytes()); // sh_info
    rodata_sh[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    rodata_sh[56..64].copy_from_slice(&0u64.to_le_bytes()); // sh_entsize
    elf.extend_from_slice(&rodata_sh);

    // .shstrtab section header
    let mut shstrtab_sh = [0u8; 64];
    shstrtab_sh[0..4].copy_from_slice(&15u32.to_le_bytes()); // sh_name (after ".text\0.rodata\0")
    shstrtab_sh[4..8].copy_from_slice(&3u32.to_le_bytes()); // sh_type: SHT_STRTAB
    shstrtab_sh[8..16].copy_from_slice(&0u64.to_le_bytes()); // sh_flags
    shstrtab_sh[16..24].copy_from_slice(&0u64.to_le_bytes()); // sh_addr
    shstrtab_sh[24..32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes()); // sh_offset
    shstrtab_sh[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
    shstrtab_sh[40..44].copy_from_slice(&0u32.to_le_bytes()); // sh_link
    shstrtab_sh[44..48].copy_from_slice(&0u32.to_le_bytes()); // sh_info
    shstrtab_sh[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
    shstrtab_sh[56..64].copy_from_slice(&0u64.to_le_bytes()); // sh_entsize
    elf.extend_from_slice(&shstrtab_sh);

    // Update ELF header with section header info
    elf[40..48].copy_from_slice(&(sh_offset as u64).to_le_bytes()); // e_shoff
    elf[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum (4 sections)
    elf[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx (index of .shstrtab)

    elf
}

/// Write minimal ELF to a temp file and return the path
fn create_temp_elf() -> (tempfile::NamedTempFile, PathBuf) {
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    let elf_data = create_minimal_elf();
    file.write_all(&elf_data).expect("write ELF data");
    file.flush().expect("flush");
    let path = file.path().to_path_buf();
    (file, path)
}

#[test]
fn elf_file_can_be_parsed() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");
    assert_eq!(elf.format(), FileFormat::Elf);
}

#[test]
fn elf_default_signed_sections_are_text_and_rodata() {
    assert_eq!(DEFAULT_SIGNED_SECTIONS, &[".text", ".rodata"]);
}

#[test]
fn elf_digest_regions_returns_expected_sections() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");
    let regions = elf.digest_regions().expect("get digest regions");

    assert_eq!(regions.len(), 2);
    assert!(regions.iter().any(|r| r.name == ".text"));
    assert!(regions.iter().any(|r| r.name == ".rodata"));
}

#[test]
fn elf_digest_produces_consistent_hash() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");

    let algo = Algorithms::ECDSA_SHA2_256;
    let digest1 = elf.digest(&algo).expect("calculate digest");
    let digest2 = elf.digest(&algo).expect("calculate digest again");

    assert_eq!(digest1, digest2, "digest should be deterministic");
    assert!(!digest1.is_empty(), "digest should not be empty");
}

#[test]
fn elf_set_signed_sections_filters_empty_names() {
    let (_file, path) = create_temp_elf();
    let mut elf = ElfFile::new(path).expect("parse ELF");

    elf.set_signed_sections(vec![".text".to_string(), "  ".to_string(), "".to_string()])
        .expect("set sections");

    let regions = elf.digest_regions().expect("get regions");
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].name, ".text");
}

#[test]
fn elf_set_signed_sections_rejects_ksu_sign_section() {
    let (_file, path) = create_temp_elf();
    let mut elf = ElfFile::new(path).expect("parse ELF");

    let result = elf.set_signed_sections(vec![KSU_SIGN_SECTION.to_string()]);
    assert!(result.is_err(), "should reject .ksu_sign section");
}

#[test]
fn elf_set_signed_sections_rejects_empty_list() {
    let (_file, path) = create_temp_elf();
    let mut elf = ElfFile::new(path).expect("parse ELF");

    let result = elf.set_signed_sections(vec![]);
    assert!(result.is_err(), "should reject empty section list");
}

#[test]
fn elf_missing_section_returns_error() {
    let (_file, path) = create_temp_elf();
    let mut elf = ElfFile::new(path).expect("parse ELF");

    elf.set_signed_sections(vec![".nonexistent".to_string()])
        .expect("set sections");

    let result = elf.digest_regions();
    assert!(result.is_err(), "should fail for missing section");
}

#[test]
fn elf_get_signing_block_returns_none_for_unsigned() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");

    let block = elf.get_signing_block().expect("get signing block");
    assert!(block.is_none(), "unsigned ELF should have no signing block");
}

#[test]
fn elf_write_with_signature_adds_ksu_sign_section() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");

    // Create a minimal signing block
    let signing_block = SigningBlock::new_with_padding(vec![]).expect("create signing block");

    let mut output = Vec::new();
    elf.write_with_signature(&mut output, &signing_block)
        .expect("write with signature");

    // Verify the output is valid ELF with .ksu_sign section
    assert!(
        output.len() > create_minimal_elf().len(),
        "output should be larger"
    );
    assert!(&output[0..4] == b"\x7fELF", "should still be valid ELF");

    // Parse the signed ELF and verify .ksu_sign exists
    let mut temp_signed = tempfile::NamedTempFile::new().expect("create temp");
    temp_signed.write_all(&output).expect("write signed");
    temp_signed.flush().expect("flush");

    let signed_elf = ElfFile::new(temp_signed.path().to_path_buf()).expect("parse signed ELF");
    let block = signed_elf.get_signing_block().expect("get signing block");
    assert!(block.is_some(), "signed ELF should have signing block");
}

#[test]
fn signable_file_detects_elf_format() {
    let (_file, path) = create_temp_elf();
    let signable = SignableFile::open(&path).expect("open signable");

    assert_eq!(signable.format(), FileFormat::Elf);
}

#[test]
fn elf_section_info_serialization_roundtrip() {
    let sections = vec![
        SectionEntry::new(".text".to_string(), 100, 500),
        SectionEntry::new(".rodata".to_string(), 700, 200),
    ];
    let info = ElfSectionInfo::new(sections);

    let serialized = info.to_u8();

    // Parse manually: size (8 bytes) + id (4 bytes) + count (4 bytes) + entries
    assert!(serialized.len() >= 16, "serialized should have header");

    // Verify size field
    let size = u64::from_le_bytes(serialized[0..8].try_into().unwrap()) as usize;
    let id = u32::from_le_bytes(serialized[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(serialized[12..16].try_into().unwrap());

    assert_eq!(id, ELF_SECTION_INFO_BLOCK_ID);
    assert_eq!(count, 2);
    assert!(size > 0, "size should be positive");
}

#[test]
fn elf_section_info_block_id_is_correct() {
    // "KSEL" in little-endian
    assert_eq!(ELF_SECTION_INFO_BLOCK_ID, 0x4c45_534b);
}

#[test]
fn elf_digest_different_sections_produce_different_hashes() {
    let (_file, path) = create_temp_elf();
    let mut elf = ElfFile::new(path.clone()).expect("parse ELF");

    let algo = Algorithms::ECDSA_SHA2_256;

    // Digest with default sections (.text + .rodata)
    let digest_both = elf.digest(&algo).expect("digest both");

    // Digest with only .text
    elf.set_signed_sections(vec![".text".to_string()])
        .expect("set sections");
    let digest_text_only = elf.digest(&algo).expect("digest text only");

    assert_ne!(
        digest_both, digest_text_only,
        "different sections should produce different digests"
    );
}

#[test]
fn elf_section_entry_byte_size_is_correct() {
    let entry = SectionEntry::new(".text".to_string(), 100, 500);

    // 2 (name_len) + 5 (.text) + 8 (offset) + 8 (size) = 23
    assert_eq!(entry.byte_size(), 23);
}

#[test]
fn elf_signable_trait_implementation() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");

    // Test Signable trait methods
    assert_eq!(elf.format(), FileFormat::Elf);
    assert!(!elf.is_signed(), "fresh ELF should not be signed");

    let regions = elf.digest_regions().expect("digest regions");
    assert!(!regions.is_empty(), "should have digest regions");
}

#[test]
fn elf_write_and_read_back_preserves_signature() {
    let (_file, path) = create_temp_elf();
    let elf = ElfFile::new(path).expect("parse ELF");

    // Create a signing block
    let signing_block = SigningBlock::new_with_padding(vec![]).expect("create signing block");
    let original_block_bytes = signing_block.to_u8();

    // Write signed ELF
    let mut output = Vec::new();
    elf.write_with_signature(&mut output, &signing_block)
        .expect("write with signature");

    // Read back
    let mut temp_signed = tempfile::NamedTempFile::new().expect("create temp");
    temp_signed.write_all(&output).expect("write signed");
    temp_signed.flush().expect("flush");

    let signed_elf = ElfFile::new(temp_signed.path().to_path_buf()).expect("parse signed ELF");
    let read_block = signed_elf
        .get_signing_block()
        .expect("get signing block")
        .expect("should have block");

    let read_block_bytes = read_block.to_u8();
    assert_eq!(
        original_block_bytes, read_block_bytes,
        "signing block should be preserved"
    );
}
