//! CLI digest command tests

use assert_cmd::Command;
use predicates::str::{contains, is_match};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn cli_digest_zip_sha256_default() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_unsigned.zip"])
        .assert()
        .success()
        .stdout(is_match(r"^[a-f0-9]{64}\n$").unwrap());
}

#[test]
fn cli_digest_zip_sha512() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_unsigned.zip", "--sha512"])
        .assert()
        .success()
        .stdout(is_match(r"^[a-f0-9]{128}\n$").unwrap());
}

#[test]
fn cli_digest_zip_base64_format() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args([
            "digest",
            "tests/fixtures/test_unsigned.zip",
            "--format",
            "base64",
        ])
        .assert()
        .success()
        .stdout(is_match(r"^[A-Za-z0-9+/=]+\n$").unwrap());
}

#[test]
fn cli_digest_shows_regions() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_unsigned.zip"])
        .assert()
        .success()
        .stderr(contains("zip_entries"))
        .stderr(contains("central_directory"))
        .stderr(contains("eocd"));
}

#[test]
fn cli_digest_dump_creates_file() {
    let output = NamedTempFile::new().expect("create temp file");
    let output_path = output.path().to_str().unwrap();

    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args([
            "digest",
            "tests/fixtures/test_unsigned.zip",
            "--dump",
            output_path,
        ])
        .assert()
        .success()
        .stderr(contains("Dumped"));

    // Verify file was created with correct size
    let metadata = std::fs::metadata(output_path).expect("read metadata");
    assert!(metadata.len() > 0, "dump file should not be empty");
}

#[test]
fn cli_digest_signed_zip_works() {
    // Note: directprint feature may output signing block info to stdout
    // We just verify the command succeeds and output contains a valid hex digest
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_signed.zip"])
        .assert()
        .success()
        .stdout(contains("265c3e52dba8ac115eb84e432c9c3025421b5b40e53e1056b6681071db8f2500"));
}

#[test]
fn cli_digest_sha256_and_sha512_mutually_exclusive() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args([
            "digest",
            "tests/fixtures/test_unsigned.zip",
            "--sha256",
            "--sha512",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_digest_nonexistent_file_fails() {
    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "nonexistent_file.zip"])
        .assert()
        .failure();
}

#[test]
fn cli_digest_consistent_output() {
    // Run digest twice and ensure output is identical
    let output1 = Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_unsigned.zip"])
        .output()
        .expect("run command");

    let output2 = Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", "tests/fixtures/test_unsigned.zip"])
        .output()
        .expect("run command");

    assert_eq!(
        output1.stdout, output2.stdout,
        "digest should be deterministic"
    );
}

/// Create a minimal ELF file for testing
fn create_minimal_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64];

    // ELF magic
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1; // version
    elf[16..18].copy_from_slice(&1u16.to_le_bytes()); // type: executable
    elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // machine: x86-64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // header size
    elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // section header size

    let shstrtab = b"\0.text\0.rodata\0.shstrtab\0";
    let shstrtab_offset = elf.len();
    elf.extend_from_slice(shstrtab);

    let text_offset = elf.len();
    let text_content = b"fake code for testing";
    elf.extend_from_slice(text_content);

    let rodata_offset = elf.len();
    let rodata_content = b"read only data";
    elf.extend_from_slice(rodata_content);

    while elf.len() % 8 != 0 {
        elf.push(0);
    }

    let sh_offset = elf.len();

    // NULL section header
    elf.extend_from_slice(&[0u8; 64]);

    // .text section header
    let mut text_sh = [0u8; 64];
    text_sh[0..4].copy_from_slice(&1u32.to_le_bytes());
    text_sh[4..8].copy_from_slice(&1u32.to_le_bytes());
    text_sh[24..32].copy_from_slice(&(text_offset as u64).to_le_bytes());
    text_sh[32..40].copy_from_slice(&(text_content.len() as u64).to_le_bytes());
    text_sh[48..56].copy_from_slice(&1u64.to_le_bytes());
    elf.extend_from_slice(&text_sh);

    // .rodata section header
    let mut rodata_sh = [0u8; 64];
    rodata_sh[0..4].copy_from_slice(&7u32.to_le_bytes());
    rodata_sh[4..8].copy_from_slice(&1u32.to_le_bytes());
    rodata_sh[24..32].copy_from_slice(&(rodata_offset as u64).to_le_bytes());
    rodata_sh[32..40].copy_from_slice(&(rodata_content.len() as u64).to_le_bytes());
    rodata_sh[48..56].copy_from_slice(&1u64.to_le_bytes());
    elf.extend_from_slice(&rodata_sh);

    // .shstrtab section header
    let mut shstrtab_sh = [0u8; 64];
    shstrtab_sh[0..4].copy_from_slice(&15u32.to_le_bytes());
    shstrtab_sh[4..8].copy_from_slice(&3u32.to_le_bytes());
    shstrtab_sh[24..32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes());
    shstrtab_sh[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
    shstrtab_sh[48..56].copy_from_slice(&1u64.to_le_bytes());
    elf.extend_from_slice(&shstrtab_sh);

    // Update header
    elf[40..48].copy_from_slice(&(sh_offset as u64).to_le_bytes());
    elf[60..62].copy_from_slice(&4u16.to_le_bytes());
    elf[62..64].copy_from_slice(&3u16.to_le_bytes());

    elf
}

#[test]
fn cli_digest_elf_default_sections() {
    let mut elf_file = NamedTempFile::new().expect("create temp file");
    elf_file.write_all(&create_minimal_elf()).expect("write ELF");
    elf_file.flush().expect("flush");

    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args(["digest", elf_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(contains("ELF"))
        .stderr(contains(".text"))
        .stderr(contains(".rodata"))
        .stdout(is_match(r"^[a-f0-9]{64}\n$").unwrap());
}

#[test]
fn cli_digest_elf_custom_section() {
    let mut elf_file = NamedTempFile::new().expect("create temp file");
    elf_file.write_all(&create_minimal_elf()).expect("write ELF");
    elf_file.flush().expect("flush");

    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args([
            "digest",
            elf_file.path().to_str().unwrap(),
            "--elf-section",
            ".text",
        ])
        .assert()
        .success()
        .stderr(contains(".text"));
}

#[test]
fn cli_digest_elf_dump() {
    let mut elf_file = NamedTempFile::new().expect("create temp file");
    elf_file.write_all(&create_minimal_elf()).expect("write ELF");
    elf_file.flush().expect("flush");

    let output = NamedTempFile::new().expect("create output file");

    Command::cargo_bin("ksusig")
        .expect("binary exists")
        .args([
            "digest",
            elf_file.path().to_str().unwrap(),
            "--dump",
            output.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(contains("Dumped"));

    let metadata = std::fs::metadata(output.path()).expect("read metadata");
    assert!(metadata.len() > 0, "dump file should not be empty");
}
