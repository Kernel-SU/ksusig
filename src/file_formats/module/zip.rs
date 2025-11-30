//! Zip file utilities - an Module is a zip file

use std::io::{self, Read, Seek, SeekFrom};

/// End of Central Directory signature
const EOCD_SIG: usize = 0x0605_4b50;
/// End of Central Directory signature as u8
const EOCD_SIG_U8: [u8; 4] = (EOCD_SIG as u32).to_le_bytes();

/// End of Central Directory Record
#[derive(Debug)]
pub struct EndOfCentralDirectoryRecord {
    /// File offset
    pub file_offset: usize,
    /// Signature
    pub signature: [u8; 4],
    /// Disk number
    pub disk_number: u16,
    /// Disk where the CD starts
    pub disk_with_cd: u16,
    /// Number of CD
    pub num_entries: u16,
    /// Total number CD
    pub total_entries: u16,
    /// Size of the CD
    pub cd_size: u32,
    /// Offset of the CD
    pub cd_offset: u32,
    /// Length of the comment
    pub comment_len: u16,
    /// Comment
    pub comment: Vec<u8>,
}

impl EndOfCentralDirectoryRecord {
    /// Convert the EOCD to a u8 vector
    pub fn to_u8(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.disk_number.to_le_bytes());
        data.extend_from_slice(&self.disk_with_cd.to_le_bytes());
        data.extend_from_slice(&self.num_entries.to_le_bytes());
        data.extend_from_slice(&self.total_entries.to_le_bytes());
        data.extend_from_slice(&self.cd_size.to_le_bytes());
        data.extend_from_slice(&self.cd_offset.to_le_bytes());
        data.extend_from_slice(&self.comment_len.to_le_bytes());
        data.extend_from_slice(&self.comment);
        data
    }
}

/// Maximum comment length in ZIP (65535 bytes)
const MAX_COMMENT_LEN: usize = 65535;

/// Minimum EOCD record size (22 bytes without comment)
const MIN_EOCD_SIZE: usize = 22;

/// Find the EOCD of the Module file
///
/// This implementation uses block reading + memory search for better performance.
/// Instead of seeking byte by byte, it reads the entire search region at once
/// and searches for the EOCD signature in memory.
///
/// # Errors
/// Returns an error if the file cannot be read
pub fn find_eocd<R: Read + Seek>(
    module: &mut R,
    file_len: usize,
) -> Result<EndOfCentralDirectoryRecord, io::Error> {
    if file_len < MIN_EOCD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File too small for valid ZIP",
        ));
    }

    // EOCD must be in the last (MIN_EOCD_SIZE + MAX_COMMENT_LEN) bytes of the file
    let search_size = (MAX_COMMENT_LEN + MIN_EOCD_SIZE).min(file_len);
    let read_start = file_len - search_size;

    // Read the entire search region at once (single IO operation)
    module.seek(SeekFrom::Start(read_start as u64))?;
    let mut buffer = vec![0u8; search_size];
    module.read_exact(&mut buffer)?;

    // Search for EOCD signature from the end towards the beginning
    // The EOCD must be at least MIN_EOCD_SIZE bytes from the end
    find_eocd_in_buffer(&buffer, read_start, file_len)
}

/// Search for EOCD in a buffer and parse it
///
/// # Errors
/// Returns an error if the EOCD is not found in the buffer
fn find_eocd_in_buffer(
    buffer: &[u8],
    buffer_offset: usize,
    file_len: usize,
) -> Result<EndOfCentralDirectoryRecord, io::Error> {
    // Search from the end backwards, stopping when we can't fit a minimum EOCD
    let search_end = buffer.len().saturating_sub(MIN_EOCD_SIZE);

    for i in (0..=search_end).rev() {
        // Check for EOCD signature
        if buffer.get(i..i + 4) == Some(&EOCD_SIG_U8) {
            // Found potential EOCD signature, try to parse it
            if let Ok(eocd) = parse_eocd_at_offset(buffer, i, buffer_offset, file_len) {
                return Ok(eocd);
            }
            // If parsing failed, continue searching (might be false positive in data)
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "EOCD not found"))
}

/// Parse EOCD at a specific offset in the buffer
///
/// # Errors
/// Returns an error if the EOCD data is invalid or incomplete
fn parse_eocd_at_offset(
    buffer: &[u8],
    offset: usize,
    buffer_offset: usize,
    file_len: usize,
) -> Result<EndOfCentralDirectoryRecord, io::Error> {
    let data = buffer
        .get(offset..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD offset"))?;

    if data.len() < MIN_EOCD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete EOCD",
        ));
    }

    // Parse fields (safe: we verified data.len() >= MIN_EOCD_SIZE above)
    let signature: [u8; 4] = data
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD signature"))?;
    let disk_number = u16::from_le_bytes(create_fixed_buffer_2(
        data.get(4..6)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let disk_with_cd = u16::from_le_bytes(create_fixed_buffer_2(
        data.get(6..8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let num_entries = u16::from_le_bytes(create_fixed_buffer_2(
        data.get(8..10)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let total_entries = u16::from_le_bytes(create_fixed_buffer_2(
        data.get(10..12)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let cd_size = u32::from_le_bytes(create_fixed_buffer_4(
        data.get(12..16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let cd_offset = u32::from_le_bytes(create_fixed_buffer_4(
        data.get(16..20)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));
    let comment_len = u16::from_le_bytes(create_fixed_buffer_2(
        data.get(20..22)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD"))?,
    ));

    let expected_total_size = MIN_EOCD_SIZE + comment_len as usize;
    let file_offset = buffer_offset + offset;

    // Validate that EOCD + comment fits within the file
    // Allow trailing bytes after EOCD (e.g., alignment padding or appended data)
    if file_offset + expected_total_size > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "EOCD extends beyond file end",
        ));
    }

    // Verify we have enough data in the buffer for the comment
    if data.len() < expected_total_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete EOCD comment data",
        ));
    }

    // Extract comment
    let comment = data
        .get(22..22 + comment_len as usize)
        .map(|c| c.to_vec())
        .unwrap_or_default();

    Ok(EndOfCentralDirectoryRecord {
        file_offset,
        signature,
        disk_number,
        disk_with_cd,
        num_entries,
        total_entries,
        cd_size,
        cd_offset,
        comment_len,
        comment,
    })
}

/// Create a fixed buffer of 4 bytes
pub(crate) const fn create_fixed_buffer_4(buf: &[u8]) -> [u8; 4] {
    let mut buffer = [0; 4];
    buffer.copy_from_slice(buf);
    buffer
}

/// Create a fixed buffer of 2 bytes
pub(crate) const fn create_fixed_buffer_2(buf: &[u8]) -> [u8; 2] {
    let mut buffer = [0; 2];
    buffer.copy_from_slice(buf);
    buffer
}

/// File offsets of the Module (a zip file)
///
/// <https://source.android.com/docs/security/features/apksigning/v2>
///
/// |       Content of ZIP entries      | KSU Signing Block |      Central Directory      |     End of Central Directory      |
/// |-----------------------------------|-------------------|-----------------------------|-----------------------------------|
/// | `start_content` -> `stop_content` |                   | `start_cd`   ->   `stop_cd` | `start_eocd`    ->    `stop_eocd` |
///
/// Some fields are the same as the others, but they are separated for clarity:
///
/// - [`FileOffsets::stop_cd`] and [`FileOffsets::start_eocd`] are generally the same
/// - [`FileOffsets::stop_content`] and [`FileOffsets::start_cd`] are the same if there is no KSU Signing Block
#[derive(Debug)]
pub struct FileOffsets {
    /// Start index of content
    pub start_content: usize,
    /// Stop index of content
    pub stop_content: usize,
    /// Start index of central directory
    pub start_cd: usize,
    /// Stop index of central directory
    pub stop_cd: usize,
    /// Start index of end of central directory
    pub start_eocd: usize,
    /// Stop index of end of central directory
    pub stop_eocd: usize,
}

impl FileOffsets {
    /// Create a new instance of `FileOffsets`
    pub const fn new(
        stop_content: usize,
        start_cd: usize,
        stop_cd: usize,
        stop_eocd: usize,
    ) -> Self {
        Self {
            start_content: 0,
            stop_content,
            start_cd,
            stop_cd,
            start_eocd: stop_cd,
            stop_eocd,
        }
    }

    /// Create a new instance of `FileOffsets`
    /// With only 3 arguments, the signature is not included
    pub const fn without_signature(stop_content: usize, stop_cd: usize, stop_eocd: usize) -> Self {
        Self::new(stop_content, stop_content, stop_cd, stop_eocd)
    }
}
