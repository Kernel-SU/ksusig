//! ELF section digest calculation

#![cfg(feature = "elf")]

use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

use crate::signing_block::algorithms::Algorithms;

/// Chunk size (1MB)
const CHUNK_SIZE: usize = 1 << 20;

/// Start byte for chunk
const START_BYTE_CHUNK: u8 = 0xa5;

/// Start byte for final chunk
const START_BYTE_END_CHUNK: u8 = 0x5a;

/// Digest a single chunk
fn digest_chunk(chunk: &[u8], algo: &Algorithms) -> Vec<u8> {
    let chunk_size = (chunk.len() as u32).to_le_bytes().to_vec();
    let mut data = vec![START_BYTE_CHUNK];
    data.extend(chunk_size);
    data.extend(chunk);
    algo.hash(&data)
}

/// Calculate final digest from chunk digests
fn digest_final(chunks: Vec<Vec<u8>>, algo: &Algorithms) -> Vec<u8> {
    let mut final_chunk = vec![START_BYTE_END_CHUNK];
    final_chunk.extend((chunks.len() as u32).to_le_bytes());
    final_chunk.extend(chunks.concat());
    algo.hash(&final_chunk)
}

/// Calculate digest for ELF sections
///
/// # Arguments
/// * `file` - ELF file reader
/// * `sections` - List of sections to digest (name, offset, size)
/// * `algo` - Digest algorithm
///
/// # Returns
/// Combined digest of all sections
///
/// # Errors
/// Returns error if file cannot be read
pub fn digest_elf_sections<R: Read + Seek>(
    file: &mut R,
    sections: &[(String, u64, u64)],
    algo: &Algorithms,
) -> Result<Vec<u8>, io::Error> {
    let mut all_chunk_digests = Vec::new();

    // Note: sections are expected to be pre-sorted by offset from collect_sections()
    for (_name, offset, size) in sections {
        // Calculate chunked digest for each section
        file.seek(SeekFrom::Start(*offset))?;
        let taker = file.take(*size);
        let mut reader = BufReader::with_capacity(CHUNK_SIZE, taker);

        loop {
            let chunk = reader.fill_buf()?;
            let length = chunk.len();
            if length == 0 {
                break;
            }
            all_chunk_digests.push(digest_chunk(chunk, algo));
            reader.consume(length);
        }

        // Reset for next section
        file.seek(SeekFrom::Start(0))?;
    }

    // Calculate final digest
    let final_digest = digest_final(all_chunk_digests, algo);
    Ok(final_digest)
}
