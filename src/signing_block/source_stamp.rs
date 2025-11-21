//! Source Stamp Signature Scheme
//! <https://source.android.com/docs/security/features/apksigning/v2#source-stamp>

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::add_space;
use crate::common::{AdditionalAttributes, Certificates, Digests, PubKey, Signatures};
use crate::utils::print_string;
use crate::MyReader;

/// Source Stamp Block ID (V2)
pub const SOURCE_STAMP_BLOCK_ID: u32 = 0x6dff_800d;

/// Source Stamp Certificate Hash ZIP Entry Name
pub const SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME: &str = "stamp-cert-sha256";

/// Stamp Time Attribute ID
pub const STAMP_TIME_ATTR_ID: u32 = 0xe43c_5946;

/// The `SourceStamp` struct represents the source stamp signature scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SourceStamp {
    /// The size of the source stamp.
    pub size: usize,

    /// The ID of the source stamp.
    pub id: u32,

    /// The stamp block data.
    pub stamp_block: StampBlock,
}

impl SourceStamp {
    /// Create a new source stamp
    pub const fn new(stamp_block: StampBlock) -> Self {
        Self {
            size: stamp_block.size,
            id: SOURCE_STAMP_BLOCK_ID,
            stamp_block,
        }
    }

    /// Parse the source stamp
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(size: usize, id: u32, data: &mut MyReader) -> Result<Self, String> {
        add_space!(4);
        print_string!("Source Stamp Block:");
        let stamp_block = StampBlock::parse(data)?;
        Ok(Self {
            size,
            id,
            stamp_block,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self.stamp_block.to_u8();
        [(self.size as u64).to_le_bytes().to_vec(), self.id.to_le_bytes().to_vec(), content]
            .concat()
    }
}

/// The `StampBlock` struct represents the stamp block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StampBlock {
    /// The size of the stamp block.
    pub size: usize,

    /// The signed data of the stamp.
    pub signed_data: SignedData,

    /// The signatures of the stamp.
    pub signatures: Signatures,

    /// The public key of the stamp.
    pub public_key: PubKey,
}

impl StampBlock {
    /// Create a new stamp block
    pub fn new(signed_data: SignedData, signatures: Signatures, public_key: PubKey) -> Self {
        let size = mem::size_of::<u32>() + signed_data.size()
            + mem::size_of::<u32>() + signatures.size
            + mem::size_of::<u32>() + public_key.size;
        Self {
            size,
            signed_data,
            signatures,
            public_key,
        }
    }

    /// Parse the stamp block
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_stamp_block = data.read_size()?;
        add_space!(4);
        print_string!("size_stamp_block: {}", size_stamp_block);

        let data = &mut data.as_slice(size_stamp_block)?;

        let signed_data = SignedData::parse(data)?;
        let signatures = Signatures::parse(data)?;
        let public_key = PubKey::parse(data)?;

        Ok(Self {
            size: size_stamp_block,
            signed_data,
            signatures,
            public_key,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        [
            (self.size as u32).to_le_bytes().to_vec(),
            self.signed_data.to_u8(),
            self.signatures.to_u8(),
            self.public_key.to_u8(),
        ]
        .concat()
    }
}

/// The `SignedData` struct represents the signed data of the stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedData {
    /// The digests of the stamp.
    pub digests: Digests,

    /// The certificates of the stamp.
    pub certificates: Certificates,

    /// The additional attributes of the stamp.
    pub additional_attributes: AdditionalAttributes,
}

impl SignedData {
    /// Create a new signed data
    pub const fn new(
        digests: Digests,
        certificates: Certificates,
        additional_attributes: AdditionalAttributes,
    ) -> Self {
        Self {
            digests,
            certificates,
            additional_attributes,
        }
    }

    /// Parse the signed data
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signed_data = data.read_size()?;
        add_space!(4);
        print_string!("size_signed_data: {}", size_signed_data);

        let data = &mut data.as_slice(size_signed_data)?;

        let digests = Digests::parse(data)?;
        let certificates = Certificates::parse(data)?;
        let additional_attributes = AdditionalAttributes::parse(data)?;

        Ok(Self {
            digests,
            certificates,
            additional_attributes,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.digests.to_u8(),
            self.certificates.to_u8(),
            self.additional_attributes.to_u8(),
        ]
        .concat();
        [(content.len() as u32).to_le_bytes().to_vec(), content].concat()
    }

    /// Size of the signed data
    pub fn size(&self) -> usize {
        self.digests.size
            + self.certificates.size
            + self.additional_attributes.size
            + mem::size_of::<u32>() * 3 // size prefixes for each component
    }
}
