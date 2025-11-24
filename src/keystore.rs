//! Keystore module for loading private keys and certificates
//!
//! Supports PEM format (separate key and cert files) and P12/PKCS12 keystore format.

use crate::signing_block::algorithms::{Algorithms, PrivateKey};
use pkcs8::DecodePrivateKey;

/// Error type for keystore operations
#[derive(Debug)]
pub enum KeystoreError {
    /// Failed to read file
    IoError(String),
    /// Failed to parse PEM
    PemError(String),
    /// Failed to parse PKCS8
    Pkcs8Error(String),
    /// Failed to parse P12
    P12Error(String),
    /// Failed to parse certificate
    CertError(String),
    /// Unsupported key type
    UnsupportedKeyType(String),
    /// Password required
    PasswordRequired,
    /// Invalid password
    InvalidPassword,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::PemError(e) => write!(f, "PEM parse error: {}", e),
            Self::Pkcs8Error(e) => write!(f, "PKCS8 parse error: {}", e),
            Self::P12Error(e) => write!(f, "P12 parse error: {}", e),
            Self::CertError(e) => write!(f, "Certificate parse error: {}", e),
            Self::UnsupportedKeyType(e) => write!(f, "Unsupported key type: {}", e),
            Self::PasswordRequired => write!(f, "Password required for encrypted key"),
            Self::InvalidPassword => write!(f, "Invalid password"),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Signer credentials containing private key, certificate, and algorithm
pub struct SignerCredentials {
    /// The private key
    pub private_key: PrivateKey,
    /// The certificate in DER format
    pub certificate: Vec<u8>,
    /// The detected/recommended algorithm
    pub algorithm: Algorithms,
    /// Optional certificate chain (intermediate certificates)
    pub cert_chain: Vec<Vec<u8>>,
}

impl SignerCredentials {
    /// Create new signer credentials
    pub const fn new(
        private_key: PrivateKey,
        certificate: Vec<u8>,
        algorithm: Algorithms,
        cert_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            private_key,
            certificate,
            algorithm,
            cert_chain,
        }
    }
}

/// Load signer credentials from PEM files
///
/// # Arguments
/// * `key_path` - Path to the private key PEM file
/// * `cert_path` - Path to the certificate PEM file
/// * `password` - Optional password for encrypted private key
///
/// # Errors
/// Returns `KeystoreError` if loading fails
pub fn load_pem(
    key_path: &str,
    cert_path: &str,
    password: Option<&str>,
) -> Result<SignerCredentials, KeystoreError> {
    // Read key file
    let key_pem =
        std::fs::read_to_string(key_path).map_err(|e| KeystoreError::IoError(e.to_string()))?;

    // Read cert file
    let cert_pem =
        std::fs::read_to_string(cert_path).map_err(|e| KeystoreError::IoError(e.to_string()))?;

    load_pem_from_bytes(key_pem.as_bytes(), cert_pem.as_bytes(), password)
}

/// Load signer credentials from PEM bytes
///
/// Supports both single certificate and certificate chain files.
/// If multiple certificates are present, the first is used as the end-entity
/// certificate and the rest are stored as the certificate chain.
///
/// # Arguments
/// * `key_pem` - Private key in PEM format
/// * `cert_pem` - Certificate or certificate chain in PEM format
/// * `password` - Optional password for encrypted private key
///
/// # Errors
/// Returns `KeystoreError` if parsing fails
pub fn load_pem_from_bytes(
    key_pem: &[u8],
    cert_pem: &[u8],
    password: Option<&str>,
) -> Result<SignerCredentials, KeystoreError> {
    // Parse the private key
    let (private_key, algorithm) = parse_private_key_pem(key_pem, password)?;

    // Parse certificate chain (supports multiple certificates)
    let (certificate, cert_chain) = parse_certificate_chain_pem(cert_pem)?;

    Ok(SignerCredentials::new(
        private_key,
        certificate,
        algorithm,
        cert_chain,
    ))
}

/// Parse a private key from PEM format
/// # Errors
/// Returns an error if the PEM data is invalid or the key type is unsupported
fn parse_private_key_pem(
    pem_data: &[u8],
    password: Option<&str>,
) -> Result<(PrivateKey, Algorithms), KeystoreError> {
    let pem_str =
        std::str::from_utf8(pem_data).map_err(|e| KeystoreError::PemError(e.to_string()))?;

    // Try to parse as unencrypted PKCS8 EC key first
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str) {
        return Ok((PrivateKey::EcdsaP256(key), Algorithms::ECDSA_SHA2_256));
    }

    if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem_str) {
        return Ok((PrivateKey::EcdsaP384(key), Algorithms::ECDSA_SHA2_512));
    }

    // Try encrypted PKCS8
    if let Some(pwd) = password {
        // Try P256
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, pwd.as_bytes())
        {
            return Ok((PrivateKey::EcdsaP256(key), Algorithms::ECDSA_SHA2_256));
        }

        // Try P384
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_encrypted_pem(pem_str, pwd.as_bytes())
        {
            return Ok((PrivateKey::EcdsaP384(key), Algorithms::ECDSA_SHA2_512));
        }

        return Err(KeystoreError::InvalidPassword);
    }

    // Check if it looks like an encrypted key
    if pem_str.contains("ENCRYPTED") {
        return Err(KeystoreError::PasswordRequired);
    }

    Err(KeystoreError::UnsupportedKeyType(
        "Only ECDSA P-256 and P-384 keys are supported".to_string(),
    ))
}

/// Parse a certificate from PEM format and return DER bytes
/// # Errors
/// Returns an error if the PEM data is invalid
fn parse_certificate_pem(pem_data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let pem = pem::parse(pem_data).map_err(|e| KeystoreError::PemError(e.to_string()))?;

    if pem.tag() != "CERTIFICATE" {
        return Err(KeystoreError::CertError(format!(
            "Expected CERTIFICATE, got {}",
            pem.tag()
        )));
    }

    Ok(pem.into_contents())
}

/// Parse certificate chain from PEM format
///
/// Supports both single certificate and certificate chain files.
/// Returns (end_entity_cert, intermediate_certs)
///
/// # Arguments
/// * `pem_data` - PEM data containing one or more certificates
///
/// # Returns
/// A tuple of (end_entity_certificate, certificate_chain) where:
/// - end_entity_certificate: The first certificate (signer's certificate)
/// - certificate_chain: All subsequent certificates (intermediate CAs, root CA)
///
/// # Errors
/// Returns an error if no valid certificates are found
fn parse_certificate_chain_pem(pem_data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), KeystoreError> {
    // Try to parse multiple PEM blocks
    match pem::parse_many(pem_data) {
        Ok(pem_blocks) => {
            if pem_blocks.is_empty() {
                return Err(KeystoreError::CertError(
                    "No certificates found in PEM data".to_string(),
                ));
            }

            // Filter for CERTIFICATE blocks only
            let certs: Vec<Vec<u8>> = pem_blocks
                .into_iter()
                .filter(|pem| pem.tag() == "CERTIFICATE")
                .map(pem::Pem::into_contents)
                .collect();

            if certs.is_empty() {
                return Err(KeystoreError::CertError(
                    "No valid CERTIFICATE blocks found".to_string(),
                ));
            }

            // First cert is the end-entity, rest are intermediates/chain
            let end_entity = certs
                .first()
                .ok_or_else(|| KeystoreError::CertError("No certificates found".to_string()))?
                .clone();
            let chain: Vec<Vec<u8>> = certs.into_iter().skip(1).collect();

            Ok((end_entity, chain))
        }
        Err(_) => {
            // Fallback: try to parse as single certificate
            let cert = parse_certificate_pem(pem_data)?;
            Ok((cert, Vec::new()))
        }
    }
}

/// Load signer credentials from a P12/PKCS12 keystore file
///
/// # Arguments
/// * `path` - Path to the P12 file
/// * `password` - Password for the keystore
///
/// # Errors
/// Returns `KeystoreError` if loading fails
pub fn load_p12(path: &str, password: &str) -> Result<SignerCredentials, KeystoreError> {
    let data = std::fs::read(path).map_err(|e| KeystoreError::IoError(e.to_string()))?;
    load_p12_from_bytes(&data, password)
}

/// Load signer credentials from P12/PKCS12 bytes
///
/// # Arguments
/// * `data` - P12 file contents
/// * `password` - Password for the keystore
///
/// # Errors
/// Returns `KeystoreError` if parsing fails
pub fn load_p12_from_bytes(
    data: &[u8],
    password: &str,
) -> Result<SignerCredentials, KeystoreError> {
    let p12 = p12::PFX::parse(data).map_err(|e| KeystoreError::P12Error(format!("{:?}", e)))?;

    // Decrypt and extract keys and certs
    let keys = p12
        .key_bags(password)
        .map_err(|e| KeystoreError::P12Error(format!("Failed to extract keys: {:?}", e)))?;

    let certs = p12
        .cert_x509_bags(password)
        .map_err(|e| KeystoreError::P12Error(format!("Failed to extract certs: {:?}", e)))?;

    if keys.is_empty() {
        return Err(KeystoreError::P12Error("No private key found".to_string()));
    }

    if certs.is_empty() {
        return Err(KeystoreError::P12Error("No certificate found".to_string()));
    }

    // Get the first key (PKCS8 DER format)
    let key_der = keys
        .first()
        .ok_or_else(|| KeystoreError::P12Error("No key available".to_string()))?;

    // Try to parse as ECDSA key
    let (private_key, algorithm) = parse_private_key_der(key_der)?;

    // Get the first cert (already DER format from p12)
    let certificate = certs
        .first()
        .ok_or_else(|| KeystoreError::P12Error("No cert available".to_string()))?
        .clone();

    // Collect remaining certs as chain
    let cert_chain: Vec<Vec<u8>> = certs.iter().skip(1).cloned().collect();

    Ok(SignerCredentials::new(
        private_key,
        certificate,
        algorithm,
        cert_chain,
    ))
}

/// Parse a private key from DER format
/// # Errors
/// Returns an error if the DER data is invalid or the key type is unsupported
fn parse_private_key_der(der_data: &[u8]) -> Result<(PrivateKey, Algorithms), KeystoreError> {
    // Try P256
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der_data) {
        return Ok((PrivateKey::EcdsaP256(key), Algorithms::ECDSA_SHA2_256));
    }

    // Try P384
    if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der_data) {
        return Ok((PrivateKey::EcdsaP384(key), Algorithms::ECDSA_SHA2_512));
    }

    Err(KeystoreError::UnsupportedKeyType(
        "Only ECDSA P-256 and P-384 keys are supported".to_string(),
    ))
}

/// Load private key from DER bytes directly
///
/// # Errors
/// Returns `KeystoreError` if parsing fails
pub fn load_private_key_der(der_data: &[u8]) -> Result<(PrivateKey, Algorithms), KeystoreError> {
    parse_private_key_der(der_data)
}

/// Load certificate from DER bytes directly
///
/// # Errors
/// Returns `KeystoreError` if the data is empty
pub fn load_certificate_der(der_data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if der_data.is_empty() {
        return Err(KeystoreError::CertError(
            "Empty certificate data".to_string(),
        ));
    }
    Ok(der_data.to_vec())
}
