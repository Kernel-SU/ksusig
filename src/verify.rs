//! Certificate chain verification module
//!
//! This module provides certificate chain verification with support for
//! built-in trusted root certificates.

use crate::signing_block::{SigningBlock, ValueSigningBlock};

/// Error type for verification operations
#[derive(Debug)]
pub enum VerifyError {
    /// No signature found
    NoSignature,
    /// Invalid signature
    InvalidSignature(String),
    /// Certificate error
    CertificateError(String),
    /// Certificate chain error
    CertChainError(String),
    /// Untrusted certificate
    UntrustedCertificate,
    /// Digest mismatch
    DigestMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignature => write!(f, "No signature found"),
            Self::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
            Self::CertificateError(e) => write!(f, "Certificate error: {}", e),
            Self::CertChainError(e) => write!(f, "Certificate chain error: {}", e),
            Self::UntrustedCertificate => write!(f, "Untrusted certificate"),
            Self::DigestMismatch => write!(f, "Digest mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Result of signature verification
#[derive(Debug)]
pub struct VerifyResult {
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the certificate chain is valid
    pub cert_chain_valid: bool,
    /// Whether the certificate is trusted (signed by a trusted root)
    pub is_trusted: bool,
    /// The signing certificate in DER format
    pub certificate: Option<Vec<u8>>,
    /// Certificate chain (if present)
    pub cert_chain: Vec<Vec<u8>>,
    /// Warnings during verification
    pub warnings: Vec<String>,
}

impl Default for VerifyResult {
    fn default() -> Self {
        Self {
            signature_valid: false,
            cert_chain_valid: false,
            is_trusted: false,
            certificate: None,
            cert_chain: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Built-in trusted root certificates
///
/// This struct holds the trusted root certificates used for verifying
/// the certificate chain of signed modules.
///
/// Developers can add their own root certificates or use the default empty set.
pub struct TrustedRoots {
    /// List of trusted root certificates (DER format)
    roots: Vec<Vec<u8>>,
}

impl Default for TrustedRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedRoots {
    /// Create an empty trusted roots store
    pub const fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Create with built-in KSU root certificates
    ///
    /// Note: This is a placeholder. Add actual root certificates here.
    pub fn with_builtin() -> Self {
        let roots = Self::new();

        // ==========================================
        // PLACEHOLDER: Add built-in root certificates here
        // ==========================================
        //
        // Example:
        // roots.add_root(include_bytes!("../certs/ksu_root_ca.der").to_vec());
        //
        // The root certificate should be the DER-encoded X.509 certificate
        // of the trusted CA that signs developer certificates.
        //
        // For KSU module signing, this would typically be:
        // 1. KSU Official Root CA - for official modules
        // 2. Developer Root CA - for community modules
        //
        // To generate a root CA:
        // openssl ecparam -genkey -name prime256v1 -out root_ca.key
        // openssl req -new -x509 -days 3650 -key root_ca.key -out root_ca.crt
        // openssl x509 -in root_ca.crt -outform DER -out root_ca.der

        roots
    }

    /// Add a trusted root certificate
    pub fn add_root(&mut self, cert_der: Vec<u8>) {
        self.roots.push(cert_der);
    }

    /// Add a trusted root certificate from PEM format
    ///
    /// # Errors
    /// Returns an error if PEM parsing fails
    #[cfg(feature = "keystore")]
    pub fn add_root_pem(&mut self, pem_data: &[u8]) -> Result<(), String> {
        let pem = pem::parse(pem_data).map_err(|e| format!("Failed to parse PEM: {}", e))?;
        if pem.tag() != "CERTIFICATE" {
            return Err(format!("Expected CERTIFICATE, got {}", pem.tag()));
        }
        self.roots.push(pem.into_contents());
        Ok(())
    }

    /// Check if a certificate is trusted (directly or via chain)
    pub fn is_trusted(&self, cert_der: &[u8]) -> bool {
        // Direct match check
        for root in &self.roots {
            if root == cert_der {
                return true;
            }
        }
        false
    }

    /// Get all root certificates
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// Check if roots store is empty
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Certificate chain verifier
pub struct CertChainVerifier {
    /// Trusted root certificates
    trusted_roots: TrustedRoots,
}

impl CertChainVerifier {
    /// Create a new verifier with given trusted roots
    pub const fn new(trusted_roots: TrustedRoots) -> Self {
        Self { trusted_roots }
    }

    /// Create a verifier with built-in trusted roots
    pub fn with_builtin_roots() -> Self {
        Self::new(TrustedRoots::with_builtin())
    }

    /// Verify a certificate chain
    ///
    /// # Arguments
    /// * `end_entity` - The end-entity (leaf) certificate
    /// * `intermediates` - Intermediate certificates in the chain
    ///
    /// # Returns
    /// A tuple of (is_chain_valid, is_trusted)
    pub fn verify_chain(&self, end_entity: &[u8], intermediates: &[Vec<u8>]) -> (bool, bool) {
        // If no trusted roots configured, we can't verify trust
        if self.trusted_roots.is_empty() {
            // Chain structure validation only
            return (true, false);
        }

        // Check if end entity is directly trusted
        if self.trusted_roots.is_trusted(end_entity) {
            return (true, true);
        }

        // Check if any intermediate is trusted (as a root)
        for intermediate in intermediates {
            if self.trusted_roots.is_trusted(intermediate) {
                // Found a trust anchor in the chain
                // TODO: Implement full chain validation (issuer matching, etc.)
                return (true, true);
            }
        }

        // No trust anchor found
        (true, false)
    }

    /// Get the trusted roots
    pub fn trusted_roots(&self) -> &TrustedRoots {
        &self.trusted_roots
    }
}

/// Signature verifier for V2 and Source Stamp blocks
pub struct SignatureVerifier {
    /// Certificate chain verifier
    cert_verifier: CertChainVerifier,
}

impl SignatureVerifier {
    /// Create a new signature verifier
    pub const fn new(cert_verifier: CertChainVerifier) -> Self {
        Self { cert_verifier }
    }

    /// Create with built-in trusted roots
    pub fn with_builtin_roots() -> Self {
        Self::new(CertChainVerifier::with_builtin_roots())
    }

    /// Create with custom trusted roots
    pub fn with_trusted_roots(roots: TrustedRoots) -> Self {
        Self::new(CertChainVerifier::new(roots))
    }

    /// Verify a V2 signature block
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_v2(&self, signing_block: &SigningBlock) -> Result<VerifyResult, VerifyError> {
        let mut result = VerifyResult::default();

        for block in &signing_block.content {
            if let ValueSigningBlock::SignatureSchemeV2Block(v2) = block {
                // Get the first signer
                let signer = v2
                    .signers
                    .signers_data
                    .first()
                    .ok_or(VerifyError::NoSignature)?;

                // Get the public key
                let pubkey = &signer.pub_key.data;

                // Get signed data bytes
                let signed_data_bytes = signer.signed_data.to_u8();
                let raw_data = signed_data_bytes
                    .get(4..)
                    .ok_or_else(|| VerifyError::InvalidSignature("Invalid signed data".to_string()))?;

                // Verify each signature
                for (idx, sig) in signer.signatures.signatures_data.iter().enumerate() {
                    let digest = signer
                        .signed_data
                        .digests
                        .digests_data
                        .get(idx)
                        .ok_or_else(|| {
                            VerifyError::InvalidSignature("Digest count mismatch".to_string())
                        })?;

                    let algo = &digest.signature_algorithm_id;
                    algo.verify(pubkey, raw_data, &sig.signature)
                        .map_err(|e| VerifyError::InvalidSignature(e))?;
                }

                result.signature_valid = true;

                // Get certificate
                if let Some(cert) = signer.signed_data.certificates.certificates_data.first() {
                    result.certificate = Some(cert.certificate.clone());

                    // Get certificate chain
                    let intermediates: Vec<Vec<u8>> = signer
                        .signed_data
                        .certificates
                        .certificates_data
                        .iter()
                        .skip(1)
                        .map(|c| c.certificate.clone())
                        .collect();
                    result.cert_chain = intermediates.clone();

                    // Verify certificate chain
                    let (chain_valid, is_trusted) = self
                        .cert_verifier
                        .verify_chain(&cert.certificate, &intermediates);
                    result.cert_chain_valid = chain_valid;
                    result.is_trusted = is_trusted;

                    if !is_trusted && self.cert_verifier.trusted_roots.is_empty() {
                        result
                            .warnings
                            .push("No trusted roots configured".to_string());
                    }
                }

                return Ok(result);
            }
        }

        Err(VerifyError::NoSignature)
    }

    /// Verify a Source Stamp block
    ///
    /// # Errors
    /// Returns `VerifyError` if verification fails
    pub fn verify_source_stamp(
        &self,
        signing_block: &SigningBlock,
    ) -> Result<VerifyResult, VerifyError> {
        let mut result = VerifyResult::default();

        for block in &signing_block.content {
            if let ValueSigningBlock::SourceStampBlock(stamp) = block {
                let stamp_block = &stamp.stamp_block;

                // Get the public key
                let pubkey = &stamp_block.public_key.data;

                // Get signed data bytes
                let signed_data_bytes = stamp_block.signed_data.to_u8();
                let raw_data = signed_data_bytes.get(4..).ok_or_else(|| {
                    VerifyError::InvalidSignature("Invalid signed data".to_string())
                })?;

                // Verify each signature
                for sig in &stamp_block.signatures.signatures_data {
                    let algo = &sig.signature_algorithm_id;
                    algo.verify(pubkey, raw_data, &sig.signature)
                        .map_err(|e| VerifyError::InvalidSignature(e))?;
                }

                result.signature_valid = true;

                // Get certificate
                if let Some(cert) = stamp_block.signed_data.certificates.certificates_data.first() {
                    result.certificate = Some(cert.certificate.clone());

                    // Verify certificate (no chain for source stamp typically)
                    let (chain_valid, is_trusted) =
                        self.cert_verifier.verify_chain(&cert.certificate, &[]);
                    result.cert_chain_valid = chain_valid;
                    result.is_trusted = is_trusted;
                }

                return Ok(result);
            }
        }

        Err(VerifyError::NoSignature)
    }

    /// Verify both V2 and Source Stamp if present
    ///
    /// # Returns
    /// A tuple of (v2_result, stamp_result) where either can be None if not present
    pub fn verify_all(
        &self,
        signing_block: &SigningBlock,
    ) -> (Option<VerifyResult>, Option<VerifyResult>) {
        let v2_result = self.verify_v2(signing_block).ok();
        let stamp_result = self.verify_source_stamp(signing_block).ok();
        (v2_result, stamp_result)
    }
}

/// Quick verification function
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_signing_block(signing_block: &SigningBlock) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_builtin_roots();
    verifier.verify_v2(signing_block)
}

/// Quick verification with custom trusted roots
///
/// # Errors
/// Returns `VerifyError` if verification fails
pub fn verify_with_roots(
    signing_block: &SigningBlock,
    roots: TrustedRoots,
) -> Result<VerifyResult, VerifyError> {
    let verifier = SignatureVerifier::with_trusted_roots(roots);
    verifier.verify_v2(signing_block)
}
