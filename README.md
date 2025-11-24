# modsig

[简体中文](README_CN.md) | English

A Rust library and CLI tool for decoding, inspecting, signing and verifying KernelSU Module signing blocks.

## Features

- **Signature Scheme V2**: Android-style module signature decoding & verification.
- **Source Stamp**: Stamp parsing and verification.
- **Certificate chain**: Validation plus trust check via built-in KernelSU Root CA (P-384) or custom roots.
- **Detailed certificate info**: CLI shows subject/issuer/validity, chain length, trust result.
- **ECDSA only**: P-256 (0x0201) & P-384 (0x0202).
- **Custom block**: Uses `KSU Sig Block 42` magic instead of the APK block.

## Installation

```sh
cargo install --git https://github.com/Kernel-SU/modsig
```

## Usage

### CLI Tool

```sh
# Quick verify
modsig verify module.zip
# Verbose (shows certificate details, chain/trust)
modsig verify module.zip -v
# Verify with custom root CA
modsig verify module.zip --root my_root.pem

# Show parsed signing block + certificate details
modsig info module.zip
```

### Rust Library

```toml
[dependencies] # adjust features as needed
modsig = { path = ".", default-features = false, features = ["signing", "serde", "verify"] }
```

Example code:

```rust
use modsig::{Module, SignatureVerifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = Module::new("module.zip".into())?;
    let signing_block = module.get_signing_block()?;
    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2(&signing_block)?;
    println!("Signature valid: {}", result.signature_valid);
    println!("Trusted by built-in roots: {}", result.is_trusted);

    Ok(())
}
```

## Supported Signature Algorithms

This project **supports ECDSA only** (RSA/DSA unsupported):

- `ECDSA_SHA2_256` (0x0201) — ECDSA P-256 + SHA-256
- `ECDSA_SHA2_512` (0x0202) — ECDSA P-384 + SHA-512

## Feature Flags

```toml
# Default features
default = ["directprint", "serde", "hash", "signing", "keystore", "verify"]

# Optional features
signing      # Signature encode/verify (ECDSA P-256/P-384)
serde        # Serialization support
hash         # Hash helpers (md5, sha1, sha256)
directprint  # Print signing block while parsing
keystore     # Load keys/certs from PEM/P12
verify       # Certificate chain parsing/issuer matching
```

Disable default features:

```toml
modsig = { path = ".", default-features = false, features = ["serde"] }
```

## Build and Test

```sh
# Build the project
cargo build

# Release build
cargo build --release

# Run tests
cargo test --release --tests

# Run clippy
cargo clippy

# Format code
cargo fmt
```

## Signing Block Structure

KSU Module uses the following signing block IDs:

- `0x7109871a` - Signature Scheme V2 Block
- `0x6dff800d` - Source Stamp Block
- `0x42726577` - Verity Padding Block

Magic number: `KSU Sig Block 42`

## Project Structure

```
src/
├── lib.rs              # Library entry point
├── module.rs           # Module file parsing
├── signing_block/      # KSU signing block implementation
│   ├── mod.rs         # Signing block main structure
│   ├── scheme_v2.rs   # V2 signature scheme
│   ├── source_stamp.rs # Source stamp signature
│   ├── algorithms.rs  # ECDSA algorithm definitions
│   └── digest.rs      # Hash calculations
├── zip.rs             # ZIP file parsing
├── utils.rs           # Utility functions
├── common.rs          # Common data structures
└── main.rs            # CLI entry point

cli/                   # CLI implementation
└── ...
```

## Code Style

- All public items must have documentation comments
- Avoid `unwrap()`, `expect()`, `panic!()`
- Avoid direct indexing, use safe alternatives like `get()`
- Follow Rust naming conventions

## License

MIT
