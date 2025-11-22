# modsig

[简体中文](README_CN.md) | English

A Rust library and CLI tool for decoding and extracting KernelSU Module signing blocks.

## Features

- **Module Signature Scheme V2** - Standard Android signature verification
- **Source Stamp** - Module source stamp signature verification
- **ECDSA Only** - Supports only ECDSA algorithms (P-256 and P-384 curves)
- **Custom Signing Block** - Uses `KSU Sig Block 42` magic (instead of standard APK signing block)

## Installation

```sh
cargo install --path .
```

## Usage

### CLI Tool

```sh
# View Module signature information
modsig module.zip

# Verify signature
modsig verify module.zip

# Show detailed information
modsig info module.zip
```

### Rust Library

```toml
[dependencies]
modsig = { path = ".", default-features = false, features = ["signing", "serde"] }
```

Example code:

```rust
use modsig::Module;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = Module::from_path("module.zip")?;

    // Get signing block
    if let Some(signing_block) = &module.signing_block {
        println!("Signing block size: {} bytes", signing_block.size);

        // Iterate through signatures
        for value_block in &signing_block.value_signing_blocks {
            println!("Signature type: {:?}", value_block);
        }
    }

    Ok(())
}
```

## Supported Signature Algorithms

This project **supports ECDSA only**, RSA and DSA are NOT supported:

- `ECDSA_SHA2_256` (0x0201) - ECDSA with P-256 curve and SHA-256
- `ECDSA_SHA2_512` (0x0202) - ECDSA with P-384 curve and SHA-512

## Feature Flags

```toml
# Default features
default = ["directprint", "serde", "hash", "signing"]

# Optional features
signing     # Signature verification (requires hash, p256, p384)
serde       # Serialization support
hash        # Certificate hash functions (md5, sha1, sha256)
directprint # Print signing block info during parsing
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
cargo test

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
