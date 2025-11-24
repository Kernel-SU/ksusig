# KSU Module Signing Guide

This guide demonstrates how to sign a KSU module using OpenSSL and verify the signature.

## Prerequisites

- OpenSSL installed
- modsig CLI tool built (`cargo build --release`)

## Step 1: Generate Signing Keys

### Option A: Generate P-384 Key Pair (Recommended)

```bash
# Generate P-384 private key
openssl ecparam -genkey -name secp384r1 -out test_p384.key

# Generate certificate signing request (CSR)
openssl req -new -key test_p384.key \
  -out test_p384.csr \
  -subj "/CN=Test Module Signer/O=Test/C=US"

# Self-sign the certificate (valid for 10 years)
openssl x509 -req -days 3650 \
  -in test_p384.csr \
  -signkey test_p384.key \
  -out test_p384.crt

# Convert to PKCS#8 format (required by modsig)
openssl pkcs8 -topk8 -nocrypt \
  -in test_p384.key \
  -out test_p384_pkcs8.key
```

### Option B: Generate P-256 Key Pair

```bash
# Generate P-256 private key
openssl ecparam -genkey -name prime256v1 -out test_p256.key

# Generate certificate signing request (CSR)
openssl req -new -key test_p256.key \
  -out test_p256.csr \
  -subj "/CN=Test Module Signer/O=Test/C=US"

# Self-sign the certificate (valid for 10 years)
openssl x509 -req -days 3650 \
  -in test_p256.csr \
  -signkey test_p256.key \
  -out test_p256.crt

# Convert to PKCS#8 format
openssl pkcs8 -topk8 -nocrypt \
  -in test_p256.key \
  -out test_p256_pkcs8.key
```

### Option C: Create PKCS#12 Keystore

```bash
# Create P12 keystore from P-384 key and certificate
openssl pkcs12 -export \
  -in test_p384.crt \
  -inkey test_p384.key \
  -out test_p384.p12 \
  -name "test_signer" \
  -password pass:test123

# Or for P-256
openssl pkcs12 -export \
  -in test_p256.crt \
  -inkey test_p256.key \
  -out test_p256.p12 \
  -name "test_signer" \
  -password pass:test123
```

## Step 2: Sign a Module

### Using PEM Key and Certificate

```bash
# Sign with P-384 (default algorithm: ecdsa256)
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_ksu_signed.zip \
  --key test_p384_pkcs8.key \
  --cert test_p384.crt

# Sign with P-384 using ecdsa384 algorithm
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_ksu_signed_384.zip \
  --key test_p384_pkcs8.key \
  --cert test_p384.crt \
  --algorithm ecdsa384

# Sign with P-256
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_ksu_signed_256.zip \
  --key test_p256_pkcs8.key \
  --cert test_p256.crt \
  --algorithm ecdsa256
```

### Using PKCS#12 Keystore

```bash
# Sign with P12 keystore
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_ksu_signed.zip \
  --p12 test_p384.p12 \
  --password test123
```

### Sign with Source Stamp (Optional)

```bash
# Generate source stamp keys (if not already generated)
openssl ecparam -genkey -name secp384r1 -out stamp_p384.key
openssl req -new -key stamp_p384.key \
  -out stamp_p384.csr \
  -subj "/CN=Source Stamp/O=Test/C=US"
openssl x509 -req -days 3650 \
  -in stamp_p384.csr \
  -signkey stamp_p384.key \
  -out stamp_p384.crt
openssl pkcs8 -topk8 -nocrypt \
  -in stamp_p384.key \
  -out stamp_p384_pkcs8.key

# Sign with both V2 and Source Stamp
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_dual_signed.zip \
  --key test_p384_pkcs8.key \
  --cert test_p384.crt \
  --stamp-key stamp_p384_pkcs8.key \
  --stamp-cert stamp_p384.crt \
  --algorithm ecdsa384
```

## Step 3: Verify the Signature

### Verify with Built-in Root CA

```bash
# Basic verification (uses built-in KernelSU Root CA P-384)
cargo run --release -- verify test_ksu_signed.zip

# Verbose verification
cargo run --release -- verify test_ksu_signed.zip --verbose
```

### Verify with Custom Root Certificate

```bash
# If you want to trust your self-signed certificate, use it as root
cargo run --release -- verify test_ksu_signed.zip \
  --root test_p384.crt \
  --verbose
```

## Step 4: Display Signing Block Information

```bash
# Show signing block details
cargo run --release -- info test_ksu_signed.zip
```

Expected output:
```
File: test_ksu_signed.zip
File size: XXXXX bytes

✓ KSU signing block found
  Location: XXXX - XXXX
  Size: XXX bytes

Signing block contents:
  ✓ V2 Signature Scheme
  ✓ Source Stamp (if present)
```

## Step 5: Create Root CA and Sign with Certificate Chain

For production use, you should create a proper CA hierarchy:

```bash
# 1. Generate Root CA
openssl ecparam -genkey -name secp384r1 -out root_ca.key
openssl req -new -x509 -days 7300 -key root_ca.key \
  -out root_ca.crt \
  -subj "/CN=KernelSU Root CA P-384/O=KernelSU"

# 2. Generate intermediate certificate (signed by root)
openssl ecparam -genkey -name secp384r1 -out intermediate.key
openssl req -new -key intermediate.key \
  -out intermediate.csr \
  -subj "/CN=Module Signer/O=Developer/C=US"
openssl x509 -req -days 3650 \
  -in intermediate.csr \
  -CA root_ca.crt \
  -CAkey root_ca.key \
  -CAcreateserial \
  -out intermediate.crt

# 3. Convert intermediate key to PKCS#8
openssl pkcs8 -topk8 -nocrypt \
  -in intermediate.key \
  -out intermediate_pkcs8.key

# 4. Sign module with intermediate certificate
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  test_ca_signed.zip \
  --key intermediate_pkcs8.key \
  --cert intermediate.crt \
  --algorithm ecdsa384

# 5. Verify with root CA
cargo run --release -- verify test_ca_signed.zip \
  --root root_ca.crt \
  --verbose
```

## Complete Example Script

Here's a complete script that does everything:

```bash
#!/bin/bash
set -e

echo "=== KSU Module Signing Example ==="
echo

# 1. Generate keys
echo "Step 1: Generating P-384 key pair..."
openssl ecparam -genkey -name secp384r1 -out my_key.key
openssl req -new -key my_key.key -out my_cert.csr \
  -subj "/CN=My Module Signer/O=MyOrg/C=US"
openssl x509 -req -days 3650 -in my_cert.csr \
  -signkey my_key.key -out my_cert.crt
openssl pkcs8 -topk8 -nocrypt -in my_key.key -out my_key_pkcs8.key
echo "✓ Keys generated"
echo

# 2. Sign module
echo "Step 2: Signing module..."
cargo run --release -- sign \
  tests/fixtures/test_unsigned.zip \
  my_signed_module.zip \
  --key my_key_pkcs8.key \
  --cert my_cert.crt \
  --algorithm ecdsa384
echo "✓ Module signed"
echo

# 3. Verify signature
echo "Step 3: Verifying signature..."
cargo run --release -- verify my_signed_module.zip \
  --root my_cert.crt \
  --verbose
echo "✓ Signature verified"
echo

# 4. Display info
echo "Step 4: Displaying signing block info..."
cargo run --release -- info my_signed_module.zip
echo

echo "=== Complete! ==="
```

## Notes

- **Algorithm Selection**:
  - Use `ecdsa256` for P-256 curves with SHA-256
  - Use `ecdsa384` for P-384 curves with SHA-512

- **Built-in Root CA**: The tool includes the official KernelSU Root CA P-384 certificate for verifying officially signed modules.

- **Trust Chain**: For modules to be trusted without `--root` flag, they must be signed by a certificate that chains to the built-in KernelSU Root CA.

- **Self-Signed Certificates**: For testing, you can use self-signed certificates with the `--root` flag to explicitly trust them.

## Troubleshooting

### Error: "Invalid key file path"
- Make sure your key is in PKCS#8 format
- Use `openssl pkcs8 -topk8` to convert

### Error: "Must specify --key/--cert or --p12"
- You need to provide either:
  - Both `--key` and `--cert`, OR
  - A `--p12` keystore with `--password`

### Error: "Unsupported algorithm"
- Only `ecdsa256` and `ecdsa384` are supported
- RSA and DSA are not supported

### Verification fails with "Untrusted certificate"
- Use `--root` to specify your root CA certificate
- Or ensure the signing certificate chains to the built-in KernelSU Root CA
