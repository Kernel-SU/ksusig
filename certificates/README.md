# KSU 测试证书

本目录包含用于 KernelSU 模块签名的测试证书和密钥。

⚠️ **警告：这些证书仅用于测试目的，不应在生产环境中使用！**

## 目录结构

```
certificates/
├── root_ca/              # 根证书颁发机构
│   ├── root_ca_p256.key  # ECDSA P-256 根证书私钥
│   ├── root_ca_p256.crt  # ECDSA P-256 根证书
│   ├── root_ca_p384.key  # ECDSA P-384 根证书私钥
│   └── root_ca_p384.crt  # ECDSA P-384 根证书
└── test_keys/            # 测试签名密钥
    ├── test_p256.key     # ECDSA P-256 测试私钥
    ├── test_p256.crt     # ECDSA P-256 测试证书（由 root_ca_p256 签发）
    ├── test_p384.key     # ECDSA P-384 测试私钥
    └── test_p384.crt     # ECDSA P-384 测试证书（由 root_ca_p384 签发）
```

## 证书信息

### ECDSA P-256 证书

- **曲线**: prime256v1 (secp256r1)
- **签名算法**: ECDSA with SHA-256
- **根证书 DN**: CN=KSU Test Root CA P-256, O=KernelSU, C=US
- **签名者 DN**: CN=KSU Test Signer P-256, O=KernelSU, C=US
- **有效期**:
  - 根证书: 10 年
  - 签名证书: 1 年

### ECDSA P-384 证书

- **曲线**: secp384r1
- **签名算法**: ECDSA with SHA-384
- **根证书 DN**: CN=KSU Test Root CA P-384, O=KernelSU, C=US
- **签名者 DN**: CN=KSU Test Signer P-384, O=KernelSU, C=US
- **有效期**:
  - 根证书: 10 年
  - 签名证书: 1 年

## 使用方法

### 签名模块 (V2 签名)

```bash
# 使用 P-256 密钥签名
apksig sign input.zip output.zip \
  --key test_keys/test_p256.key \
  --cert test_keys/test_p256.crt

# 使用 P-384 密钥签名
apksig sign input.zip output.zip \
  --key test_keys/test_p384.key \
  --cert test_keys/test_p384.crt
```

### 验证签名

```bash
# 使用默认的内置根证书验证
apksig verify signed_module.zip

# 使用自定义根证书验证
apksig verify signed_module.zip \
  --root root_ca/root_ca_p256.crt
```

### 双重签名 (V2 + Source Stamp)

```bash
apksig sign input.zip output.zip \
  --v2-key test_keys/test_p256.key \
  --v2-cert test_keys/test_p256.crt \
  --stamp-key test_keys/test_p384.key \
  --stamp-cert test_keys/test_p384.crt
```

## 重新生成证书

如需重新生成测试证书，可使用以下命令：

### 生成 P-256 证书

```bash
# 生成根证书
openssl ecparam -genkey -name prime256v1 -out root_ca/root_ca_p256.key
openssl req -new -x509 -days 3650 -key root_ca/root_ca_p256.key \
  -out root_ca/root_ca_p256.crt \
  -subj "/CN=KSU Test Root CA P-256/O=KernelSU/C=US"

# 生成测试密钥和证书
openssl ecparam -genkey -name prime256v1 -out test_keys/test_p256.key
openssl req -new -key test_keys/test_p256.key \
  -out test_keys/test_p256.csr \
  -subj "/CN=KSU Test Signer P-256/O=KernelSU/C=US"
openssl x509 -req -in test_keys/test_p256.csr \
  -CA root_ca/root_ca_p256.crt \
  -CAkey root_ca/root_ca_p256.key \
  -CAcreateserial -days 365 \
  -out test_keys/test_p256.crt
```

### 生成 P-384 证书

```bash
# 生成根证书
openssl ecparam -genkey -name secp384r1 -out root_ca/root_ca_p384.key
openssl req -new -x509 -days 3650 -key root_ca/root_ca_p384.key \
  -out root_ca/root_ca_p384.crt \
  -subj "/CN=KSU Test Root CA P-384/O=KernelSU/C=US"

# 生成测试密钥和证书
openssl ecparam -genkey -name secp384r1 -out test_keys/test_p384.key
openssl req -new -key test_keys/test_p384.key \
  -out test_keys/test_p384.csr \
  -subj "/CN=KSU Test Signer P-384/O=KernelSU/C=US"
openssl x509 -req -in test_keys/test_p384.csr \
  -CA root_ca/root_ca_p384.crt \
  -CAkey root_ca/root_ca_p384.key \
  -CAcreateserial -days 365 \
  -out test_keys/test_p384.crt
```

## 查看证书信息

```bash
# 查看证书详细信息
openssl x509 -in test_keys/test_p256.crt -text -noout

# 验证证书链
openssl verify -CAfile root_ca/root_ca_p256.crt test_keys/test_p256.crt

# 查看私钥信息
openssl ec -in test_keys/test_p256.key -text -noout
```

## 安全注意事项

1. **私钥保护**: 所有 `.key` 文件的权限应设置为 600 (仅所有者可读写)
2. **仅供测试**: 这些证书是自签名的测试证书，不应用于生产环境
3. **密钥管理**: 生产环境应使用硬件安全模块 (HSM) 或密钥管理服务 (KMS)
4. **证书轮换**: 定期更新生产环境的签名证书和密钥
5. **根证书保护**: 根证书私钥应离线存储，妥善保管

## 支持的算法

本项目仅支持 ECDSA 算法：
- ✅ ECDSA P-256 (prime256v1) with SHA-256
- ✅ ECDSA P-384 (secp384r1) with SHA-512
- ❌ RSA (不支持)
- ❌ DSA (不支持)
