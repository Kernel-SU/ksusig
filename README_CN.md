# modsig

简体中文 | [English](README.md)

一个用于解码、查看、签名和验证 KernelSU Module 签名块的 Rust 库和 CLI 工具。

## 特性

- **Signature Scheme V2**：Android 风格的模块签名解码与校验
- **Source Stamp**：支持解析与校验
- **证书链校验**：结构校验 + 信任判断（内置 KernelSU Root CA P-384，或自定义根证书）
- **证书详情**：CLI 输出 subject/issuer/有效期、链长度、是否可信
- **仅支持 ECDSA**：P-256 (0x0201) 与 P-384 (0x0202)
- **自定义签名块**：使用 `KSU Sig Block 42` 魔数（非 APK 标准块）

## 安装

```sh
cargo install --git https://github.com/Kernel-SU/modsig
```

## 使用

### CLI 工具

```sh
# 快速验证
modsig verify module.zip
# 查看证书详情/链校验
modsig verify module.zip -v
# 使用自定义根证书验证
modsig verify module.zip --root my_root.pem

# 显示解析出的签名块与证书详情
modsig info module.zip
```

### Rust 库

```toml
[dependencies] # 按需选择 feature
modsig = { path = ".", default-features = false, features = ["signing", "serde", "verify"] }
```

示例代码：

```rust
use modsig::{Module, SignatureVerifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = Module::new("module.zip".into())?;
    let signing_block = module.get_signing_block()?;
    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2(&signing_block)?;
    println!("签名有效: {}", result.signature_valid);
    println!("是否被内置根信任: {}", result.is_trusted);

    Ok(())
}
```

## 支持的签名算法

本项目**仅支持 ECDSA**，不支持 RSA / DSA：

- `ECDSA_SHA2_256` (0x0201) — 使用 P-256 曲线和 SHA-256
- `ECDSA_SHA2_512` (0x0202) — 使用 P-384 曲线和 SHA-512

## Feature Flags

```toml
# 默认 features
default = ["directprint", "serde", "hash", "signing", "keystore", "verify"]

# 可选 features
signing     # 签名生成/验证（ECDSA P-256/P-384）
serde       # 序列化支持
hash        # 证书哈希函数（md5, sha1, sha256）
directprint # 解析时直接打印签名块信息
keystore    # 从 PEM/P12 载入密钥与证书
verify      # 证书链解析与 issuer/subject 匹配
```

禁用默认 features：

```toml
modsig = { path = ".", default-features = false, features = ["serde"] }
```

## 构建和测试

```sh
# 构建项目
cargo build

# 发布构建
cargo build --release

# 运行测试
cargo test --release --tests

# 代码检查
cargo clippy

# 格式化代码
cargo fmt
```

## 签名块结构

KSU Module 使用以下签名块 ID：

- `0x7109871a` - Signature Scheme V2 Block
- `0x6dff800d` - Source Stamp Block
- `0x42726577` - Verity Padding Block

魔数：`KSU Sig Block 42`

## 项目结构

```
src/
├── lib.rs              # 库入口
├── module.rs           # Module 文件解析
├── signing_block/      # KSU 签名块实现
│   ├── mod.rs         # 签名块主结构
│   ├── scheme_v2.rs   # V2 签名方案
│   ├── source_stamp.rs # 源标记签名
│   ├── algorithms.rs  # ECDSA 算法定义
│   └── digest.rs      # 哈希计算
├── zip.rs             # ZIP 文件解析
├── utils.rs           # 工具函数
├── common.rs          # 通用数据结构
└── main.rs            # CLI 入口

cli/                   # CLI 实现
└── ...
```

## 代码规范

- 所有公开项必须包含文档注释
- 禁止使用 `unwrap()`, `expect()`, `panic!()`
- 禁止直接索引，使用 `get()` 等安全替代方案
- 遵循 Rust 命名约定

## 许可证

MIT
