# modsig

简体中文 | [English](README.md)

一个用于解码和提取 KernelSU Module 签名块的 Rust 库和 CLI 工具。

## 特性

- **Module Signature Scheme V2** - 标准 Android 签名验证
- **Source Stamp** - Module 源标记签名验证
- **ECDSA 专用** - 仅支持 ECDSA 算法（P-256 和 P-384 曲线）
- **自定义签名块** - 使用 `KSU Sig Block 42` 魔数（而非标准 APK 签名块）

## 安装

```sh
cargo install --path .
```

## 使用

### CLI 工具

```sh
# 查看 Module 签名信息
modsig module.zip

# 验证签名
modsig verify module.zip

# 显示详细信息
modsig info module.zip
```

### Rust 库

```toml
[dependencies]
modsig = { path = ".", default-features = false, features = ["signing", "serde"] }
```

示例代码：

```rust
use modsig::Module;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = Module::from_path("module.zip")?;

    // 获取签名块
    if let Some(signing_block) = &module.signing_block {
        println!("签名块大小: {} 字节", signing_block.size);

        // 遍历签名
        for value_block in &signing_block.value_signing_blocks {
            println!("签名类型: {:?}", value_block);
        }
    }

    Ok(())
}
```

## 支持的签名算法

本项目**仅支持 ECDSA** 算法，不支持 RSA 和 DSA：

- `ECDSA_SHA2_256` (0x0201) - 使用 P-256 曲线和 SHA-256
- `ECDSA_SHA2_512` (0x0202) - 使用 P-384 曲线和 SHA-512

## Feature Flags

```toml
# 默认 features
default = ["directprint", "serde", "hash", "signing"]

# 可选 features
signing    # 签名验证功能（需要 hash, p256, p384）
serde      # 序列化支持
hash       # 证书哈希函数（md5, sha1, sha256）
directprint # 解析时直接打印签名块信息
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
cargo test

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
