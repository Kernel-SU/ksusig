//! Verify command - Verify module signatures

use clap::Args;
use modsig::{Module, SignatureVerifier, TrustedRoots};
use std::fs;
use std::path::PathBuf;

/// 验证命令的参数
#[derive(Args)]
pub struct VerifyArgs {
    /// 要验证的模块文件
    #[arg(value_name = "MODULE")]
    pub module: PathBuf,

    /// 可信根证书文件 (可选, PEM 格式)
    #[arg(long = "root")]
    pub root_cert: Option<PathBuf>,

    /// 详细输出
    #[arg(long, short)]
    pub verbose: bool,
}

/// 执行验证命令
pub fn execute(args: VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("正在验证模块签名...");
    println!("文件: {}", args.module.display());
    println!();

    // 读取模块文件
    let module = Module::new(args.module.clone())?;

    // 获取签名块
    let signing_block = module
        .get_signing_block()
        .map_err(|e| format!("无法读取签名块: {}", e))?;

    println!("✓ 找到签名块");

    // 创建验证器
    let verifier = if let Some(root_path) = args.root_cert {
        // 使用自定义根证书
        let root_pem = fs::read(&root_path)?;

        let mut roots = TrustedRoots::new();
        roots
            .add_root_pem(&root_pem)
            .map_err(|e| format!("无法加载根证书: {}", e))?;

        println!("✓ 使用自定义根证书: {}", root_path.display());

        SignatureVerifier::with_trusted_roots(roots)
    } else {
        // 使用内置根证书
        SignatureVerifier::with_builtin_roots()
    };

    // 验证所有签名
    let (v2_result, stamp_result) = verifier.verify_all(&signing_block);

    // 显示 V2 签名验证结果
    match &v2_result {
        Some(result) => {
            if result.signature_valid {
                println!("✓ V2 签名验证通过");
                if args.verbose {
                    println!("  签名有效: {}", result.signature_valid);
                    println!("  证书链有效: {}", result.cert_chain_valid);
                    println!("  可信: {}", result.is_trusted);
                    if let Some(ref cert) = result.certificate {
                        println!("  证书大小: {} 字节", cert.len());
                    }
                }
            } else {
                eprintln!("✗ V2 签名无效");
                return Err("V2 签名验证失败".into());
            }
        }
        None => {
            println!("ℹ 未找到 V2 签名");
        }
    }

    // 显示 Source Stamp 验证结果
    match &stamp_result {
        Some(result) => {
            if result.signature_valid {
                println!("✓ Source Stamp 验证通过");
                if args.verbose {
                    println!("  签名有效: {}", result.signature_valid);
                    println!("  证书链有效: {}", result.cert_chain_valid);
                    println!("  可信: {}", result.is_trusted);
                }
            } else {
                eprintln!("⚠ Source Stamp 验证失败");
                // Source Stamp 失败不算严重错误
            }
        }
        None => {
            if args.verbose {
                println!("ℹ 未找到 Source Stamp");
            }
        }
    }

    // 总体结果
    if v2_result.is_some() && v2_result.as_ref().is_some_and(|r| r.signature_valid) {
        println!();
        println!("✓ 模块签名验证成功!");
        Ok(())
    } else {
        Err("模块签名验证失败".into())
    }
}
