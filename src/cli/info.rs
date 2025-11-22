//! Info command - Display signing block information

use clap::Args;
use modsig::SigningBlock;
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::PathBuf;

/// 显示模块签名块信息的参数
#[derive(Args)]
pub struct InfoArgs {
    /// 模块文件路径
    #[arg(value_name = "MODULE")]
    pub module: PathBuf,
}

/// 执行 info 命令
pub fn execute(args: InfoArgs) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(&args.module)?;
    let mut reader = BufReader::new(file);

    let file_len = reader.seek(SeekFrom::End(0))? as usize;

    println!("文件: {}", args.module.display());
    println!("文件大小: {} 字节", file_len);
    println!();

    match SigningBlock::from_reader(reader, file_len, 0) {
        Ok(sig_block) => {
            println!("✓ 找到 KSU 签名块");
            println!(
                "  位置: {} - {}",
                sig_block.file_offset_start, sig_block.file_offset_end
            );
            println!("  大小: {} 字节", sig_block.size_of_block_start + 8);
            println!();

            // 显示包含的签名块类型
            if !sig_block.content.is_empty() {
                println!("签名块内容:");
                for value in &sig_block.content {
                    match value {
                        modsig::ValueSigningBlock::SignatureSchemeV2Block(_) => {
                            println!("  ✓ V2 Signature Scheme");
                        }
                        modsig::ValueSigningBlock::SourceStampBlock(_) => {
                            println!("  ✓ Source Stamp");
                        }
                        modsig::ValueSigningBlock::BaseSigningBlock(data) => {
                            println!("  • Unknown Block (ID: 0x{:x})", data.id);
                        }
                    }
                }
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("✗ 错误: 无法解析 KSU 签名块");
            eprintln!("  详情: {:?}", e);
            Err(e.into())
        }
    }
}
