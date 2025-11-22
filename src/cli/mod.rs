//! Command-line interface for modsig

use clap::{Parser, Subcommand};

pub mod info;
pub mod sign;
pub mod verify;

/// KSU Module签名工具
#[derive(Parser)]
#[command(name = "modsig")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// 子命令
    #[command(subcommand)]
    pub command: Commands,
}

/// 可用的命令
#[derive(Subcommand)]
pub enum Commands {
    /// 对模块进行签名
    Sign(sign::SignArgs),

    /// 验证模块签名
    Verify(verify::VerifyArgs),

    /// 显示签名块信息
    Info(info::InfoArgs),
}

impl Cli {
    /// 解析命令行参数
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// 执行命令
    pub fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            Commands::Sign(args) => sign::execute(args),
            Commands::Verify(args) => verify::execute(args),
            Commands::Info(args) => info::execute(args),
        }
    }
}
