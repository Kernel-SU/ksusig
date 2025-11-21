//! Sign command - Sign module files

use apksig::{
    common::{Digest, Digests},
    digest_module, load_p12, load_pem, zip::find_eocd, Algorithms, ModuleSigner,
    ModuleSignerConfig,
};
use clap::Args;
use std::fs::{File, OpenOptions};
use std::io::{copy, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// 签名命令的参数
#[derive(Args)]
pub struct SignArgs {
    /// 输入模块文件
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// 输出模块文件
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// V2 签名私钥文件 (PEM 或 P12 格式)
    #[arg(long = "key")]
    pub key: Option<PathBuf>,

    /// V2 签名证书文件 (PEM 格式)
    #[arg(long = "cert")]
    pub cert: Option<PathBuf>,

    /// V2 签名 P12 密钥库文件
    #[arg(long = "p12")]
    pub p12: Option<PathBuf>,

    /// P12 密钥库密码
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Source Stamp 私钥文件
    #[arg(long = "stamp-key")]
    pub stamp_key: Option<PathBuf>,

    /// Source Stamp 证书文件
    #[arg(long = "stamp-cert")]
    pub stamp_cert: Option<PathBuf>,

    /// Source Stamp P12 密钥库
    #[arg(long = "stamp-p12")]
    pub stamp_p12: Option<PathBuf>,

    /// Source Stamp P12 密码
    #[arg(long = "stamp-password")]
    pub stamp_password: Option<String>,

    /// 签名算法 (ecdsa256 或 ecdsa384)
    #[arg(long, default_value = "ecdsa256")]
    pub algorithm: String,
}

/// 执行签名命令
pub fn execute(args: SignArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("正在签名模块文件...");
    println!("输入: {}", args.input.display());
    println!("输出: {}", args.output.display());
    println!();

    // 加载 V2 签名凭据
    let v2_creds = if let Some(p12_path) = args.p12 {
        // 从 P12 加载
        let password = args.password.ok_or("P12 格式需要密码 (--password)")?;
        let p12_str = p12_path
            .to_str()
            .ok_or("无效的 P12 文件路径")?;
        load_p12(p12_str, &password)?
    } else if let Some(key_path) = args.key {
        // 从 PEM 加载
        let cert_path = args.cert.ok_or("使用 --key 时需要 --cert")?;
        let key_str = key_path
            .to_str()
            .ok_or("无效的密钥文件路径")?;
        let cert_str = cert_path
            .to_str()
            .ok_or("无效的证书文件路径")?;
        load_pem(key_str, cert_str, args.password.as_deref())?
    } else {
        return Err("必须指定 --key/--cert 或 --p12".into());
    };

    println!("✓ V2 签名密钥已加载");

    // 加载 Source Stamp 凭据（如果提供）
    let stamp_creds = if let Some(stamp_p12) = args.stamp_p12 {
        let password = args
            .stamp_password
            .ok_or("Source Stamp P12 需要密码 (--stamp-password)")?;
        let p12_str = stamp_p12
            .to_str()
            .ok_or("无效的 Source Stamp P12 文件路径")?;
        Some(load_p12(p12_str, &password)?)
    } else if let Some(stamp_key) = args.stamp_key {
        let stamp_cert = args
            .stamp_cert
            .ok_or("使用 --stamp-key 时需要 --stamp-cert")?;
        let key_str = stamp_key
            .to_str()
            .ok_or("无效的 Source Stamp 密钥文件路径")?;
        let cert_str = stamp_cert
            .to_str()
            .ok_or("无效的 Source Stamp 证书文件路径")?;
        Some(load_pem(
            key_str,
            cert_str,
            args.stamp_password.as_deref(),
        )?)
    } else {
        None
    };

    if stamp_creds.is_some() {
        println!("✓ Source Stamp 密钥已加载");
    }

    // 创建签名器
    let signer = if let Some(stamp) = stamp_creds {
        ModuleSigner::with_source_stamp(
            ModuleSignerConfig::from_credentials(v2_creds),
            ModuleSignerConfig::from_credentials(stamp),
        )
    } else {
        ModuleSigner::v2_only(ModuleSignerConfig::from_credentials(v2_creds))
    };

    // 读取输入文件
    let mut input_file = File::open(&args.input)?;
    let input_len = input_file.metadata()?.len() as usize;

    // 找到 EOCD
    let eocd = find_eocd(&mut input_file, input_len)?;
    let cd_offset = eocd.cd_offset as usize;
    let cd_size = eocd.cd_size as usize;
    let eocd_offset = eocd.file_offset;
    let eocd_size = input_len - eocd_offset;

    println!("✓ ZIP 结构解析完成");
    println!("  Central Directory: {} 字节 @ {}", cd_size, cd_offset);
    println!("  EOCD: {} 字节 @ {}", eocd_size, eocd_offset);

    // 构建文件偏移量
    let offsets = apksig::zip::FileOffsets {
        start_content: 0,
        stop_content: cd_offset,
        start_cd: cd_offset,
        stop_cd: eocd_offset,
        start_eocd: eocd_offset,
        stop_eocd: input_len,
    };

    // 选择算法
    let algorithm = match args.algorithm.as_str() {
        "ecdsa256" => Algorithms::ECDSA_SHA2_256,
        "ecdsa384" => Algorithms::ECDSA_SHA2_512,
        _ => return Err(format!("不支持的算法: {}", args.algorithm).into()),
    };

    // 计算摘要
    println!("正在计算摘要...");
    input_file.seek(SeekFrom::Start(0))?;
    let digest = digest_module(&mut input_file, &offsets, &algorithm)?;
    println!("✓ 摘要计算完成");

    // 创建 Digests
    let digests = Digests::new(vec![Digest::new(algorithm, digest)]);

    // 签名
    println!("正在签名...");
    let signing_block = signer.sign(digests)?;
    let signing_block_bytes = signing_block.to_u8();
    let signing_block_size = signing_block_bytes.len();
    println!("✓ 签名完成 (签名块大小: {} 字节)", signing_block_size);

    // 写入输出文件
    println!("正在写入签名后的模块...");
    write_signed_module(
        &args.input,
        &args.output,
        &signing_block_bytes,
        cd_offset,
        &eocd,
    )?;

    println!("✓ 签名成功!");
    println!("输出文件: {}", args.output.display());

    Ok(())
}

/// 写入签名后的模块文件
fn write_signed_module(
    input_path: &PathBuf,
    output_path: &PathBuf,
    signing_block: &[u8],
    cd_offset: usize,
    eocd: &apksig::zip::EndOfCentralDirectoryRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::new(input_file);

    let output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    let mut writer = BufWriter::new(output_file);

    // 1. 写入 ZIP 内容 (从开始到 Central Directory 之前)
    reader.seek(SeekFrom::Start(0))?;
    let mut content_reader = reader.by_ref().take(cd_offset as u64);
    copy(&mut content_reader, &mut writer)?;

    // 2. 写入签名块
    writer.write_all(signing_block)?;

    let new_cd_offset = cd_offset + signing_block.len();

    // 3. 写入 Central Directory
    reader.seek(SeekFrom::Start(cd_offset as u64))?;
    let cd_size = (eocd.file_offset - cd_offset) as u64;
    let mut cd_reader = reader.by_ref().take(cd_size);
    copy(&mut cd_reader, &mut writer)?;

    // 4. 写入更新后的 EOCD (更新 CD offset)
    let new_eocd = apksig::zip::EndOfCentralDirectoryRecord {
        file_offset: eocd.file_offset + signing_block.len(),
        signature: eocd.signature,
        disk_number: eocd.disk_number,
        disk_with_cd: eocd.disk_with_cd,
        num_entries: eocd.num_entries,
        total_entries: eocd.total_entries,
        cd_size: eocd.cd_size,
        cd_offset: new_cd_offset as u32,
        comment_len: eocd.comment_len,
        comment: eocd.comment.clone(),
    };

    writer.write_all(&new_eocd.to_u8())?;
    writer.flush()?;

    Ok(())
}
