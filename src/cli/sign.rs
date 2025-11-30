//! Sign command - Sign module files

use clap::Args;
use ksusig::{
    common::{Digest, Digests},
    load_p12, load_pem, FileFormat, ModuleSigner, ModuleSignerConfig, SignableFile,
};
#[cfg(feature = "elf")]
use ksusig::{signing_block::elf_section_info::ElfSectionInfo, ValueSigningBlock};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Arguments for the sign command
#[derive(Args)]
pub struct SignArgs {
    /// Input module file
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output module file
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// V2 signature private key file (PEM or P12 format)
    #[arg(long = "key")]
    pub key: Option<PathBuf>,

    /// V2 signature certificate file (PEM format)
    #[arg(long = "cert")]
    pub cert: Option<PathBuf>,

    /// V2 signature P12 keystore file
    #[arg(long = "p12")]
    pub p12: Option<PathBuf>,

    /// P12 keystore password
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Source Stamp private key file
    #[arg(long = "stamp-key")]
    pub stamp_key: Option<PathBuf>,

    /// Source Stamp certificate file
    #[arg(long = "stamp-cert")]
    pub stamp_cert: Option<PathBuf>,

    /// Source Stamp P12 keystore
    #[arg(long = "stamp-p12")]
    pub stamp_p12: Option<PathBuf>,

    /// Source Stamp P12 password
    #[arg(long = "stamp-password")]
    pub stamp_password: Option<String>,

    /// ELF sections to sign (comma separated or repeated)
    #[arg(
        long = "elf-section",
        value_name = "SECTION",
        value_delimiter = ',',
        num_args = 0..
    )]
    pub elf_sections: Vec<String>,
}

/// Execute the sign command
pub fn execute(args: SignArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("Signing module file...");
    println!("Input: {}", args.input.display());
    println!("Output: {}", args.output.display());
    println!();

    // Load V2 signature credentials
    let v2_creds = if let Some(p12_path) = args.p12 {
        // Load from P12
        let password = args
            .password
            .ok_or("P12 format requires password (--password)")?;
        let p12_str = p12_path.to_str().ok_or("Invalid P12 file path")?;
        load_p12(p12_str, &password)?
    } else if let Some(key_path) = args.key {
        // Load from PEM
        let cert_path = args.cert.ok_or("--cert required when using --key")?;
        let key_str = key_path.to_str().ok_or("Invalid key file path")?;
        let cert_str = cert_path.to_str().ok_or("Invalid certificate file path")?;
        load_pem(key_str, cert_str, args.password.as_deref())?
    } else {
        return Err("Must specify --key/--cert or --p12".into());
    };

    println!("✓ V2 signing key loaded");

    // Load Source Stamp credentials (if provided)
    let stamp_creds = if let Some(stamp_p12) = args.stamp_p12 {
        let password = args
            .stamp_password
            .ok_or("Source Stamp P12 requires password (--stamp-password)")?;
        let p12_str = stamp_p12
            .to_str()
            .ok_or("Invalid Source Stamp P12 file path")?;
        Some(load_p12(p12_str, &password)?)
    } else if let Some(stamp_key) = args.stamp_key {
        let stamp_cert = args
            .stamp_cert
            .ok_or("--stamp-cert required when using --stamp-key")?;
        let key_str = stamp_key
            .to_str()
            .ok_or("Invalid Source Stamp key file path")?;
        let cert_str = stamp_cert
            .to_str()
            .ok_or("Invalid Source Stamp certificate file path")?;
        Some(load_pem(key_str, cert_str, args.stamp_password.as_deref())?)
    } else {
        None
    };

    if stamp_creds.is_some() {
        println!("✓ Source Stamp key loaded");
    }

    // Select algorithm based on V2 private key curve (before moving v2_creds)
    let algorithm = v2_creds.algorithm.clone();

    // Create signer
    let signer = if let Some(stamp) = stamp_creds {
        ModuleSigner::with_source_stamp(
            ModuleSignerConfig::from_credentials(v2_creds),
            ModuleSignerConfig::from_credentials(stamp),
        )
    } else {
        ModuleSigner::v2_only(ModuleSignerConfig::from_credentials(v2_creds))
    };

    // Prepare signable target
    let mut signable = SignableFile::open(&args.input)?;

    #[cfg(feature = "elf")]
    if !args.elf_sections.is_empty() {
        signable.set_elf_sections(args.elf_sections.clone())?;
    }

    #[cfg(not(feature = "elf"))]
    if !args.elf_sections.is_empty() {
        return Err("ELF 支持未开启，无法使用 --elf-section".into());
    }

    match signable.format() {
        FileFormat::Module => println!("✓ 检测到模块（ZIP）文件"),
        #[cfg(feature = "elf")]
        FileFormat::Elf => println!("✓ 检测到 ELF 文件"),
    }

    let regions = signable.digest_regions()?;
    println!("待签名区域:");
    for region in &regions {
        println!(
            "  - {} @ {} ({} bytes)",
            region.name, region.offset, region.size
        );
    }
    println!("ℹ 自动使用密钥曲线对应算法: {}", algorithm);

    // Calculate digests
    println!("Calculating digests...");
    let digest = signable.digest(&algorithm)?;
    println!("✓ Digest calculation complete");

    // Create Digests
    let digests = Digests::new(vec![Digest::new(algorithm, digest)]);

    // Sign
    println!("Signing...");
    let mut signing_block = signer.sign(digests)?;

    #[cfg(feature = "elf")]
    if let SignableFile::Elf(ref elf) = signable {
        let sections = elf.resolved_sections()?;
        let section_info = ElfSectionInfo::from_tuples(
            sections
                .iter()
                .map(|(name, offset, size)| (name.as_str(), *offset, *size))
                .collect(),
        );
        signing_block
            .content
            .push(ValueSigningBlock::ElfSectionInfoBlock(section_info));
        signing_block.recalculate_size();
    }

    let signing_block_size = signing_block.to_u8().len();
    println!(
        "✓ Signing complete (signing block size: {} bytes)",
        signing_block_size
    );

    // Write output file
    println!("Writing signed module...");
    let mut writer = BufWriter::new(File::create(&args.output)?);
    signable.write_with_signature(&mut writer, &signing_block)?;
    writer.flush()?;

    println!("✓ Signing successful!");
    println!("Output file: {}", args.output.display());

    Ok(())
}
