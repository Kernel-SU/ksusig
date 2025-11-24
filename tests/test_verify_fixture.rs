use std::path::PathBuf;

use modsig::{CertChainVerifier, Module, SignatureVerifier, TrustedRoots, VerifyError};

fn load_signing_block(path: &str) -> Result<modsig::SigningBlock, String> {
    let module_path = PathBuf::from(path);
    let module = Module::new(module_path).map_err(|e| e.to_string())?;
    module.get_signing_block().map_err(|e| e.to_string())
}

/// 官方 KSU 签名：应被内置根信任。
#[test]
fn verify_fixture_signed_zip_has_trusted_chain() {
    let signing_block = load_signing_block("tests/fixtures/test_ksu_signed.zip")
        .expect("extract signing block from fixture");

    let verifier = SignatureVerifier::with_builtin_roots();
    let result = verifier.verify_v2(&signing_block).expect("verify v2");

    assert!(result.signature_valid, "signature should be valid");
    assert!(result.cert_chain_valid, "certificate chain should be structurally valid");
    assert!(result.is_trusted, "certificate chain should be trusted by built-in roots");
    assert!(
        result.certificate.as_ref().is_some_and(|c| !c.is_empty()),
        "leaf certificate should be present"
    );
    assert_eq!(
        result.cert_chain.len(),
        1,
        "fixture should carry one intermediate certificate"
    );
    assert!(
        result.warnings.is_empty(),
        "no warnings expected for the official fixture"
    );
}

/// 自签/测试根：默认不可信，但加载 tests/certificates/root_ca/root_ca_p256.crt 后应可信。
#[test]
fn verify_untrusted_fixture_can_be_trusted_with_custom_root() {
    let signing_block = load_signing_block("tests/fixtures/test_signed.zip")
        .expect("extract signing block from fixture");

    // 默认根：应验签成功，但不可信。
    let default_verifier = SignatureVerifier::with_builtin_roots();
    let default_result = default_verifier.verify_v2(&signing_block).expect("verify v2");
    assert!(default_result.signature_valid, "signature should be valid");
    assert!(!default_result.is_trusted, "should not be trusted without custom root");
    let leaf = default_result
        .certificate
        .clone()
        .expect("leaf certificate present");

    // 加载测试根 CA
    let root_pem = std::fs::read("tests/certificates/root_ca/root_ca_p256.crt")
        .expect("read test root pem");
    let mut roots = TrustedRoots::new();
    roots
        .add_root_pem(&root_pem)
        .expect("parse test root pem");
    let root_der = {
        let pem = pem::parse(root_pem).expect("parse pem");
        pem.contents().to_vec()
    };

    // 使用 CertChainVerifier 直接验证链 + 信任。
    let chain_verifier = CertChainVerifier::new(roots);
    let (chain_valid, trusted) = chain_verifier.verify_chain(&leaf, &[root_der]);
    assert!(chain_valid, "chain should be structurally valid with provided root");
    assert!(trusted, "should be trusted when root is supplied as intermediate");
}

/// 双签（V2 + Source Stamp）场景：均应验签通过但默认不被信任。
#[test]
fn verify_dual_signed_has_v2_and_stamp_results() {
    let signing_block = load_signing_block("tests/fixtures/test_dual_signed.zip")
        .expect("extract signing block from fixture");

    let verifier = SignatureVerifier::with_builtin_roots();
    let (v2_result, stamp_result) = verifier.verify_all(&signing_block);

    let v2 = v2_result.expect("v2 result");
    assert!(v2.signature_valid, "v2 signature should be valid");
    assert!(v2.cert_chain_valid, "v2 chain should be valid");
    assert!(!v2.is_trusted, "v2 should not be trusted without custom root");

    let stamp = stamp_result.expect("stamp result");
    assert!(stamp.signature_valid, "stamp signature should be valid");
    assert!(stamp.cert_chain_valid, "stamp chain should be valid");
    assert!(!stamp.is_trusted, "stamp should not be trusted without custom root");
}

/// 未签名模块：应返回 NoSignature。
#[test]
fn verify_unsigned_module_returns_no_signature() {
    let module_path = PathBuf::from("tests/fixtures/test_unsigned.zip");
    let module = Module::new(module_path).expect("load module");
    let signing_block = module.get_signing_block();
    assert!(
        signing_block.is_err(),
        "unsigned module should not have a signing block"
    );

    // 若未来返回签名块，也应在 verify_v2 里报 NoSignature。
    if let Ok(block) = signing_block {
        let verifier = SignatureVerifier::with_builtin_roots();
        let err = verifier.verify_v2(&block).unwrap_err();
        assert!(
            matches!(err, VerifyError::NoSignature),
            "should return NoSignature"
        );
    }
}
