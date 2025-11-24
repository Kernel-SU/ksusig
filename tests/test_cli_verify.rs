use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn cli_verify_trusted_fixture_passes() {
    Command::cargo_bin("modsig")
        .expect("binary exists")
        .args(["verify", "tests/fixtures/test_ksu_signed.zip"])
        .assert()
        .success();
}

#[test]
fn cli_verify_untrusted_fixture_fails() {
    Command::cargo_bin("modsig")
        .expect("binary exists")
        .args(["verify", "tests/fixtures/test_signed.zip"])
        .assert()
        .failure()
        .stderr(contains("Untrusted certificate"));
}
