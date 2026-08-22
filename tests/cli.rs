//! End-to-end tests of the command-line interface.

mod common;

use std::path::Path;

use assert_cmd::Command;
use common::make_prx;
use predicates::str::contains;
use tempfile::TempDir;

fn cli() -> Command {
    Command::cargo_bin("prx-encrypter").expect("binary builds")
}

/// Write a test module into a temporary directory.
fn fixture(dir: &TempDir, name: &str, size: usize) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, make_prx("cli_module", size)).unwrap();
    path
}

#[test]
fn encrypt_writes_the_requested_output() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 4096);
    let output = dir.path().join("game.enc.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::is_empty()); // quiet by default

    assert!(output.exists());
    assert!(std::fs::read(&output).unwrap().starts_with(b"~PSP"));
}

#[test]
fn encrypt_derives_an_output_name_when_none_is_given() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 1024);

    cli()
        .args(["encrypt", input.to_str().unwrap()])
        .assert()
        .success();
    assert!(dir.path().join("game.enc.prx").exists());
}

#[test]
fn verbose_output_goes_to_stderr_and_never_leaks_keys() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 4096);

    let output = cli()
        .args(["-v", "encrypt", input.to_str().unwrap()])
        .assert()
        .success()
        .stderr(contains("Input size:"))
        .stderr(contains("Output size:"))
        .get_output()
        .clone();

    // Nothing key-shaped should ever appear in diagnostics.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    for forbidden in ["aes key", "cmac key", "key:", "kirk1"] {
        assert!(!stderr.contains(forbidden), "stderr leaked {forbidden}");
    }
    assert!(output.stdout.is_empty(), "stdout must stay quiet");
}

#[test]
fn inspect_reports_the_documented_fields() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 4096);
    let output = dir.path().join("out.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    cli()
        .args(["inspect", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Format:"))
        .stdout(contains("Encrypted:           yes"))
        .stdout(contains("Payload size:"))
        .stdout(contains("KIRK payload size:"))
        .stdout(contains("Total file size:"))
        .stdout(contains("Module name:         cli_module"))
        .stdout(contains("Segments:"))
        .stdout(contains("Entry point:"));
}

#[test]
fn inspect_also_handles_a_plain_module() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "plain.prx", 2048);

    cli()
        .args(["inspect", input.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Encrypted:           no"));
}

#[test]
fn verify_succeeds_on_our_own_output() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 8192);
    let output = dir.path().join("out.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    cli()
        .args(["verify", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("VERIFIED"))
        .stdout(contains("CMAC"));
}

#[test]
fn verify_fails_on_a_corrupted_file() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 4096);
    let output = dir.path().join("out.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut data = std::fs::read(&output).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    std::fs::write(&output, &data).unwrap();

    cli()
        .args(["verify", output.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("error:"));
}

#[test]
fn encrypt_decrypt_round_trips_through_the_cli() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 20_000);
    let encrypted = dir.path().join("out.prx");
    let decrypted = dir.path().join("back.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    cli()
        .args([
            "decrypt",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&input).unwrap(),
        std::fs::read(&decrypted).unwrap()
    );
}

#[test]
fn output_size_tracks_the_input() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "big.prx", 700 * 1024);
    let output = dir.path().join("big.enc.prx");

    cli()
        .args([
            "encrypt",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--no-compress",
        ])
        .assert()
        .success();

    let in_size = std::fs::metadata(&input).unwrap().len();
    let out_size = std::fs::metadata(&output).unwrap().len();
    assert!(
        out_size < in_size + 512,
        "input {in_size}, output {out_size}"
    );
}

#[test]
fn missing_files_fail_cleanly() {
    cli()
        .args(["encrypt", "/nonexistent/nope.prx"])
        .assert()
        .failure()
        .stderr(contains("error:"));

    cli()
        .args(["inspect", "/nonexistent/nope.prx"])
        .assert()
        .failure();
}

#[test]
fn garbage_input_fails_without_panicking() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("garbage.prx");
    std::fs::write(&path, vec![0xAAu8; 5000]).unwrap();

    let assert = cli()
        .args(["encrypt", path.to_str().unwrap()])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(stderr.contains("error:"));
    assert!(!stderr.contains("panicked"), "tool panicked: {stderr}");
}

#[test]
fn pspemu_format_reports_that_it_is_unimplemented() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 1024);

    cli()
        .args(["encrypt", input.to_str().unwrap(), "--format", "pspemu"])
        .assert()
        .failure()
        .stderr(contains("PSPemu"));
}

#[test]
fn help_and_version_work() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("encrypt"));
    cli().arg("--version").assert().success();
    cli()
        .args(["encrypt", "--help"])
        .assert()
        .success()
        .stdout(contains("--no-compress"));
}

#[test]
fn the_reference_fixture_verifies_through_the_cli() {
    // A file produced by the PSPSDK reference tool, not by us.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ref_tiny.prx");
    cli()
        .args(["verify", fixture.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("VERIFIED"));
}
