//! End-to-end tests of the command-line interface.

mod common;

use std::path::Path;

use assert_cmd::Command;
use common::make_prx;
use predicates::str::contains;
use tempfile::TempDir;

fn cli() -> Command {
    Command::cargo_bin("pspbuild").expect("binary builds")
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
        .stdout(contains("Format:              PSP PRX (encrypted)"))
        .stdout(contains("Total size:"))
        .stdout(contains("Encrypted:         yes"))
        .stdout(contains("Payload size:"))
        .stdout(contains("KIRK payload:"))
        .stdout(contains("Module name:       cli_module"))
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
        .stdout(contains("Format:              ELF/PRX (plain)"))
        .stdout(contains("Encrypted:         no"));
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

/// A flag that no longer exists must be rejected rather than ignored, so a
/// script still passing it fails loudly instead of silently building something
/// other than what it asked for.
#[test]
fn the_removed_format_flag_is_refused() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 1024);

    cli()
        .args(["encrypt", input.to_str().unwrap(), "--format", "pspemu"])
        .assert()
        .failure()
        .stderr(contains("--format"));
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

#[test]
fn build_mg_produces_an_inspectable_eboot() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 30_000);
    let output = dir.path().join("EBOOT.PBP");

    cli()
        .args([
            "build-mg",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--title",
            "Test Title",
        ])
        .assert()
        .success()
        .stdout(predicates::str::is_empty());

    cli()
        .args(["inspect", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("Format:              PBP container"))
        .stdout(contains("Category:            MG"))
        .stdout(contains("Title:               Test Title"))
        .stdout(contains("DATA.PSP"))
        .stdout(contains("PSP PRX (encrypted)"));

    // The whole container verifies, and the module comes back out intact.
    cli()
        .args(["verify", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("VALID: PBP container structure"))
        .stdout(contains("VERIFIED"));

    let recovered = dir.path().join("back.prx");
    cli()
        .args([
            "decrypt",
            output.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&input).unwrap()
    );
}

#[test]
fn build_mg_defaults_its_output_to_eboot_pbp() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 2048);

    cli()
        .args(["build-mg", input.to_str().unwrap()])
        .assert()
        .success();

    assert!(dir.path().join("EBOOT.PBP").exists());
}

#[test]
fn extract_writes_every_populated_section() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 4096);
    let eboot = dir.path().join("EBOOT.PBP");
    let icon = dir.path().join("ICON0.PNG");
    std::fs::write(&icon, b"\x89PNG\r\n\x1a\npretend pixels").unwrap();

    cli()
        .args([
            "build-mg",
            input.to_str().unwrap(),
            "-o",
            eboot.to_str().unwrap(),
            "--icon0",
            icon.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = dir.path().join("extracted");
    cli()
        .args([
            "extract",
            eboot.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--decrypt",
        ])
        .assert()
        .success();

    assert!(out.join("PARAM.SFO").exists());
    assert!(out.join("DATA.PSP").exists());
    assert_eq!(
        std::fs::read(out.join("ICON0.PNG")).unwrap(),
        std::fs::read(&icon).unwrap()
    );
    // Empty sections are skipped rather than written as zero-byte files.
    assert!(!out.join("DATA.PSAR").exists());
    assert!(!out.join("SND0.AT3").exists());
    // The decrypted executable is the module we started from.
    assert_eq!(
        std::fs::read(out.join("DATA.PSP.dec")).unwrap(),
        std::fs::read(&input).unwrap()
    );
}

/// A content ID is not optional. For a fixed-key title it derives the
/// encryption key, so guessing one would silently produce an archive nothing
/// could decrypt.
#[test]
fn build_eg_requires_a_content_id() {
    let dir = TempDir::new().unwrap();
    let iso = dir.path().join("game.iso");
    std::fs::write(&iso, vec![0u8; 4096]).unwrap();

    cli()
        .args(["build-eg", iso.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("--content-id"));
}

/// Something that is not a UMD must be refused with a reason, not turned into
/// an archive of nothing.
#[test]
fn build_eg_refuses_an_image_that_is_not_a_psp_disc() {
    let dir = TempDir::new().unwrap();
    let iso = dir.path().join("game.iso");
    std::fs::write(&iso, vec![0u8; 64 * 2048]).unwrap();

    cli()
        .args([
            "build-eg",
            iso.to_str().unwrap(),
            "--content-id",
            "UL0000-ABCD12345_00-0000000000000000",
        ])
        .assert()
        .failure();
}

#[test]
fn build_mg_refuses_an_eboot_where_a_module_belongs() {
    let dir = TempDir::new().unwrap();
    let input = fixture(&dir, "game.prx", 2048);
    let eboot = dir.path().join("EBOOT.PBP");

    cli()
        .args([
            "build-mg",
            input.to_str().unwrap(),
            "-o",
            eboot.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Feeding the EBOOT back in must name the command that does handle it.
    cli()
        .args(["build-mg", eboot.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("encrypt"));
}
