//! The audio commands and `--snd0`, end to end through the binary.

mod common;

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use common::make_prx;
use predicates::str::contains;
use pspbuild::audio::inspect_at3;
use pspbuild::mg::{MgEbootRequest, build_mg_eboot};
use pspbuild::pbp::{Pbp, PbpSection};
use tempfile::TempDir;

fn cli() -> Command {
    Command::cargo_bin("pspbuild").expect("binary builds")
}

fn known_good() -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audio/ssb64_snd0.at3"))
        .unwrap()
}

/// The known-good file with frame 17 claiming four coded bands.
fn four_band_snd0() -> Vec<u8> {
    let mut file = known_good();
    file[60 + 17 * 192] = 0xA3;
    file
}

/// A stereo 16-bit WAV of a 440 Hz tone.
fn tone_wav(dir: &TempDir, name: &str, seconds: f64) -> PathBuf {
    let path = dir.path().join(name);
    let spec = hound::WavSpec {
        channels: 2,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(&path, spec).unwrap();
    for i in 0..(44_100.0 * seconds) as usize {
        let v = (6000.0 * (2.0 * std::f64::consts::PI * 440.0 * i as f64 / 44_100.0).sin()) as i16;
        writer.write_sample(v).unwrap();
        writer.write_sample(v).unwrap();
    }
    writer.finalize().unwrap();
    path
}

fn write(dir: &TempDir, name: &str, data: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn audio_snd0_converts_quietly() {
    let dir = TempDir::new().unwrap();
    let input = tone_wav(&dir, "theme.wav", 2.0);
    let output = dir.path().join("out.at3");
    cli()
        .args(["audio", "snd0", s(&input), "-o", s(&output)])
        .assert()
        .success()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::is_empty());
    assert!(inspect_at3(&std::fs::read(&output).unwrap()).is_strictly_valid());
    cli()
        .args(["audio", "inspect", s(&output)])
        .assert()
        .success()
        .stdout(contains(
            "Loop:                samples 1024 to 89223 (2.00 s), forever",
        ))
        .stdout(contains(
            "Verdict:             playable; matches the profile pspbuild writes",
        ));
}

#[test]
fn audio_snd0_defaults_to_snd0_at3_and_explains_when_verbose() {
    let dir = TempDir::new().unwrap();
    let input = tone_wav(&dir, "theme.wav", 1.0);
    cli()
        .args(["-v", "audio", "snd0", s(&input)])
        .assert()
        .success()
        .stdout(predicates::str::is_empty())
        .stderr(contains("SND0 source:      WAV, 44100 Hz, 2 channels"))
        .stderr(contains("ATRAC3 LP4"));
    assert!(dir.path().join("SND0.AT3").exists());
}

#[test]
fn audio_snd0_warns_when_it_cuts() {
    let dir = TempDir::new().unwrap();
    let input = tone_wav(&dir, "long.wav", 56.0);
    cli()
        .args(["audio", "snd0", s(&input)])
        .assert()
        .success()
        .stderr(contains("warning:"))
        .stderr(contains("cut to the first 54.94 s"));
}

#[test]
fn audio_snd0_refuses_what_it_cannot_read() {
    let dir = TempDir::new().unwrap();
    let input = write(&dir, "song.m4a", b"\0\0\0\x20ftypM4A \0\0\0\0\0\0\0\0");
    cli()
        .args(["audio", "snd0", s(&input)])
        .assert()
        .failure()
        .stderr(contains("AAC/M4A is not supported"));
    assert!(!dir.path().join("SND0.AT3").exists());
}

#[test]
fn audio_inspect_explains_a_good_file() {
    let dir = TempDir::new().unwrap();
    let input = write(&dir, "SND0.AT3", &known_good());
    cli()
        .args(["audio", "inspect", s(&input)])
        .assert()
        .success()
        .stdout(contains("fmt   offset 0x0000000C"))
        .stdout(contains("66144 bps (LP4), 192-byte frames"))
        .stdout(contains("Frames:              1103 (25.61 s)"))
        .stdout(contains("Coded QMF bands:     3 bands in 1103"))
        .stdout(contains("Loop:                none"))
        .stdout(contains("Verdict:             playable, with warnings"))
        .stdout(contains("WARNING: it has no loop point (smpl chunk)"));
}

#[test]
fn audio_inspect_fails_on_a_four_band_frame() {
    let dir = TempDir::new().unwrap();
    let input = write(&dir, "SND0.AT3", &four_band_snd0());
    cli()
        .args(["audio", "inspect", s(&input)])
        .assert()
        .failure()
        .stdout(contains("Verdict:             NOT PLAYABLE"))
        .stdout(contains(
            "ERROR: frame 17 codes four QMF bands; the XMB will not play this",
        ))
        .stderr(contains("frame 17 codes four QMF bands"));
}

#[test]
fn audio_inspect_strict_also_fails_on_warnings() {
    let dir = TempDir::new().unwrap();
    // A trailing LIST chunk: harmless as far as anyone knows, but not what
    // pspbuild writes.
    let mut file = known_good();
    file.extend_from_slice(b"LIST\x04\0\0\0INFO");
    let size = (file.len() - 8) as u32;
    file[4..8].copy_from_slice(&size.to_le_bytes());
    let input = write(&dir, "SND0.AT3", &file);
    cli()
        .args(["audio", "inspect", s(&input)])
        .assert()
        .success()
        .stdout(contains("WARNING: it has a 'LIST' chunk"));
    cli()
        .args(["audio", "inspect", "--strict", s(&input)])
        .assert()
        .failure();
}

#[test]
fn build_mg_converts_snd0_and_inspect_and_verify_check_it() {
    let dir = TempDir::new().unwrap();
    let module = write(&dir, "game.prx", &make_prx("cli_module", 4096));
    let music = tone_wav(&dir, "theme.wav", 3.0);
    let eboot = dir.path().join("EBOOT.PBP");
    cli()
        .args(["build-mg", s(&module), "-o", s(&eboot), "--snd0", s(&music)])
        .assert()
        .success()
        .stdout(predicates::str::is_empty());

    let data = std::fs::read(&eboot).unwrap();
    let pbp = Pbp::parse(&data).unwrap();
    assert!(inspect_at3(pbp.section(PbpSection::Snd0At3)).is_strictly_valid());

    cli()
        .args(["inspect", s(&eboot)])
        .assert()
        .success()
        .stdout(contains("SND0.AT3:"))
        .stdout(contains(
            "  Verdict:             playable; matches the profile pspbuild writes",
        ));
    cli()
        .args(["verify", s(&eboot)])
        .assert()
        .success()
        .stdout(contains(
            "VALID: SND0.AT3 is ATRAC3 the XMB can play (132 frames)",
        ));
}

#[test]
fn build_mg_passes_a_playable_snd0_through_byte_for_byte() {
    let dir = TempDir::new().unwrap();
    let module = write(&dir, "game.prx", &make_prx("cli_module", 4096));
    let music = write(&dir, "SND0.AT3", &known_good());
    let eboot = dir.path().join("EBOOT.PBP");
    cli()
        .args(["build-mg", s(&module), "-o", s(&eboot), "--snd0", s(&music)])
        .assert()
        .success();
    let data = std::fs::read(&eboot).unwrap();
    assert_eq!(
        Pbp::parse(&data).unwrap().section(PbpSection::Snd0At3),
        &known_good()[..]
    );
}

#[test]
fn build_mg_trims_snd0_on_request() {
    let dir = TempDir::new().unwrap();
    let module = write(&dir, "game.prx", &make_prx("cli_module", 4096));
    let music = tone_wav(&dir, "theme.wav", 5.0);
    let eboot = dir.path().join("EBOOT.PBP");
    cli()
        .args([
            "build-mg",
            s(&module),
            "-o",
            s(&eboot),
            "--snd0",
            s(&music),
            "--snd0-start",
            "1",
            "--snd0-duration",
            "2",
        ])
        .assert()
        .success();
    let data = std::fs::read(&eboot).unwrap();
    let report = inspect_at3(Pbp::parse(&data).unwrap().section(PbpSection::Snd0At3));
    assert_eq!(report.frames, pspbuild::audio::frames_for(88_200));
}

#[test]
fn verify_rejects_an_eboot_whose_snd0_the_xmb_will_not_play() {
    let dir = TempDir::new().unwrap();
    let module = make_prx("cli_module", 4096);
    // The library packages SND0 bytes as given, so this is how a bad one gets
    // into a container.
    let built = build_mg_eboot(&MgEbootRequest {
        module: &module,
        compress: true,
        snd0: Some(four_band_snd0()),
        ..Default::default()
    })
    .unwrap();
    let eboot = write(&dir, "EBOOT.PBP", &built.data);
    cli()
        .args(["verify", s(&eboot)])
        .assert()
        .failure()
        .stderr(contains("SND0.AT3: frame 17 codes four QMF bands"));
    cli()
        .args(["inspect", s(&eboot)])
        .assert()
        .success()
        .stdout(contains("  Verdict:             NOT PLAYABLE"));
}
