//! SND0 audio: the ATRAC3 encoder, decoder and validator.
//!
//! Three kinds of evidence, strongest first:
//!
//! - **Sony's own files.** Retail SND0s are extracted from whatever PBPs sit in
//!   `plans/` (gitignored; the tests skip when there are none). A known-good
//!   LP4 SND0 that plays on hardware is committed as a fixture.
//! - **ffmpeg as a black box.** When it is installed, it decodes the files
//!   pspbuild writes and the files Sony wrote, and must agree with pspbuild's
//!   own decoder. It is never required.
//! - **Measured quality.** Test signals are encoded, decoded again and
//!   compared with what went in, against floors set below what was measured.

use std::path::{Path, PathBuf};

use pspbuild::audio::atrac3::bits::BitWriter;
use pspbuild::audio::atrac3::decoder::{Decoder, Layout, decode_all};
use pspbuild::audio::atrac3::dsp::qmf_analysis_periodic;
use pspbuild::audio::atrac3::encoder::{self, FRAME_BYTES};
use pspbuild::audio::atrac3::tables::FRAME_SAMPLES;
use pspbuild::audio::pcm::{self, Pcm};
use pspbuild::audio::riff::{self, LP4_FMT, write_lp4};
use pspbuild::audio::{Snd0Options, Snd0Source, encode_snd0, inspect_at3, make_snd0};
use pspbuild::pbp::{Pbp, PbpSection};

const LP4: Layout = Layout {
    block_align: 192,
    joint_stereo: true,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/audio")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The known-good LP4 SND0: 25.6 s, 1103 frames, plays in the XMB.
fn known_good() -> Vec<u8> {
    fixture("ssb64_snd0.at3")
}

/// Every distinct SND0 in the retail PBPs under `plans/`.
fn retail_snd0s() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("plans");
    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return found;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.extension().and_then(|e| e.to_str()) != Some("PBP") {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(pbp) = Pbp::parse(&data) else { continue };
        let snd0 = pbp.section(PbpSection::Snd0At3);
        if !snd0.is_empty() && !found.iter().any(|(_, s)| s == snd0) {
            found.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                snd0.to_vec(),
            ));
        }
    }
    if found.is_empty() {
        eprintln!("no retail SND0 in plans/; skipping");
    }
    found
}

fn data_chunk(file: &[u8]) -> &[u8] {
    riff::parse(file).unwrap().data.unwrap()
}

fn layout_of(file: &[u8]) -> Layout {
    let fmt = riff::parse(file).unwrap().fmt.unwrap();
    Layout {
        block_align: usize::from(fmt.block_align),
        joint_stereo: fmt.joint_stereo().unwrap(),
    }
}

/// Decode an AT3 with ffmpeg, if it is installed.
fn ffmpeg_decode(file: &[u8]) -> Option<[Vec<f32>; 2]> {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.at3");
    std::fs::write(&input, file).unwrap();
    let output = std::process::Command::new("ffmpeg")
        .args(["-v", "error", "-i"])
        .arg(&input)
        .args(["-f", "f32le", "-acodec", "pcm_f32le", "-"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let samples: Vec<f32> = output
        .stdout
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes(b.try_into().unwrap()) * 32768.0)
        .collect();
    let left = samples.iter().step_by(2).copied().collect();
    let right = samples.iter().skip(1).step_by(2).copied().collect();
    Some([left, right])
}

fn snr_db(reference: &[f32], test: &[f32]) -> f64 {
    let (mut signal, mut noise) = (0f64, 0f64);
    for (&r, &t) in reference.iter().zip(test) {
        signal += f64::from(r).powi(2);
        noise += f64::from(r - t).powi(2);
    }
    10.0 * (signal / noise.max(1e-30)).log10()
}

/// SNR in each of the three coded QMF bands, measured by splitting reference
/// and error with the codec's own filter bank.
fn band_snr_db(reference: &[f32], test: &[f32]) -> [f64; 3] {
    let error: Vec<f32> = reference.iter().zip(test).map(|(r, t)| r - t).collect();
    let bands = |x: &[f32]| {
        let (low, high) = qmf_analysis_periodic(x);
        let (b0, b1) = qmf_analysis_periodic(&low);
        let (_, b2) = qmf_analysis_periodic(&high);
        [b0, b1, b2]
    };
    let (r, e) = (bands(reference), bands(&error));
    let energy = |x: &[f32]| x.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>();
    [0, 1, 2].map(|b| 10.0 * (energy(&r[b]) / energy(&e[b]).max(1e-30)).log10())
}

/// Decode frames the way a looping player does: the second pass is steady
/// state, with the end of the track as the history of its start.
fn decode_looped(frames: &[u8]) -> [Vec<f32>; 2] {
    let mut decoder = Decoder::new(LP4);
    let mut out = [[0f32; FRAME_SAMPLES]; 2];
    let mut pcm = [Vec::new(), Vec::new()];
    for pass in 0..2 {
        for frame in frames.chunks_exact(FRAME_BYTES) {
            decoder.decode(frame, &mut out).unwrap();
            if pass == 1 {
                pcm[0].extend_from_slice(&out[0]);
                pcm[1].extend_from_slice(&out[1]);
            }
        }
    }
    pcm
}

// --- test signals ------------------------------------------------------------

const RATE: f64 = 44_100.0;

/// A deterministic generator, so every run measures the same thing.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> f32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 40) as f32 / (1u64 << 23) as f32) - 1.0
    }
}

fn samples(seconds: f64) -> usize {
    (seconds * RATE) as usize
}

/// A logarithmic sweep from 50 Hz to 15 kHz.
fn sweep(seconds: f64) -> Pcm {
    let n = samples(seconds);
    let (f0, f1) = (50f64, 15_000f64);
    let k = (f1 / f0).ln() / seconds;
    let left: Vec<f32> = (0..n)
        .map(|i| {
            let t = i as f64 / RATE;
            (12_000.0 * (2.0 * std::f64::consts::PI * f0 * ((k * t).exp() - 1.0) / k).sin()) as f32
        })
        .collect();
    Pcm {
        sample_rate: 44_100,
        channels: vec![left.clone(), left],
    }
}

/// Pink noise from the Voss-McCartney algorithm, different in each channel.
fn pink_noise(seconds: f64) -> Pcm {
    let n = samples(seconds);
    let channel = |seed| {
        let mut rng = Lcg(seed);
        let mut rows = [0f32; 16];
        let mut sum = 0f32;
        (0..n)
            .map(|i: usize| {
                let row = (i.trailing_zeros() as usize).min(15);
                sum -= rows[row];
                rows[row] = rng.next();
                sum += rows[row];
                (sum + rng.next()) * 1500.0
            })
            .collect()
    };
    Pcm {
        sample_rate: 44_100,
        channels: vec![channel(1), channel(2)],
    }
}

/// Kick, snare and hi-hat at 120 bpm: sharp attacks with silence between.
fn drum_loop(seconds: f64) -> Pcm {
    let n = samples(seconds);
    let mut rng = Lcg(3);
    let mut left = vec![0f32; n];
    let beat = samples(0.25);
    for (b, start) in (0..n).step_by(beat).enumerate() {
        for i in 0..samples(0.2).min(n - start) {
            let t = i as f64 / RATE;
            let v = match b % 4 {
                0 => {
                    20_000.0
                        * (-t * 25.0).exp()
                        * (2.0 * std::f64::consts::PI * (60.0 + 90.0 * (-t * 40.0).exp()) * t).sin()
                }
                2 => 9_000.0 * (-t * 30.0).exp() * f64::from(rng.next()),
                _ => 3_000.0 * (-t * 120.0).exp() * f64::from(rng.next()),
            };
            left[start + i] += v as f32;
        }
    }
    let right = left.iter().map(|v| v * 0.8).collect();
    Pcm {
        sample_rate: 44_100,
        channels: vec![left, right],
    }
}

/// A sustained A-major chord with a little stereo spread.
fn chord(seconds: f64) -> Pcm {
    let n = samples(seconds);
    let tone = |freqs: &[(f64, f64)]| -> Vec<f32> {
        (0..n)
            .map(|i| {
                let t = i as f64 / RATE;
                freqs
                    .iter()
                    .map(|&(f, a)| a * (2.0 * std::f64::consts::PI * f * t).sin())
                    .sum::<f64>() as f32
            })
            .collect()
    };
    let notes = [
        (220.0, 6000.0),
        (277.18, 4500.0),
        (329.63, 4000.0),
        (440.0, 2500.0),
        (1320.0, 800.0),
    ];
    let mut right_notes = notes;
    right_notes[4].1 = 400.0;
    Pcm {
        sample_rate: 44_100,
        channels: vec![tone(&notes), tone(&right_notes)],
    }
}

/// Encode a test signal through the full pipeline and decode it again in
/// steady state. Returns the low-passed reference and the decoded audio.
fn round_trip(signal: Pcm) -> ([Vec<f32>; 2], [Vec<f32>; 2], Vec<u8>) {
    let (file, cut) = encode_snd0(signal.clone(), &Snd0Options::default()).unwrap();
    assert_eq!(cut, None);
    let report = inspect_at3(&file);
    assert!(report.is_strictly_valid(), "{:?}", report.findings);

    let mut reference = signal;
    pcm::lowpass(&mut reference);
    let decoded = decode_looped(data_chunk(&file));
    let n = reference.len();
    let reference = [reference.channels[0].clone(), reference.channels[1].clone()];
    let decoded = [decoded[0][..n].to_vec(), decoded[1][..n].to_vec()];
    (reference, decoded, file)
}

// --- the known-good fixture and retail files ------------------------------------

#[test]
fn known_good_fixture_is_what_the_plan_says() {
    let file = known_good();
    assert_eq!(file.len(), 211_836);
    let report = inspect_at3(&file);
    assert!(report.is_strictly_valid(), "{:?}", report.findings);
    assert_eq!(report.frames, 1103);
    assert_eq!(report.bitrate_bps(), Some(66_144));
    assert!((report.duration_seconds() - 25.61).abs() < 0.01);
    // Three coded bands in every frame, in both units.
    assert_eq!(report.bands_first_unit, [0, 0, 1103, 0]);
    assert_eq!(report.bands_second_unit, [0, 0, 1103, 0]);
    assert!(data_chunk(&file).chunks_exact(192).all(|f| f[0] == 0xA2));
}

#[test]
fn our_fmt_chunk_is_the_known_good_one_byte_for_byte() {
    let file = known_good();
    let theirs = riff::parse(&file).unwrap().fmt.unwrap();
    assert_eq!(theirs.raw, LP4_FMT);
    let (ours, _) = encode_snd0(chord(0.5), &Snd0Options::default()).unwrap();
    // The whole header, not just fmt: RIFF, fmt, then data and nothing else.
    assert_eq!(ours[12..52], file[12..52]);
    let names: Vec<_> = riff::parse(&ours)
        .unwrap()
        .chunks
        .iter()
        .map(|c| c.name())
        .collect();
    assert_eq!(names, ["fmt", "data"]);
}

#[test]
fn retail_snd0s_are_playable_and_share_the_invariant_fmt_fields() {
    for (name, file) in retail_snd0s() {
        let report = inspect_at3(&file);
        assert!(report.is_playable(), "{name}: {:?}", report.findings);
        assert_eq!(report.frames_decoded, report.frames, "{name}");
        // Sony never codes the fourth band either.
        assert_eq!(report.bands_first_unit[3], 0, "{name}");
        assert_eq!(report.bands_second_unit[3], 0, "{name}");

        let fmt = riff::parse(&file).unwrap().fmt.unwrap();
        // Whatever the bitrate, these agree with the LP4 profile.
        assert_eq!(fmt.raw[0..8], LP4_FMT[0..8], "{name}: tag, channels, rate");
        assert_eq!(
            fmt.raw[14..24],
            LP4_FMT[14..24],
            "{name}: bits, extension start"
        );
        assert_eq!(fmt.raw[28..32], LP4_FMT[28..32], "{name}: extension end");
        eprintln!(
            "{name}: {} frames of {} bytes, first-unit bands {:?}, warnings: {}",
            report.frames,
            fmt.block_align,
            report.bands_first_unit,
            report.warnings().count()
        );
    }
}

#[test]
fn our_decoder_agrees_with_ffmpeg_on_sony_and_known_good_files() {
    let mut files = vec![("known good".to_string(), known_good())];
    files.extend(retail_snd0s());
    for (name, file) in files {
        let ours = decode_all(data_chunk(&file), layout_of(&file)).unwrap();
        let Some(theirs) = ffmpeg_decode(&file) else {
            eprintln!("ffmpeg not available; skipping the oracle comparison");
            return;
        };
        for ch in 0..2 {
            assert_eq!(ours[ch].len(), theirs[ch].len(), "{name}");
            let snr = snr_db(&theirs[ch], &ours[ch]);
            assert!(snr > 100.0, "{name} channel {ch}: {snr:.1} dB from ffmpeg");
        }
    }
}

#[test]
fn retail_and_known_good_files_survive_a_round_trip_through_our_codec() {
    let mut files = vec![("known good".to_string(), known_good())];
    files.extend(retail_snd0s());
    for (name, file) in files {
        // Decode theirs, encode ours, decode ours: a real music signal.
        let snd0 = make_snd0(
            &file,
            &Snd0Options {
                start: None,
                duration: Some(6.0),
            },
        )
        .unwrap();
        assert!(matches!(snd0.source, Snd0Source::Encoded { .. }));
        let report = inspect_at3(&snd0.data);
        assert!(report.is_strictly_valid(), "{name}: {:?}", report.findings);
        let [l, r] = decode_all(data_chunk(&file), layout_of(&file)).unwrap();
        let mut reference = Pcm {
            sample_rate: 44_100,
            channels: vec![l, r],
        };
        pcm::trim(&mut reference, 0.0, Some(6.0));
        pcm::lowpass(&mut reference);
        let ours = decode_looped(data_chunk(&snd0.data));
        let n = reference.len();
        let snr = snr_db(&reference.channels[0], &ours[0][..n]);
        eprintln!("{name}: re-encoded at {snr:.1} dB SNR");
        assert!(snr > 8.0, "{name}: {snr:.1} dB");
    }
}

// --- the validator rejects what the XMB rejects ------------------------------------

/// A frame that decodes cleanly but codes `bands` QMF bands in the first unit.
fn silent_frame(bands: u32) -> [u8; FRAME_BYTES] {
    let mut mid = BitWriter::new();
    mid.put(0x28, 6);
    mid.put(bands - 1, 2);
    for _ in 0..bands {
        mid.put(0, 3); // no gain points
    }
    mid.put(0, 5); // no tonal components
    mid.put(0, 5); // one subband ...
    mid.put(0, 1);
    mid.put(0, 3); // ... coding nothing
    let mut side = BitWriter::new();
    side.put(0, 1);
    side.put(7, 3);
    for _ in 0..4 {
        side.put(3, 2);
    }
    side.put(3, 2);
    side.put(2, 2);
    for _ in 0..3 {
        side.put(0, 3);
    }
    side.put(0, 5);
    side.put(0, 5);
    side.put(0, 1);
    side.put(0, 3);
    let mut frame = [0u8; FRAME_BYTES];
    let (mid, side) = (mid.into_bytes(), side.into_bytes());
    frame[..mid.len()].copy_from_slice(&mid);
    for (k, &b) in side.iter().enumerate() {
        frame[FRAME_BYTES - 1 - k] = b;
    }
    frame
}

fn silent_file(frames: usize) -> Vec<u8> {
    write_lp4(&silent_frame(3).repeat(frames))
}

/// Replace the fmt body of an LP4 file.
fn with_fmt(file: &[u8], edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut out = file.to_vec();
    edit(&mut out[20..52]);
    out
}

fn strict_failure(file: &[u8]) -> String {
    inspect_at3(file)
        .failure_summary(true)
        .expect("expected the strict check to fail")
}

#[test]
fn synthetic_silent_frames_are_valid() {
    let report = inspect_at3(&silent_file(20));
    assert!(report.is_strictly_valid(), "{:?}", report.findings);
}

#[test]
fn a_four_band_frame_is_named_and_rejected() {
    let mut frames = silent_frame(3).repeat(20);
    frames[17 * FRAME_BYTES..18 * FRAME_BYTES].copy_from_slice(&silent_frame(4));
    let file = write_lp4(&frames);
    let report = inspect_at3(&file);
    assert!(!report.is_playable());
    // It is a well-formed frame; the only thing wrong is the band count.
    assert_eq!(report.frames_decoded, 20);
    let errors: Vec<_> = report.errors().map(|f| f.message.clone()).collect();
    assert_eq!(
        errors,
        ["frame 17 codes four QMF bands; the XMB will not play this"]
    );
    assert_eq!(data_chunk(&file)[17 * FRAME_BYTES], 0xA3);
}

#[test]
fn a_four_band_frame_is_named_even_when_it_does_not_decode() {
    let mut frames = encoder::encode(&chord(0.5).channels[0], &chord(0.5).channels[1]);
    frames[5 * FRAME_BYTES] = 0xA3;
    let summary = inspect_at3(&write_lp4(&frames))
        .failure_summary(false)
        .unwrap();
    assert!(
        summary.contains("frame 5 codes four QMF bands"),
        "{summary}"
    );
}

#[test]
fn lp2_is_flagged() {
    let file = with_fmt(&silent_file(20), |fmt| {
        fmt[8..12].copy_from_slice(&16538u32.to_le_bytes());
        fmt[12..14].copy_from_slice(&384u16.to_le_bytes());
    });
    assert!(strict_failure(&file).contains("it is LP2 (132 kbps)"));
}

#[test]
fn a_fact_chunk_is_flagged() {
    let plain = silent_file(20);
    let mut file = plain[..52].to_vec();
    file.extend_from_slice(b"fact");
    file.extend_from_slice(&8u32.to_le_bytes());
    file.extend_from_slice(&(20u32 * 1024 - 1000).to_le_bytes());
    file.extend_from_slice(&1000u32.to_le_bytes());
    file.extend_from_slice(&plain[52..]);
    let riff_size = (file.len() - 8) as u32;
    file[4..8].copy_from_slice(&riff_size.to_le_bytes());
    let report = inspect_at3(&file);
    // Sony's files carry one and play; it fails only the strict profile.
    assert!(report.is_playable());
    assert!(strict_failure(&file).contains("it has a fact chunk"));
}

#[test]
fn over_55_seconds_is_rejected() {
    // 2369 frames is 55.008 s.
    let summary = inspect_at3(&silent_file(2369))
        .failure_summary(false)
        .unwrap();
    assert_eq!(summary, "it lasts 55.01 s; the XMB plays at most 55 s");
    assert!(inspect_at3(&silent_file(2368)).is_strictly_valid());
}

#[test]
fn over_500_kb_is_rejected() {
    let summary = inspect_at3(&silent_file(2700))
        .failure_summary(false)
        .unwrap();
    assert!(
        summary.contains("the file is 518460 bytes; the XMB plays at most 500000 bytes (500 KB)"),
        "{summary}"
    );
}

#[test]
fn mono_is_rejected() {
    let file = with_fmt(&silent_file(20), |fmt| {
        fmt[2..4].copy_from_slice(&1u16.to_le_bytes())
    });
    let summary = inspect_at3(&file).failure_summary(false).unwrap();
    assert!(
        summary.contains("it has 1 channel (mono); SND0 must be stereo"),
        "{summary}"
    );
}

#[test]
fn a_48khz_file_is_rejected() {
    let file = with_fmt(&silent_file(20), |fmt| {
        fmt[4..8].copy_from_slice(&48_000u32.to_le_bytes())
    });
    let summary = inspect_at3(&file).failure_summary(false).unwrap();
    assert!(
        summary.contains("the sample rate is 48000 Hz; the XMB only plays 44100 Hz"),
        "{summary}"
    );
}

#[test]
fn other_formats_and_garbage_are_rejected_not_panicked_on() {
    for file in [
        Vec::new(),
        b"RIFF\x04\0\0\0WAVE".to_vec(),
        with_fmt(&silent_file(4), |fmt| {
            fmt[0..2].copy_from_slice(&1u16.to_le_bytes())
        }),
        {
            let mut f = silent_file(4);
            f.truncate(f.len() - 7);
            f
        },
        {
            let mut f = silent_file(4);
            for b in &mut f[60..] {
                *b = 0xFF;
            }
            f
        },
    ] {
        assert!(!inspect_at3(&file).is_playable());
    }
}

// --- what the encoder writes --------------------------------------------------------

#[test]
fn every_frame_codes_three_bands_and_carries_unity_joint_stereo() {
    let signal = drum_loop(1.0);
    let frames = encoder::encode(&signal.channels[0], &signal.channels[1]);
    for frame in frames.chunks_exact(FRAME_BYTES) {
        assert_eq!(frame[0], 0xA2);
        // Reversed: no weighting (0, 7), then matrix selector 3 in all bands.
        assert_eq!(frame[FRAME_BYTES - 1], 0x7F);
    }
}

#[test]
fn quality_floors_hold_for_the_test_signals() {
    // (name, signal, overall floor, per-band floors) in dB. Measured values
    // are recorded in docs/AUDIO.md; floors sit a little below them. The
    // chord has almost nothing above band 0, and at 66 kbps pink noise gets
    // next to no bits in band 2, so those band floors are low by nature.
    let cases: [(&str, Pcm, f64, [f64; 3]); 4] = [
        ("sine sweep", sweep(2.0), 31.0, [31.0, 31.0, 29.5]),
        ("pink noise", pink_noise(2.0), 8.5, [11.0, 1.5, -1.0]),
        ("drum loop", drum_loop(2.0), 16.5, [21.0, 6.0, 5.0]),
        ("tonal chord", chord(2.0), 32.5, [32.5, 7.0, 4.0]),
    ];
    for (name, signal, floor, band_floors) in cases {
        let (reference, decoded, file) = round_trip(signal);
        for ch in 0..2 {
            let snr = snr_db(&reference[ch], &decoded[ch]);
            let bands = band_snr_db(&reference[ch], &decoded[ch]);
            eprintln!(
                "{name} ch{ch}: {snr:.1} dB; bands {:.1} / {:.1} / {:.1} dB",
                bands[0], bands[1], bands[2]
            );
            assert!(snr >= floor, "{name} ch{ch}: {snr:.1} dB < {floor}");
            for b in 0..3 {
                assert!(
                    bands[b] >= band_floors[b],
                    "{name} ch{ch} band {b}: {:.1} dB",
                    bands[b]
                );
            }
        }
        if let Some(theirs) = ffmpeg_decode(&file) {
            // ffmpeg starts cold rather than in steady state; skip the first
            // frame, where only the history differs.
            let ours = decode_all(data_chunk(&file), LP4).unwrap();
            for ch in 0..2 {
                let snr = snr_db(&theirs[ch][FRAME_SAMPLES..], &ours[ch][FRAME_SAMPLES..]);
                assert!(snr > 100.0, "{name} ch{ch}: ffmpeg disagrees ({snr:.1} dB)");
            }
        }
    }
}

#[test]
fn output_is_aligned_with_the_input_and_the_loop_seam_is_clean() {
    let (reference, decoded, _) = round_trip(chord(1.0));
    let overall = snr_db(&reference[0], &decoded[0]);
    // The first and last 2048 samples straddle the loop point.
    let n = reference[0].len();
    let seam: Vec<f32> = [&reference[0][n - 2048..], &reference[0][..2048]].concat();
    let seam_decoded: Vec<f32> = [&decoded[0][n - 2048..], &decoded[0][..2048]].concat();
    let at_seam = snr_db(&seam, &seam_decoded);
    assert!(
        at_seam > overall - 6.0,
        "seam {at_seam:.1} dB vs {overall:.1} dB overall"
    );
}

#[test]
fn output_has_no_delay() {
    // Broadband, so any shift shows: the best match must be at lag zero.
    let (reference, decoded, _) = round_trip(drum_loop(1.0));
    let n = reference[0].len();
    let correlation = |lag: isize| -> f64 {
        (0..n)
            .map(|i| {
                let j = (i as isize + lag).rem_euclid(n as isize) as usize;
                f64::from(reference[0][i]) * f64::from(decoded[0][j])
            })
            .sum()
    };
    let best = (-64..=64)
        .max_by(|&a, &b| correlation(a).total_cmp(&correlation(b)))
        .unwrap();
    assert_eq!(best, 0);
}

// --- the pipeline ------------------------------------------------------------------

fn wav(rate: u32, channels: &[Vec<f32>]) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    let spec = hound::WavSpec {
        channels: channels.len() as u16,
        sample_rate: rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::new(&mut out, spec).unwrap();
    for i in 0..channels[0].len() {
        for c in channels {
            writer
                .write_sample(c[i].round().clamp(-32768.0, 32767.0) as i16)
                .unwrap();
        }
    }
    writer.finalize().unwrap();
    out.into_inner()
}

fn tone(rate: u32, hz: f64, seconds: f64, amplitude: f64) -> Vec<f32> {
    (0..(f64::from(rate) * seconds) as usize)
        .map(|i| {
            (amplitude * (2.0 * std::f64::consts::PI * hz * i as f64 / f64::from(rate)).sin())
                as f32
        })
        .collect()
}

/// The 1 kHz-ish content of an SND0, as SNR against a clean tone.
fn check_tone(file: &[u8], hz: f64, amplitude: f64, seconds: f64) {
    let report = inspect_at3(file);
    assert!(report.is_strictly_valid(), "{:?}", report.findings);
    let decoded = decode_looped(data_chunk(file));
    let expected = tone(44_100, hz, seconds, amplitude);
    let n = expected.len() - 4096;
    for (ch, decoded) in decoded.iter().enumerate() {
        let snr = snr_db(&expected[2048..n], &decoded[2048..n]);
        assert!(snr > 25.0, "channel {ch}: {snr:.1} dB");
    }
}

#[test]
fn every_input_format_converts() {
    for name in ["chord_48k.flac", "chord.ogg", "chord_32k_mono.mp3"] {
        let snd0 = make_snd0(&fixture(name), &Snd0Options::default()).unwrap();
        let Snd0Source::Encoded { input_seconds, .. } = snd0.source else {
            panic!("{name} was not encoded");
        };
        // MP3 padding must be trimmed, or a looped track gains a gap.
        assert!(
            (input_seconds - 1.5).abs() < 0.001,
            "{name}: {input_seconds} s"
        );
        assert!(
            snd0.report.is_strictly_valid(),
            "{name}: {:?}",
            snd0.report.findings
        );
        assert_eq!(
            snd0.report.frames,
            (1.5f64 * 44_100.0 / 1024.0).ceil() as usize,
            "{name}"
        );
        // The dominant 220 Hz tone comes back at the level the input decodes
        // to (a lossy input need not hold it at exactly its nominal level).
        let level = |pcm: &[f32], rate: u32| {
            let reference = tone(rate, 220.0, 1.5, 1.0);
            reference
                .iter()
                .zip(pcm)
                .map(|(&a, &b)| f64::from(a) * f64::from(b))
                .sum::<f64>()
                / reference.iter().map(|&a| f64::from(a).powi(2)).sum::<f64>()
        };
        let (_, input) = pspbuild::audio::input::decode(&fixture(name)).unwrap();
        let before = level(&input.channels[0], input.sample_rate);
        let decoded = decode_looped(data_chunk(&snd0.data));
        for (ch, decoded) in decoded.iter().enumerate() {
            let after = level(decoded, 44_100);
            assert!(
                (after / before - 1.0).abs() < 0.03,
                "{name} ch{ch}: 220 Hz at {after:.0}, was {before:.0}"
            );
        }
    }
}

#[test]
fn wav_inputs_of_any_rate_and_layout_convert() {
    // Stereo at the target rate.
    let t = tone(44_100, 1000.0, 1.0, 8000.0);
    check_tone(
        &make_snd0(&wav(44_100, &[t.clone(), t]), &Snd0Options::default())
            .unwrap()
            .data,
        1000.0,
        8000.0,
        1.0,
    );
    // Mono at 48 kHz: resampled and duplicated.
    let t = tone(48_000, 1000.0, 1.0, 8000.0);
    check_tone(
        &make_snd0(&wav(48_000, &[t]), &Snd0Options::default())
            .unwrap()
            .data,
        1000.0,
        8000.0,
        1.0,
    );
    // 5.1 with the tone in front left and right only: folded to stereo at
    // the level of a two-channel file whose loudest input is the same.
    let t = tone(22_050, 1000.0, 1.0, 8000.0);
    let silence = vec![0f32; t.len()];
    let surround = [
        t.clone(),
        t,
        silence.clone(),
        silence.clone(),
        silence.clone(),
        silence,
    ];
    let snd0 = make_snd0(&wav(22_050, &surround), &Snd0Options::default()).unwrap();
    let scale = 1.0 / (1.0 + 2.0 * std::f64::consts::FRAC_1_SQRT_2);
    check_tone(&snd0.data, 1000.0, 8000.0 * scale, 1.0);
}

#[test]
fn long_input_is_cut_to_fit_and_says_so() {
    let t = tone(44_100, 440.0, 60.0, 3000.0);
    let snd0 = make_snd0(&wav(44_100, &[t]), &Snd0Options::default()).unwrap();
    assert_eq!(snd0.report.frames, 2368);
    assert!(snd0.report.duration_seconds() <= 55.0);
    assert!(snd0.data.len() <= 500_000);
    assert_eq!(snd0.notices.len(), 1);
    assert!(
        snd0.notices[0].contains("cut to the first 54.98 s"),
        "{}",
        snd0.notices[0]
    );
}

#[test]
fn start_and_duration_select_a_section() {
    // Two seconds of 500 Hz then two of 1500 Hz; keep one second of the second.
    let mut t = tone(44_100, 500.0, 2.0, 8000.0);
    t.extend(tone(44_100, 1500.0, 2.0, 8000.0));
    let options = Snd0Options {
        start: Some(2.0),
        duration: Some(1.0),
    };
    let snd0 = make_snd0(&wav(44_100, &[t]), &options).unwrap();
    assert_eq!(snd0.report.frames, 44_100usize.div_ceil(1024));
    check_tone(&snd0.data, 1500.0, 8000.0, 1.0);

    let past = Snd0Options {
        start: Some(10.0),
        duration: None,
    };
    assert!(make_snd0(&wav(44_100, &[tone(44_100, 500.0, 1.0, 1.0)]), &past).is_err());
}

#[test]
fn a_playable_snd0_passes_through_untouched() {
    let file = known_good();
    let snd0 = make_snd0(&file, &Snd0Options::default()).unwrap();
    assert_eq!(snd0.source, Snd0Source::PassedThrough);
    assert_eq!(snd0.data, file);
    assert!(snd0.notices.is_empty());
}

#[test]
fn an_unplayable_atrac3_file_is_reencoded() {
    // A four-band frame makes the XMB play nothing; decode it and start over.
    let mut frames = silent_frame(3).repeat(40);
    frames[..FRAME_BYTES].copy_from_slice(&silent_frame(4));
    let bad = write_lp4(&frames);
    let snd0 = make_snd0(&bad, &Snd0Options::default()).unwrap();
    let Snd0Source::Encoded {
        reencoded_because, ..
    } = &snd0.source
    else {
        panic!("passed an unplayable file through");
    };
    assert!(
        reencoded_because
            .as_deref()
            .unwrap()
            .contains("four QMF bands")
    );
    assert!(snd0.report.is_strictly_valid());
}

#[test]
fn unsupported_inputs_say_why() {
    let error = make_snd0(b"\0\0\0\x20ftypM4A \0\0\0\0", &Snd0Options::default())
        .unwrap_err()
        .to_string();
    assert!(error.contains("AAC/M4A is not supported"), "{error}");
    let error = make_snd0(b"not audio at all", &Snd0Options::default())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unrecognised audio format"), "{error}");
}

#[test]
fn damaged_inputs_fail_cleanly() {
    let mut rng = Lcg(7);
    let wav_file = wav(44_100, &[tone(44_100, 440.0, 0.2, 5000.0)]);
    let inputs = [
        fixture("chord_48k.flac"),
        fixture("chord.ogg"),
        fixture("chord_32k_mono.mp3"),
        wav_file,
        silent_file(8),
    ];
    for input in &inputs {
        for cut in [0, 1, 4, 12, 44, 100, input.len() / 3, input.len() - 1] {
            let _ = make_snd0(&input[..cut.min(input.len())], &Snd0Options::default());
        }
        for _ in 0..4 {
            let mut damaged = input.clone();
            for _ in 0..16 {
                let at = (rng.next().abs() * (damaged.len() - 1) as f32) as usize;
                damaged[at] ^= 1 << ((rng.next().abs() * 7.0) as u32);
            }
            let _ = make_snd0(&damaged, &Snd0Options::default());
            let _ = inspect_at3(&damaged);
        }
    }
    // A header claiming 0-bit samples.
    let mut zero_bits = wav(44_100, &[vec![0.0; 16]]);
    zero_bits[34] = 0;
    assert!(make_snd0(&zero_bits, &Snd0Options::default()).is_err());
}
