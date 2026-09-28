//! Audio for the XMB: turning ordinary music files into `SND0.AT3`.
//!
//! ```no_run
//! use pspbuild::audio::{Snd0Options, make_snd0};
//!
//! let theme = std::fs::read("theme.flac")?;
//! let snd0 = make_snd0(&theme, &Snd0Options::default())?;
//! std::fs::write("SND0.AT3", &snd0.data)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Pipeline
//!
//! ```text
//! WAV/FLAC/Ogg/MP3 -> PCM -> stereo -> trim -> 44.1 kHz -> low-pass 15.5 kHz
//!                  -> ATRAC3 LP4, three bands -> RIFF (fmt, data) -> validate
//! ```
//!
//! The format rules, and the reason for each, are in `docs/AUDIO.md`.

pub mod atrac3;
pub mod input;
pub mod pcm;
pub mod riff;
pub mod validate;

pub use input::InputFormat;
pub use pcm::Pcm;
pub use validate::{At3Report, Finding, Severity, inspect_at3};

use crate::error::{Error, Result};
use atrac3::tables::FRAME_SAMPLES;
use validate::{MAX_SECONDS, SAMPLE_RATE};

/// Choices for [`make_snd0`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snd0Options {
    /// Seconds to skip at the start of the input.
    pub start: Option<f64>,
    /// Seconds to keep. Without it, as much as the XMB allows.
    pub duration: Option<f64>,
}

impl Snd0Options {
    fn trims(&self) -> bool {
        self.start.is_some() || self.duration.is_some()
    }
}

/// How an SND0 came to be.
#[derive(Debug, Clone, PartialEq)]
pub enum Snd0Source {
    /// The input was already a playable SND0 and is used byte for byte.
    PassedThrough,
    /// The input was decoded and encoded afresh.
    Encoded {
        format: InputFormat,
        sample_rate: u32,
        channels: usize,
        /// Length of the input, in seconds.
        input_seconds: f64,
        /// Why an input that was already ATRAC3 was not used as-is.
        reencoded_because: Option<String>,
    },
}

/// A finished `SND0.AT3`.
#[derive(Debug, Clone)]
pub struct Snd0 {
    pub data: Vec<u8>,
    pub source: Snd0Source,
    /// The validator's view of `data`.
    pub report: At3Report,
    /// Things the caller should hear about even on success, such as the input
    /// being cut to fit.
    pub notices: Vec<String>,
}

/// The most samples an SND0 may hold: whole frames within [`MAX_SECONDS`].
pub const MAX_SAMPLES: usize =
    (MAX_SECONDS as usize * SAMPLE_RATE as usize) / FRAME_SAMPLES * FRAME_SAMPLES;

/// Turn any supported audio file into an `SND0.AT3`.
///
/// A file that is already a playable SND0 is passed through unchanged, unless
/// trimming was asked for. Anything else — including an ATRAC3 file the XMB
/// would reject — is decoded and encoded afresh. The result is validated
/// strictly; a file that fails is never returned.
pub fn make_snd0(input: &[u8], options: &Snd0Options) -> Result<Snd0> {
    let format = input::detect(input)?;
    let mut reencoded_because = None;
    if format == InputFormat::Atrac3 {
        let report = inspect_at3(input);
        if report.is_playable() && !options.trims() {
            let notices = report
                .warnings()
                .map(|w| format!("SND0 passed through as-is, but {}", w.message))
                .collect();
            return Ok(Snd0 {
                data: input.to_vec(),
                source: Snd0Source::PassedThrough,
                report,
                notices,
            });
        }
        reencoded_because = Some(
            report
                .failure_summary(false)
                .unwrap_or_else(|| "trimming was requested".into()),
        );
    }

    let (format, pcm) = input::decode(input)?;
    let (sample_rate, channels, input_seconds) =
        (pcm.sample_rate, pcm.channels.len(), pcm.seconds());
    let mut notices = Vec::new();
    if let Some(reason) = &reencoded_because {
        notices.push(format!("the ATRAC3 input was re-encoded: {reason}"));
    }
    let (data, cut) = encode_snd0(pcm, options)?;
    if let Some(seconds) = cut {
        notices.push(format!(
            "the audio was cut to the first {:.2} s; the XMB plays at most {MAX_SECONDS:.0} s \
             (choose another section with --start/--duration)",
            seconds
        ));
    }
    let report = inspect_at3(&data);
    if let Some(problems) = report.failure_summary(true) {
        return Err(Error::InvalidAudio(format!(
            "refusing to write an SND0 that fails validation: {problems}"
        )));
    }
    Ok(Snd0 {
        data,
        source: Snd0Source::Encoded {
            format,
            sample_rate,
            channels,
            input_seconds,
            reencoded_because,
        },
        report,
        notices,
    })
}

/// Condition PCM and encode it as an `SND0.AT3`.
///
/// Returns the file and, when the audio had to be shortened to fit the XMB's
/// limit, the length it was cut to.
pub fn encode_snd0(mut pcm: Pcm, options: &Snd0Options) -> Result<(Vec<u8>, Option<f64>)> {
    for (name, value) in [("start", options.start), ("duration", options.duration)] {
        if let Some(v) = value
            && !(v.is_finite() && v >= 0.0)
        {
            return Err(Error::InvalidAudio(format!(
                "--{name} must be a non-negative number of seconds, not {v}"
            )));
        }
    }
    if options.duration == Some(0.0) {
        return Err(Error::InvalidAudio(
            "--duration 0 leaves nothing to encode".into(),
        ));
    }

    pcm = pcm::to_stereo(pcm);
    if options.trims() {
        let start = options.start.unwrap_or(0.0);
        if start >= pcm.seconds() {
            return Err(Error::InvalidAudio(format!(
                "--start {start} is past the end of the {:.2} s input",
                pcm.seconds()
            )));
        }
        pcm::trim(&mut pcm, start, options.duration);
    }
    // Cut in the source rate before resampling, so only what is kept is
    // processed; then cut exactly once resampled.
    let mut cut = None;
    if pcm.seconds() > MAX_SAMPLES as f64 / f64::from(SAMPLE_RATE) {
        let keep = MAX_SAMPLES as f64 / f64::from(SAMPLE_RATE);
        pcm::trim(&mut pcm, 0.0, Some(keep + 0.1));
        cut = Some(keep);
    }
    let mut pcm = pcm::resample(&pcm, SAMPLE_RATE);
    for channel in &mut pcm.channels {
        channel.truncate(MAX_SAMPLES);
    }
    // No fade, at either end: the XMB loops SND0, and a fade would put a dip
    // at the loop point.
    pcm::lowpass(&mut pcm);

    let frames = atrac3::encoder::encode(&pcm.channels[0], &pcm.channels[1]);
    Ok((riff::write_lp4(&frames), cut))
}
