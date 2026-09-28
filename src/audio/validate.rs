//! Checking an `SND0.AT3` against what the XMB will play.
//!
//! Findings come in two strengths:
//!
//! - **errors**: the XMB will not play the file, or it is not a well-formed
//!   ATRAC3 stream at all;
//! - **warnings**: the file differs from the profile pspbuild writes — the one
//!   proven on hardware — in a way that is not known to break playback.
//!   Sony's own SND0s trip some of these, which is why they are not errors.
//!
//! A strict check, which is what pspbuild applies to its own output, treats
//! both as failures.

use super::atrac3::decoder::{Decoder, Layout, unit_bands};
use super::atrac3::tables::FRAME_SAMPLES;
use super::riff::{self, FORMAT_ATRAC3, LP4_FMT};

/// Longest SND0 the XMB plays, in seconds.
pub const MAX_SECONDS: f64 = 55.0;

/// Largest SND0 the XMB plays, in bytes.
pub const MAX_BYTES: usize = 500_000;

/// The only sample rate the XMB plays.
pub const SAMPLE_RATE: u32 = 44_100;

/// LP4: 66 kbps joint stereo.
pub const LP4_BLOCK_ALIGN: u16 = 192;

/// LP2: 132 kbps, two independent channels.
pub const LP2_BLOCK_ALIGN: u16 = 384;

/// How many problem frames to name before summarising the rest.
const FRAMES_NAMED: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The XMB will not play this.
    Error,
    /// Differs from the hardware-proven profile.
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

/// One chunk, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkReport {
    pub id: String,
    pub offset: usize,
    pub size: u32,
}

/// Everything `audio inspect` says about a file.
#[derive(Debug, Clone, Default)]
pub struct At3Report {
    pub file_size: usize,
    pub chunks: Vec<ChunkReport>,
    pub format_tag: Option<u16>,
    pub channels: Option<u16>,
    pub sample_rate: Option<u32>,
    pub byte_rate: Option<u32>,
    pub block_align: Option<u16>,
    pub joint_stereo: Option<bool>,
    /// Whether the fmt chunk is byte for byte the known-good LP4 one.
    pub fmt_matches_known_good: bool,
    pub frames: usize,
    /// Frames by stored band count (0 to 3) of the first sound unit.
    pub bands_first_unit: [usize; 4],
    /// The same for the second unit: the side channel in joint stereo, the
    /// right channel otherwise.
    pub bands_second_unit: [usize; 4],
    /// Frames that decoded without error.
    pub frames_decoded: usize,
    /// The `fact` chunk: samples and decoder delay.
    pub fact: Option<riff::Fact>,
    /// The loop point from `smpl`.
    pub loop_points: Option<riff::Loop>,
    pub findings: Vec<Finding>,
}

impl At3Report {
    /// Playing time implied by the frame count.
    pub fn duration_seconds(&self) -> f64 {
        (self.frames * FRAME_SAMPLES) as f64 / f64::from(SAMPLE_RATE)
    }

    pub fn bitrate_bps(&self) -> Option<u32> {
        self.byte_rate.map(|b| b * 8)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
    }

    /// No errors: nothing known to stop the XMB playing it.
    pub fn is_playable(&self) -> bool {
        self.errors().next().is_none()
    }

    /// No findings at all: the profile pspbuild writes.
    pub fn is_strictly_valid(&self) -> bool {
        self.findings.is_empty()
    }

    /// The findings that fail a check, strict or not, in one message.
    pub fn failure_summary(&self, strict: bool) -> Option<String> {
        let failing: Vec<_> = self
            .findings
            .iter()
            .filter(|f| strict || f.severity == Severity::Error)
            .map(|f| f.message.as_str())
            .collect();
        (!failing.is_empty()).then(|| failing.join("; "))
    }

    fn error(&mut self, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Error,
            message: message.into(),
        });
    }

    fn warning(&mut self, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Warning,
            message: message.into(),
        });
    }
}

/// Inspect and validate an `SND0.AT3`. Never fails: a file that cannot be
/// read is a report full of errors.
pub fn inspect_at3(file: &[u8]) -> At3Report {
    let mut report = At3Report {
        file_size: file.len(),
        ..Default::default()
    };

    let wave = match riff::parse(file) {
        Ok(wave) => wave,
        Err(e) => {
            report.error(e);
            return report;
        }
    };
    report.chunks = wave
        .chunks
        .iter()
        .map(|c| ChunkReport {
            id: c.name(),
            offset: c.offset,
            size: c.size,
        })
        .collect();

    if file.len() > MAX_BYTES {
        report.error(format!(
            "the file is {} bytes; the XMB plays at most {MAX_BYTES} bytes (500 KB)",
            file.len()
        ));
    }

    let Some(fmt) = wave.fmt.clone() else {
        report.error("there is no fmt chunk, so nothing says what the audio is");
        return report;
    };
    report.format_tag = Some(fmt.format_tag);
    report.channels = Some(fmt.channels);
    report.sample_rate = Some(fmt.sample_rate);
    report.byte_rate = Some(fmt.byte_rate);
    report.block_align = Some(fmt.block_align);
    report.joint_stereo = fmt.joint_stereo();
    report.fmt_matches_known_good = fmt.raw == LP4_FMT;

    let mut decodable = true;
    if fmt.format_tag != FORMAT_ATRAC3 {
        report.error(format!(
            "the format tag is {:#06X} ({}), not 0x0270 (ATRAC3)",
            fmt.format_tag,
            format_name(fmt.format_tag)
        ));
        decodable = false;
    }
    if fmt.sample_rate != SAMPLE_RATE {
        report.error(format!(
            "the sample rate is {} Hz; the XMB only plays {SAMPLE_RATE} Hz",
            fmt.sample_rate
        ));
    }
    if fmt.channels != 2 {
        report.error(format!(
            "it has {} channel{}{}; SND0 must be stereo",
            fmt.channels,
            if fmt.channels == 1 { "" } else { "s" },
            if fmt.channels == 1 { " (mono)" } else { "" }
        ));
        decodable = false;
    }
    match fmt.block_align {
        LP4_BLOCK_ALIGN => {}
        LP2_BLOCK_ALIGN => report.warning(
            "it is LP2 (132 kbps); pspbuild writes LP4 (66 kbps), the bitrate proven on \
             hardware. Sony ships LP2 SND0s, but homebrew LP2 files have been seen not to play",
        ),
        other => {
            report.error(format!(
                "the block align is {other} bytes, which is neither LP4 (192) nor LP2 (384)"
            ));
            decodable = false;
        }
    }
    let expected_rate = f64::from(fmt.block_align) * f64::from(SAMPLE_RATE) / FRAME_SAMPLES as f64;
    if (f64::from(fmt.byte_rate) - expected_rate).abs() >= 1.0 {
        report.warning(format!(
            "the byte rate is {} bytes/s, but {}-byte frames at {SAMPLE_RATE} Hz are {:.0} bytes/s",
            fmt.byte_rate, fmt.block_align, expected_rate
        ));
    }
    let joint = match (fmt.joint_stereo(), fmt.block_align) {
        (Some(joint), _) => joint,
        (None, align) => {
            report.warning("the fmt chunk has no ATRAC3 extension, so the stereo mode is a guess");
            align == LP4_BLOCK_ALIGN
        }
    };
    if fmt.block_align == LP4_BLOCK_ALIGN && !joint {
        report.warning("LP4 without joint stereo; every LP4 SND0 known to play is joint stereo");
    }
    if decodable
        && fmt.block_align == LP4_BLOCK_ALIGN
        && fmt.extension.len() == 14
        && !report.fmt_matches_known_good
    {
        report.warning("the fmt chunk differs from the known-good LP4 one");
    }

    for chunk in &report.chunks.clone() {
        match chunk.id.as_str() {
            "fmt" | "data" | "fact" | "smpl" => {}
            other => report.warning(format!(
                "it has a '{other}' chunk; pspbuild writes only fmt, fact, smpl and data"
            )),
        }
    }
    report.fact = wave.fact;
    report.loop_points = wave.loop_points;

    let Some(data) = wave.data else {
        report.error("there is no data chunk");
        return report;
    };
    let align = usize::from(fmt.block_align);
    if align == 0 {
        return report;
    }
    if data.len() % align != 0 {
        report.error(format!(
            "the data is {} bytes, not a whole number of {align}-byte frames",
            data.len()
        ));
    }
    report.frames = data.len() / align;
    if report.frames == 0 {
        report.error("there are no frames");
        return report;
    }
    check_loop(&mut report);
    if report.duration_seconds() > MAX_SECONDS {
        report.error(format!(
            "it lasts {:.2} s; the XMB plays at most {MAX_SECONDS:.0} s",
            report.duration_seconds()
        ));
    }
    if decodable {
        check_frames(
            &mut report,
            data,
            Layout {
                block_align: align,
                joint_stereo: joint,
            },
        );
    }
    report
}

/// Whether the XMB will loop the file, from its `fact` and `smpl` chunks.
///
/// All three layouts below were tried on a PSP Slim: without a loop point
/// the XMB plays the file once and stops; with one but no `fact` it plays
/// nothing; with `fact` = (length, delay) and a loop from `delay` to
/// `delay + length - 1` it loops cleanly. Sony's own SND0 uses the last form.
fn check_loop(report: &mut At3Report) {
    let stream_samples = (report.frames * FRAME_SAMPLES) as u64;
    match (report.fact, report.loop_points) {
        (None, None) => report
            .warning("it has no loop point (smpl chunk), so the XMB plays it once and then stops"),
        (None, Some(_)) => report.error(
            "it has a loop point (smpl chunk) but no fact chunk; the XMB plays nothing at all",
        ),
        (Some(_), None) => report.warning(
            "it has a fact chunk but no loop point (smpl chunk), so the XMB will not loop it",
        ),
        (Some(fact), Some(looped)) => {
            let end = u64::from(fact.delay) + u64::from(fact.samples);
            if fact.samples == 0 || end > stream_samples {
                report.warning(format!(
                    "the fact chunk claims {} samples after a delay of {}, but the frames hold {stream_samples}",
                    fact.samples, fact.delay
                ));
            }
            if u64::from(looped.start) != u64::from(fact.delay) || u64::from(looped.end) + 1 != end
            {
                report.warning(format!(
                    "the loop runs from sample {} to {}, not from the fact delay {} to {}; \
                     only that layout is known to loop",
                    looped.start,
                    looped.end,
                    fact.delay,
                    end.saturating_sub(1)
                ));
            }
            if looped.play_count != 0 {
                report.warning(format!(
                    "the loop plays {} times rather than forever",
                    looped.play_count
                ));
            }
        }
    }
}

/// The report for an SND0 too large to be worth reading in full.
pub fn oversized(size: usize) -> At3Report {
    let mut report = At3Report {
        file_size: size,
        ..Default::default()
    };
    report.error(format!(
        "the file is {size} bytes; the XMB plays at most {MAX_BYTES} bytes (500 KB)"
    ));
    report
}

/// Decode every frame, counting band usage and naming bad frames.
fn check_frames(report: &mut At3Report, data: &[u8], layout: Layout) {
    let mut decoder = Decoder::new(layout);
    let mut out = [[0f32; FRAME_SAMPLES]; 2];
    let mut four_bands = Vec::new();
    let mut broken = Vec::new();
    for (i, frame) in data.chunks_exact(layout.block_align).enumerate() {
        // The band counts come from the unit headers, so a four-band frame is
        // named as such even when the rest of it will not decode.
        if let Ok([a, b]) = unit_bands(frame, layout) {
            report.bands_first_unit[usize::from(a)] += 1;
            report.bands_second_unit[usize::from(b)] += 1;
            if a == 3 || b == 3 {
                four_bands.push((i, a == 3, b == 3));
            }
        }
        match decoder.decode(frame, &mut out) {
            Ok(_) => report.frames_decoded += 1,
            Err(e) => {
                broken.push((i, e));
                // State is suspect after a bad frame; start afresh.
                decoder = Decoder::new(layout);
            }
        }
    }

    let second = if layout.joint_stereo {
        "side channel"
    } else {
        "right channel"
    };
    for &(i, first, other) in four_bands.iter().take(FRAMES_NAMED) {
        let which = match (first, other) {
            (true, true) => "codes four QMF bands in both channels".to_string(),
            (true, false) => "codes four QMF bands".to_string(),
            _ => format!("codes four QMF bands in its {second}"),
        };
        report.error(format!("frame {i} {which}; the XMB will not play this"));
    }
    if four_bands.len() > FRAMES_NAMED {
        report.error(format!(
            "{} more frames code four QMF bands",
            four_bands.len() - FRAMES_NAMED
        ));
    }
    for (i, e) in broken.iter().take(FRAMES_NAMED) {
        report.error(format!("frame {i} is not a valid ATRAC3 frame: {e}"));
    }
    if broken.len() > FRAMES_NAMED {
        report.error(format!(
            "{} more frames do not decode",
            broken.len() - FRAMES_NAMED
        ));
    }
}

fn format_name(tag: u16) -> &'static str {
    match tag {
        0x0001 => "PCM",
        0x0003 => "IEEE float",
        0x0055 => "MP3",
        0xFFFE => "extensible; ATRAC3plus uses this",
        _ => "unknown",
    }
}
