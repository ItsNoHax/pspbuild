//! Decoding ordinary audio files to PCM.
//!
//! Every decoder here is pure Rust under a permissive licence; see
//! `docs/AUDIO.md` for the list and for why some formats are missing.

use std::io::Cursor;

use super::pcm::Pcm;
use crate::error::{Error, Result};

/// A recognised input format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    Wav,
    Flac,
    OggVorbis,
    Mp3,
    /// An ATRAC3 `.AT3`, decoded with pspbuild's own decoder.
    Atrac3,
}

impl InputFormat {
    pub fn name(self) -> &'static str {
        match self {
            InputFormat::Wav => "WAV",
            InputFormat::Flac => "FLAC",
            InputFormat::OggVorbis => "Ogg Vorbis",
            InputFormat::Mp3 => "MP3",
            InputFormat::Atrac3 => "ATRAC3",
        }
    }
}

impl std::fmt::Display for InputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

const SUPPORTED: &str = "supported inputs are WAV, FLAC, Ogg Vorbis, MP3 and ATRAC3";

/// Identify an input by its content.
pub fn detect(data: &[u8]) -> Result<InputFormat> {
    let starts = |magic: &[u8]| data.len() >= magic.len() && &data[..magic.len()] == magic;
    if super::riff::is_wave(data) {
        let tag = super::riff::parse(data)
            .ok()
            .and_then(|w| w.fmt)
            .map(|f| f.format_tag);
        return Ok(if tag == Some(super::riff::FORMAT_ATRAC3) {
            InputFormat::Atrac3
        } else {
            InputFormat::Wav
        });
    }
    if starts(b"fLaC") {
        return Ok(InputFormat::Flac);
    }
    if starts(b"OggS") {
        if data.windows(7).take(256).any(|w| w == b"\x01vorbis") {
            return Ok(InputFormat::OggVorbis);
        }
        return Err(Error::UnsupportedAudio(format!(
            "this Ogg file does not hold Vorbis (Opus is not supported); {SUPPORTED}"
        )));
    }
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return Err(Error::UnsupportedAudio(format!(
            "AAC/M4A is not supported: there is no permissively licensed pure-Rust decoder for it; {SUPPORTED}"
        )));
    }
    if starts(b"ID3") || (data.len() >= 2 && data[0] == 0xFF && data[1] & 0xE0 == 0xE0) {
        return Ok(InputFormat::Mp3);
    }
    Err(Error::UnsupportedAudio(format!(
        "unrecognised audio format; {SUPPORTED}"
    )))
}

/// Decode a WAV, FLAC, Ogg Vorbis or MP3 file.
pub fn decode(data: &[u8]) -> Result<(InputFormat, Pcm)> {
    let format = detect(data)?;
    let pcm = match format {
        InputFormat::Wav => decode_wav(data)?,
        InputFormat::Flac => decode_flac(data)?,
        InputFormat::OggVorbis => decode_vorbis(data)?,
        InputFormat::Mp3 => decode_mp3(data)?,
        InputFormat::Atrac3 => decode_atrac3(data)?,
    };
    if pcm.is_empty() {
        return Err(Error::InvalidAudio(format!(
            "the {format} file holds no audio"
        )));
    }
    if !(MIN_RATE..=MAX_RATE).contains(&pcm.sample_rate) {
        return Err(Error::InvalidAudio(format!(
            "the {format} file claims a sample rate of {} Hz; expected {MIN_RATE} to {MAX_RATE} Hz",
            pcm.sample_rate
        )));
    }
    Ok((format, pcm))
}

/// Sample rates accepted from an input. Outside this, a file is more likely
/// corrupt than real, and resampling it would be absurd.
const MIN_RATE: u32 = 4_000;
const MAX_RATE: u32 = 384_000;

/// Scale from an integer sample of `bits` bits to 16-bit units.
fn int_scale(format: &str, bits: u32) -> Result<f32> {
    if !(1..=32).contains(&bits) {
        return Err(bad(format, format!("{bits}-bit samples")));
    }
    Ok(32768.0 / (1u64 << (bits - 1)) as f32)
}

fn bad(format: &str, e: impl std::fmt::Display) -> Error {
    Error::InvalidAudio(format!("{format}: {e}"))
}

fn decode_wav(data: &[u8]) -> Result<Pcm> {
    let mut reader = hound::WavReader::new(Cursor::new(data)).map_err(|e| bad("WAV", e))?;
    let spec = reader.spec();
    let channels = usize::from(spec.channels);
    if channels == 0 {
        return Err(bad("WAV", "no channels"));
    }
    let samples: Vec<f32> = match spec.sample_format {
        hound::SampleFormat::Float => reader
            .samples::<f32>()
            .map(|s| s.map(|v| v * 32768.0))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| bad("WAV", e))?,
        hound::SampleFormat::Int => {
            let scale = int_scale("WAV", u32::from(spec.bits_per_sample))?;
            reader
                .samples::<i32>()
                .map(|s| s.map(|v| v as f32 * scale))
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| bad("WAV", e))?
        }
    };
    Ok(Pcm::from_interleaved(spec.sample_rate, channels, &samples))
}

fn decode_flac(data: &[u8]) -> Result<Pcm> {
    let mut reader = claxon::FlacReader::new(Cursor::new(data)).map_err(|e| bad("FLAC", e))?;
    let info = reader.streaminfo();
    let channels = info.channels as usize;
    let scale = int_scale("FLAC", info.bits_per_sample)?;
    let samples: Vec<f32> = reader
        .samples()
        .map(|s| s.map(|v| v as f32 * scale))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| bad("FLAC", e))?;
    Ok(Pcm::from_interleaved(info.sample_rate, channels, &samples))
}

/// Vorbis orders channels differently from WAVE; this maps each WAVE-order
/// position to the Vorbis channel that fills it.
fn vorbis_to_wave_order(channels: usize) -> Vec<usize> {
    match channels {
        3 => vec![0, 2, 1],
        5 => vec![0, 2, 1, 3, 4],
        6 => vec![0, 2, 1, 5, 3, 4],
        7 => vec![0, 2, 1, 6, 5, 3, 4],
        8 => vec![0, 2, 1, 7, 5, 6, 3, 4],
        n => (0..n).collect(),
    }
}

fn decode_vorbis(data: &[u8]) -> Result<Pcm> {
    let mut reader = lewton::inside_ogg::OggStreamReader::new(Cursor::new(data))
        .map_err(|e| bad("Ogg Vorbis", e))?;
    let channels = usize::from(reader.ident_hdr.audio_channels);
    let rate = reader.ident_hdr.audio_sample_rate;
    let mut decoded: Vec<Vec<f32>> = vec![Vec::new(); channels];
    while let Some(packet) = reader.read_dec_packet().map_err(|e| bad("Ogg Vorbis", e))? {
        for (c, samples) in packet.into_iter().enumerate().take(channels) {
            decoded[c].extend(samples.into_iter().map(f32::from));
        }
    }
    let order = vorbis_to_wave_order(channels);
    let channels = order
        .iter()
        .map(|&i| std::mem::take(&mut decoded[i]))
        .collect();
    Ok(Pcm {
        sample_rate: rate,
        channels,
    })
}

fn decode_mp3(data: &[u8]) -> Result<Pcm> {
    let mut decoder = nanomp3::Decoder::new();
    let mut buffer = vec![0f32; nanomp3::MAX_SAMPLES_PER_FRAME];
    let mut position = 0;
    let mut layout: Option<(u32, usize)> = None;
    let mut samples = Vec::new();
    while position < data.len() {
        let (consumed, info) = decoder.decode(&data[position..], &mut buffer);
        if consumed == 0 {
            break;
        }
        position += consumed;
        let Some(info) = info else { continue };
        let channels = usize::from(info.channels.num());
        match layout {
            None => layout = Some((info.sample_rate, channels)),
            Some((rate, count)) if rate != info.sample_rate || count != channels => {
                return Err(bad(
                    "MP3",
                    "the sample rate or channel count changes mid-stream",
                ));
            }
            Some(_) => {}
        }
        samples.extend(
            buffer[..info.samples_produced * channels]
                .iter()
                .map(|v| v * 32768.0),
        );
    }
    let Some((rate, channels)) = layout else {
        return Err(bad("MP3", "no MP3 frames found"));
    };
    let mut pcm = Pcm::from_interleaved(rate, channels, &samples);
    if let Some(gapless) = lame_gapless(data) {
        // The tag frame itself decodes as a frame of silence, then come the
        // encoder's delay and the decoder's own; the end carries padding.
        let start = gapless.frame_samples + gapless.delay + MP3_DECODER_DELAY;
        let end = gapless.padding.saturating_sub(MP3_DECODER_DELAY);
        for channel in &mut pcm.channels {
            let keep = channel.len().saturating_sub(end);
            channel.truncate(keep);
            channel.drain(..start.min(keep));
        }
    }
    Ok(pcm)
}

/// Samples an MP3 decoder emits before the first real one, on top of what
/// the encoder records as its own delay.
const MP3_DECODER_DELAY: usize = 529;

/// Gapless-playback information from a LAME header frame.
struct Gapless {
    /// Samples in one frame, which the header frame decodes to as silence.
    frame_samples: usize,
    delay: usize,
    padding: usize,
}

/// Read the encoder delay and padding LAME records in its header frame.
///
/// The header frame is an MP3 frame of silence whose side-information area
/// carries an `Xing` or `Info` tag; after the tag's optional fields comes a
/// nine-byte encoder name and, 21 bytes into that, the delay and padding as
/// two 12-bit numbers.
///
/// Without trimming them a looped MP3 would gain a gap of silence at the
/// seam, which is exactly what SND0 must avoid.
fn lame_gapless(data: &[u8]) -> Option<Gapless> {
    let mut offset = 0;
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let size = data[6..10]
            .iter()
            .fold(0usize, |a, &b| (a << 7) | usize::from(b & 0x7F));
        offset = 10 + size + if data[5] & 0x10 != 0 { 10 } else { 0 };
    }
    let header = data.get(offset..offset + 4)?;
    if header[0] != 0xFF || header[1] & 0xE0 != 0xE0 {
        return None;
    }
    let mpeg1 = header[1] & 0x18 == 0x18;
    let mono = header[3] >> 6 == 3;
    let side_info = match (mpeg1, mono) {
        (true, false) => 32,
        (true, true) | (false, false) => 17,
        (false, true) => 9,
    };
    let crc = if header[1] & 1 == 0 { 2 } else { 0 };
    let xing = offset + 4 + crc + side_info;
    let tag = data.get(xing..xing + 4)?;
    if tag != b"Xing" && tag != b"Info" {
        return None;
    }
    let flags = u32::from_be_bytes(data.get(xing + 4..xing + 8)?.try_into().ok()?);
    let mut lame = xing + 8;
    for (bit, size) in [(1, 4), (2, 4), (4, 100), (8, 4)] {
        if flags & bit != 0 {
            lame += size;
        }
    }
    // LAME writes its name here; ffmpeg's encoder writes "Lavc" in the same
    // structure.
    if !matches!(data.get(lame..lame + 4)?, b"LAME" | b"Lavc" | b"Lavf") {
        return None;
    }
    let b = data.get(lame + 21..lame + 24)?;
    Some(Gapless {
        frame_samples: if mpeg1 { 1152 } else { 576 },
        delay: (usize::from(b[0]) << 4) | usize::from(b[1] >> 4),
        padding: (usize::from(b[1] & 0x0F) << 8) | usize::from(b[2]),
    })
}

fn decode_atrac3(data: &[u8]) -> Result<Pcm> {
    use super::atrac3::decoder::{Layout, decode_all};
    let wave = super::riff::parse(data).map_err(|e| bad("ATRAC3", e))?;
    let fmt = wave.fmt.ok_or_else(|| bad("ATRAC3", "no fmt chunk"))?;
    let frames = wave.data.ok_or_else(|| bad("ATRAC3", "no data chunk"))?;
    if fmt.channels != 2 {
        return Err(bad("ATRAC3", "only stereo ATRAC3 is supported"));
    }
    let block_align = usize::from(fmt.block_align);
    if block_align == 0 || block_align % 2 != 0 {
        return Err(bad("ATRAC3", format!("unusable block align {block_align}")));
    }
    let layout = Layout {
        block_align,
        joint_stereo: fmt.joint_stereo().unwrap_or(block_align == 192),
    };
    let [mut left, mut right] =
        decode_all(frames, layout).map_err(|(i, e)| bad("ATRAC3", format!("frame {i}: {e}")))?;
    // With a fact chunk, only the samples it names are the track: the lead-in
    // before them and any spare frame after are not part of the loop.
    if let Some(fact) = wave.fact {
        let start = (fact.delay as usize).min(left.len());
        let end = start.saturating_add(fact.samples as usize).min(left.len());
        if end > start {
            for channel in [&mut left, &mut right] {
                channel.truncate(end);
                channel.drain(..start);
            }
        }
    }
    Ok(Pcm {
        sample_rate: fmt.sample_rate,
        channels: vec![left, right],
    })
}
