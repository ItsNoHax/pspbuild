//! ATRAC3 decoder.
//!
//! Written for self-verification: every file pspbuild writes is decoded again
//! before it is accepted, and the validator decodes every frame of a file it
//! inspects. It also decodes Sony's own files, which is how its correctness is
//! tested.

use super::bits::{BitReader, Overrun, vlc_tables};
use super::dsp::{QmfSynthesis, imdct};
use super::tables::*;

/// How the frames of a stream are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Bytes per frame, for both channels together.
    pub block_align: usize,
    /// Joint stereo: one frame holds a mid unit read forwards and a side unit
    /// read backwards from the end. Otherwise each channel has its own unit of
    /// half the frame.
    pub joint_stereo: bool,
}

/// Why a frame could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Overrun> for DecodeError {
    fn from(_: Overrun) -> Self {
        DecodeError("the bitstream runs past the end of its sound unit".into())
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, DecodeError> {
    Err(DecodeError(message.into()))
}

/// Gain-control points for one QMF band.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GainPoints {
    pub count: usize,
    pub levels: [u8; 8],
    pub locations: [u8; 8],
}

/// A parsed sound unit: everything the bitstream says about one channel.
#[derive(Clone)]
pub struct SoundUnit {
    /// Coded QMF bands minus one, as stored.
    pub bands_coded: u8,
    pub gain: [GainPoints; 4],
    pub spectrum: Box<[f32; FRAME_SAMPLES]>,
    /// Tonal components found.
    pub tonal_components: usize,
    /// Bits the unit occupied.
    pub bits_used: usize,
}

/// Read one sound unit.
pub fn read_sound_unit(
    reader: &mut BitReader<'_>,
    joint_side: bool,
) -> Result<SoundUnit, DecodeError> {
    let start = reader.position();
    if joint_side {
        let id = reader.bits(2)?;
        if id != u32::from(JOINT_UNIT_ID) {
            return invalid(format!(
                "the side sound unit starts with {id:#04b}, not {:#04b}",
                JOINT_UNIT_ID
            ));
        }
    } else {
        let id = reader.bits(6)?;
        if id != u32::from(SOUND_UNIT_ID) {
            return invalid(format!(
                "the sound unit starts with id {id:#04X}, not {SOUND_UNIT_ID:#04X}"
            ));
        }
    }
    let bands_coded = reader.bits(2)? as u8;
    let coded = usize::from(bands_coded) + 1;

    let mut gain = [GainPoints::default(); 4];
    for points in gain.iter_mut().take(coded) {
        points.count = reader.bits(3)? as usize;
        for i in 0..points.count {
            points.levels[i] = reader.bits(4)? as u8;
            points.locations[i] = reader.bits(5)? as u8;
            if i > 0 && points.locations[i] <= points.locations[i - 1] {
                return invalid("gain-control locations are not in increasing order");
            }
        }
    }

    let mut spectrum = Box::new([0f32; FRAME_SAMPLES]);
    let tonal = read_tonal_components(reader, coded)?;
    read_spectrum(reader, &mut spectrum)?;
    for component in &tonal {
        for (i, &value) in component.values.iter().enumerate() {
            spectrum[component.position + i] += value;
        }
    }

    Ok(SoundUnit {
        bands_coded,
        gain,
        spectrum,
        tonal_components: tonal.len(),
        bits_used: reader.position() - start,
    })
}

struct TonalComponent {
    position: usize,
    values: Vec<f32>,
}

fn read_tonal_components(
    reader: &mut BitReader<'_>,
    coded_bands: usize,
) -> Result<Vec<TonalComponent>, DecodeError> {
    let mut components = Vec::new();
    let groups = reader.bits(5)?;
    if groups == 0 {
        return Ok(components);
    }
    let mode_selector = reader.bits(2)?;
    if mode_selector == 2 {
        return invalid("tonal coding-mode selector 2 is reserved");
    }
    for _ in 0..groups {
        let mut band_flags = [false; 4];
        for flag in band_flags.iter_mut().take(coded_bands) {
            *flag = reader.bit()? == 1;
        }
        let values_per_component = reader.bits(3)? as usize + 1;
        let selector = reader.bits(3)? as usize;
        if selector <= 1 {
            return invalid(format!("tonal quantiser selector {selector} is reserved"));
        }
        let clc = if mode_selector == 3 {
            reader.bit()? == 1
        } else {
            mode_selector == 1
        };
        // Each band is split into four blocks of 64 lines.
        for block in 0..coded_bands * 4 {
            if !band_flags[block / 4] {
                continue;
            }
            let count = reader.bits(3)?;
            for _ in 0..count {
                let sf = reader.bits(6)? as u8;
                let position = block * 64 + reader.bits(6)? as usize;
                if components.len() >= 64 {
                    return invalid("more than 64 tonal components");
                }
                let length = values_per_component.min(FRAME_SAMPLES - position);
                let mut levels = [0i32; 8];
                read_levels(reader, selector, clc, &mut levels[..length])?;
                let step = scale_factor(sf) / MAX_QUANT[selector];
                components.push(TonalComponent {
                    position,
                    values: levels[..length].iter().map(|&q| q as f32 * step).collect(),
                });
            }
        }
    }
    Ok(components)
}

fn read_spectrum(
    reader: &mut BitReader<'_>,
    spectrum: &mut [f32; FRAME_SAMPLES],
) -> Result<(), DecodeError> {
    let subbands = reader.bits(5)? as usize + 1;
    let clc = reader.bit()? == 1;
    let mut selectors = [0usize; 32];
    for s in selectors.iter_mut().take(subbands) {
        *s = reader.bits(3)? as usize;
    }
    let mut factors = [0u8; 32];
    for i in 0..subbands {
        if selectors[i] != 0 {
            factors[i] = reader.bits(6)? as u8;
        }
    }
    let mut levels = [0i32; 128];
    for i in 0..subbands {
        let selector = selectors[i];
        if selector == 0 {
            continue;
        }
        let (first, last) = (SUBBAND_EDGES[i], SUBBAND_EDGES[i + 1]);
        let levels = &mut levels[..last - first];
        read_levels(reader, selector, clc, levels)?;
        let step = scale_factor(factors[i]) / MAX_QUANT[selector];
        for (line, &q) in spectrum[first..last].iter_mut().zip(levels.iter()) {
            *line = q as f32 * step;
        }
    }
    Ok(())
}

/// Read quantised levels under one selector, in either coding.
fn read_levels(
    reader: &mut BitReader<'_>,
    selector: usize,
    clc: bool,
    out: &mut [i32],
) -> Result<(), DecodeError> {
    let tables = vlc_tables();
    if selector == 1 {
        for pair in out.chunks_mut(2) {
            let (a, b) = if clc {
                let code = reader.bits(4)? as usize;
                (CLC_PAIR_VALUES[code >> 2], CLC_PAIR_VALUES[code & 3])
            } else {
                VLC_PAIRS[tables.read(reader, 1)?]
            };
            pair[0] = a;
            if pair.len() > 1 {
                pair[1] = b;
            }
        }
    } else {
        for value in out.iter_mut() {
            *value = if clc {
                reader.signed(CLC_BITS[selector])?
            } else {
                vlc_symbol_value(tables.read(reader, selector)?)
            };
        }
    }
    Ok(())
}

/// Gain factor of a level code: 4 is unity, each step is 6 dB.
fn gain_of(level: u8) -> f32 {
    (4.0 - f32::from(level)).exp2()
}

/// Per-channel reconstruction state carried between frames.
#[derive(Clone)]
struct ChannelState {
    overlap: [[f32; BAND_LINES]; 4],
    /// The previous frame's gain points, which shape this frame's output.
    gain: [GainPoints; 4],
    qmf: [QmfSynthesis; 3],
}

impl ChannelState {
    fn new() -> Self {
        ChannelState {
            overlap: [[0.0; BAND_LINES]; 4],
            gain: [GainPoints::default(); 4],
            qmf: [
                QmfSynthesis::new(),
                QmfSynthesis::new(),
                QmfSynthesis::new(),
            ],
        }
    }

    /// Inverse MDCT, gain compensation and overlap, into four band signals.
    fn bands(
        &mut self,
        unit: &SoundUnit,
        window: &[f32; 2 * BAND_LINES],
    ) -> [[f32; BAND_LINES]; 4] {
        let mut out = [[0f32; BAND_LINES]; 4];
        for (band, signal) in out.iter_mut().enumerate() {
            let mut spectrum = [0f32; BAND_LINES];
            spectrum.copy_from_slice(&unit.spectrum[band * BAND_LINES..(band + 1) * BAND_LINES]);
            if band % 2 == 1 {
                // Odd QMF bands arrive spectrally inverted.
                spectrum.reverse();
            }
            let mut time = [0f32; 2 * BAND_LINES];
            imdct(&spectrum, &mut time);
            for (t, w) in time.iter_mut().zip(window) {
                *t *= w * IMDCT_SCALE;
            }

            let next = unit.gain[band];
            let rescale = if next.count > 0 {
                gain_of(next.levels[0])
            } else {
                1.0
            };
            let envelope = gain_envelope(&self.gain[band]);
            for (n, sample) in signal.iter_mut().enumerate() {
                *sample = (time[n] * rescale + self.overlap[band][n]) * envelope[n];
            }
            self.overlap[band].copy_from_slice(&time[BAND_LINES..]);
            self.gain[band] = next;
        }
        out
    }

    /// Merge four band signals into 1024 PCM samples.
    fn synthesise(&mut self, bands: &[[f32; BAND_LINES]; 4], out: &mut [f32; FRAME_SAMPLES]) {
        let mut low = [0f32; 2 * BAND_LINES];
        let mut high = [0f32; 2 * BAND_LINES];
        self.qmf[0].run(&bands[0], &bands[1], &mut low);
        // The upper pair is itself inverted, so its highest band comes first.
        self.qmf[1].run(&bands[3], &bands[2], &mut high);
        self.qmf[2].run(&low, &high, out);
    }
}

/// Output scale of the windowed inverse MDCT, in 16-bit sample units. The
/// sign is the format's: with a positive scale every sample comes out inverted.
const IMDCT_SCALE: f32 = -1.0;

/// Gain applied across the 256 samples of a band, from its points.
///
/// Each point holds a level up to its location (in units of eight samples),
/// then glides geometrically over eight samples to the next point's level;
/// after the last point the level is unity.
fn gain_envelope(points: &GainPoints) -> [f32; BAND_LINES] {
    let mut envelope = [1f32; BAND_LINES];
    let mut position = 0usize;
    for i in 0..points.count {
        let level = points.levels[i];
        let next = if i + 1 < points.count {
            points.levels[i + 1]
        } else {
            4
        };
        let edge = usize::from(points.locations[i]) * 8;
        let mut value = gain_of(level);
        while position < edge {
            envelope[position] = value;
            position += 1;
        }
        let step = ((f32::from(level) - f32::from(next)) / 8.0).exp2();
        for _ in 0..8 {
            if position >= BAND_LINES {
                break;
            }
            envelope[position] = value;
            value *= step;
            position += 1;
        }
    }
    envelope
}

/// A streaming ATRAC3 decoder for one stereo stream.
pub struct Decoder {
    layout: Layout,
    channels: [ChannelState; 2],
    window: [f32; 2 * BAND_LINES],
    /// Joint-stereo matrix selectors per band: previous, current, next.
    matrix: [[u8; 4]; 3],
    /// Joint-stereo weighting: (flag, index) for the previous and current
    /// frame and the one just read.
    weighting: [(bool, u8); 3],
}

/// The per-frame facts the validator reports on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSummary {
    /// Stored band count (coded bands minus one) of each sound unit.
    pub bands_coded: [u8; 2],
}

impl Decoder {
    pub fn new(layout: Layout) -> Self {
        Decoder {
            layout,
            channels: [ChannelState::new(), ChannelState::new()],
            window: synthesis_window(),
            matrix: [[3; 4]; 3],
            weighting: [(false, 7); 3],
        }
    }

    /// Decode one frame into 1024 samples per channel, left then right.
    pub fn decode(
        &mut self,
        frame: &[u8],
        out: &mut [[f32; FRAME_SAMPLES]; 2],
    ) -> Result<FrameSummary, DecodeError> {
        if frame.len() != self.layout.block_align {
            return invalid(format!(
                "frame is {} bytes, expected {}",
                frame.len(),
                self.layout.block_align
            ));
        }
        if self.layout.joint_stereo {
            self.decode_joint(frame, out)
        } else {
            let half = frame.len() / 2;
            let mut bands_coded = [0u8; 2];
            for ch in 0..2 {
                let unit = read_sound_unit(
                    &mut BitReader::new(&frame[ch * half..(ch + 1) * half]),
                    false,
                )?;
                bands_coded[ch] = unit.bands_coded;
                let bands = self.channels[ch].bands(&unit, &self.window);
                self.channels[ch].synthesise(&bands, &mut out[ch]);
            }
            Ok(FrameSummary { bands_coded })
        }
    }

    fn decode_joint(
        &mut self,
        frame: &[u8],
        out: &mut [[f32; FRAME_SAMPLES]; 2],
    ) -> Result<FrameSummary, DecodeError> {
        let mid = read_sound_unit(&mut BitReader::new(frame), false)?;

        // The side unit is stored byte-reversed from the end of the frame,
        // after any 0xF8 padding.
        let mut reversed: Vec<u8> = frame.iter().rev().copied().collect();
        let skip = reversed.iter().take_while(|&&b| b == 0xF8).count();
        if skip == reversed.len() {
            return invalid("the side sound unit is missing");
        }
        reversed.drain(..skip);
        let mut reader = BitReader::new(&reversed);

        self.weighting[0] = self.weighting[1];
        self.weighting[1] = self.weighting[2];
        self.weighting[2] = (reader.bit()? == 1, reader.bits(3)? as u8);
        self.matrix[0] = self.matrix[1];
        self.matrix[1] = self.matrix[2];
        for band in 0..4 {
            self.matrix[2][band] = reader.bits(2)? as u8;
        }
        let side = read_sound_unit(&mut reader, true)?;

        let mut m = self.channels[0].bands(&mid, &self.window);
        let mut s = self.channels[1].bands(&side, &self.window);
        self.unmatrix(&mut m, &mut s);
        self.unweight(&mut m, &mut s);
        self.channels[0].synthesise(&m, &mut out[0]);
        self.channels[1].synthesise(&s, &mut out[1]);
        Ok(FrameSummary {
            bands_coded: [mid.bands_coded, side.bands_coded],
        })
    }

    /// Turn mid/side band signals into left/right.
    fn unmatrix(&self, a: &mut [[f32; BAND_LINES]; 4], b: &mut [[f32; BAND_LINES]; 4]) {
        for band in 0..4 {
            let (from, to) = (self.matrix[0][band], self.matrix[1][band]);
            let mut start = 0;
            if from != to {
                // Crossfade the matrix over the first eight samples.
                let (fl, fr) = MATRIX_COEFFS[usize::from(from)];
                let (tl, tr) = MATRIX_COEFFS[usize::from(to)];
                for n in 0..8 {
                    let t = n as f32 / 8.0;
                    let (x, y) = (a[band][n], b[band][n]);
                    let left = x * (fl + t * (tl - fl)) + y * (fr + t * (tr - fr));
                    a[band][n] = left;
                    b[band][n] = x * 2.0 - left;
                }
                start = 8;
            }
            for n in start..BAND_LINES {
                let (x, y) = (a[band][n], b[band][n]);
                let (left, right) = match to {
                    0 => (y * 2.0, (x - y) * 2.0),
                    1 => ((x + y) * 2.0, (x - y) * -2.0),
                    _ => (x + y, x - y),
                };
                a[band][n] = left;
                b[band][n] = right;
            }
        }
    }

    /// Apply the joint-stereo channel weights to the upper three bands.
    fn unweight(&self, a: &mut [[f32; BAND_LINES]; 4], b: &mut [[f32; BAND_LINES]; 4]) {
        let (before, now) = (self.weighting[0], self.weighting[1]);
        if before.1 == 7 && now.1 == 7 {
            return;
        }
        let weights = |(swap, index): (bool, u8)| {
            if index == 7 {
                (1.0, 1.0)
            } else {
                let l = f32::from(index) / 7.0;
                let r = (2.0 - l * l).sqrt();
                if swap { (r, l) } else { (l, r) }
            }
        };
        let (bl, br) = weights(before);
        let (nl, nr) = weights(now);
        for band in 1..4 {
            for n in 0..BAND_LINES {
                let t = (n as f32 / 8.0).min(1.0);
                a[band][n] *= bl + t * (nl - bl);
                b[band][n] *= br + t * (nr - br);
            }
        }
    }
}

/// The stored band count (coded bands minus one) of each sound unit in a
/// frame, read from the unit headers alone.
///
/// This does not depend on the rest of the frame being valid, so a frame
/// that codes four bands is recognised as such even if it is otherwise
/// garbage.
pub fn unit_bands(frame: &[u8], layout: Layout) -> Result<[u8; 2], DecodeError> {
    let first = *frame
        .first()
        .ok_or_else(|| DecodeError("the frame is empty".into()))?;
    if first >> 2 != SOUND_UNIT_ID {
        return invalid(format!(
            "the sound unit starts with id {:#04X}, not {SOUND_UNIT_ID:#04X}",
            first >> 2
        ));
    }
    let second = if layout.joint_stereo {
        let tail: Vec<u8> = frame
            .iter()
            .rev()
            .skip_while(|&&b| b == 0xF8)
            .take(2)
            .copied()
            .collect();
        let mut reader = BitReader::new(&tail);
        reader.bits(JOINT_HEADER_BITS)?;
        let id = reader.bits(2)?;
        if id != u32::from(JOINT_UNIT_ID) {
            return invalid(format!(
                "the side sound unit starts with {id:#04b}, not {JOINT_UNIT_ID:#04b}"
            ));
        }
        reader.bits(2)? as u8
    } else {
        let byte = frame[frame.len() / 2];
        if byte >> 2 != SOUND_UNIT_ID {
            return invalid(format!(
                "the right channel's sound unit starts with id {:#04X}, not {SOUND_UNIT_ID:#04X}",
                byte >> 2
            ));
        }
        byte & 3
    };
    Ok([first & 3, second])
}

/// Bits of joint-stereo weighting and matrix parameters before the side
/// unit's identifier.
const JOINT_HEADER_BITS: u32 = 12;

/// Decode a whole stream of frames to interleaved-free stereo PCM.
pub fn decode_all(data: &[u8], layout: Layout) -> Result<[Vec<f32>; 2], (usize, DecodeError)> {
    let mut decoder = Decoder::new(layout);
    let frames = data.len() / layout.block_align;
    let mut left = Vec::with_capacity(frames * FRAME_SAMPLES);
    let mut right = Vec::with_capacity(frames * FRAME_SAMPLES);
    let mut out = [[0f32; FRAME_SAMPLES]; 2];
    for (i, frame) in data.chunks_exact(layout.block_align).enumerate() {
        decoder.decode(frame, &mut out).map_err(|e| (i, e))?;
        left.extend_from_slice(&out[0]);
        right.extend_from_slice(&out[1]);
    }
    Ok([left, right])
}
