//! ATRAC3 encoder for XMB background music: LP4, joint stereo, three bands.
//!
//! The encoder is built around the one rule the XMB is strict about: a sound
//! unit may code at most three of the four QMF bands. Here that is not a
//! check applied afterwards but a property of the design — the analysis never
//! produces a spectrum above [`CODED_LINES`], so there is nothing to code in a
//! fourth band and no way to ask for one.
//!
//! Each frame goes through:
//!
//! ```text
//! L/R -> mid/side -> QMF tree (4 bands) -> MDCT per band
//!     -> per-subband scale factor and quantiser -> bit allocation -> frame
//! ```
//!
//! The analysis is the exact transpose of the decoder's synthesis, run over
//! the track as if it were periodic. Two things follow: the output is aligned
//! with the input (no decoder delay to compensate), and when the XMB loops the
//! track the frame before the first is the last, so the seam is coded as
//! carefully as any other point.

use super::bits::{BitWriter, vlc_tables};
use super::dsp::{mdct, qmf_analysis_periodic};
use super::tables::*;

/// QMF bands coded. The XMB plays nothing if a fourth is present.
pub const CODED_BANDS: usize = 3;

/// Spectral lines those bands cover.
pub const CODED_LINES: usize = CODED_BANDS * BAND_LINES;

/// Quantisation units inside the coded bands.
pub const CODED_SUBBANDS: usize = {
    let mut n = 0;
    while n + 1 < SUBBAND_EDGES.len() && SUBBAND_EDGES[n + 1] <= CODED_LINES {
        n += 1;
    }
    n
};

/// Bytes per LP4 frame, both channels together: 66 kbps.
pub const FRAME_BYTES: usize = 192;

/// Bits in a frame.
const FRAME_BITS: usize = FRAME_BYTES * 8;

/// The two sound units each round up to a whole byte, so leave room for both.
const BIT_BUDGET: usize = FRAME_BITS - 14;

/// Joint-stereo parameters at the head of the side unit: weighting (1 + 3
/// bits) and one two-bit matrix selector per band.
const JOINT_HEADER_BITS: usize = 4 + 4 * 2;

/// Bits every unit spends before its spectrum: id, band count, a zero
/// gain-point count per coded band, a zero tonal count, subband count and
/// coding mode.
const fn unit_overhead(id_bits: usize) -> usize {
    id_bits + 2 + 3 * CODED_BANDS + 5 + 5 + 1
}

/// Scale of the analysis relative to the decoder's synthesis: the MDCT pair
/// gains 256 and each of the two QMF levels gains two.
const ANALYSIS_SCALE: f32 = -1.0 / (256.0 * 4.0);

/// Encode stereo PCM at 44.1 kHz, in 16-bit sample units, to LP4 frames.
///
/// The track is padded with silence to a whole number of frames.
pub fn encode(left: &[f32], right: &[f32]) -> Vec<u8> {
    assert_eq!(left.len(), right.len(), "channels differ in length");
    let frames = left.len().div_ceil(FRAME_SAMPLES).max(1);
    let length = frames * FRAME_SAMPLES;

    // Matrix selector 3 in the decoder is L = M + S, R = M - S.
    let mut mid = vec![0f32; length];
    let mut side = vec![0f32; length];
    for i in 0..left.len() {
        mid[i] = (left[i] + right[i]) * 0.5;
        side[i] = (left[i] - right[i]) * 0.5;
    }
    let spectra = [analyse(&mid, frames), analyse(&side, frames)];

    let mut out = Vec::with_capacity(frames * FRAME_BYTES);
    for f in 0..frames {
        let units = [
            &spectra[0][f * CODED_LINES..(f + 1) * CODED_LINES],
            &spectra[1][f * CODED_LINES..(f + 1) * CODED_LINES],
        ];
        out.extend_from_slice(&encode_frame(units));
    }
    out
}

/// Split one channel into spectra: `frames * CODED_LINES` coefficients.
fn analyse(signal: &[f32], frames: usize) -> Vec<f32> {
    // The decoder's QMF tree: bands (0, 1) form the lower half, and the upper
    // half is merged from (3, 2), inverted.
    let (low, high) = qmf_analysis_periodic(signal);
    let (b0, b1) = qmf_analysis_periodic(&low);
    let (b3, b2) = qmf_analysis_periodic(&high);
    let bands = [b0, b1, b2, b3];
    let window = analysis_window();
    let band_length = frames * BAND_LINES;

    let mut spectra = vec![0f32; frames * CODED_LINES];
    for f in 0..frames {
        for (b, band) in bands.iter().enumerate().take(CODED_BANDS) {
            let mut block = [0f32; 2 * BAND_LINES];
            for (n, sample) in block.iter_mut().enumerate() {
                *sample = band[(f * BAND_LINES + n) % band_length] * window[n];
            }
            let mut coefficients = [0f32; BAND_LINES];
            mdct(&block, &mut coefficients);
            if b % 2 == 1 {
                coefficients.reverse();
            }
            let base = f * CODED_LINES + b * BAND_LINES;
            for (out, c) in spectra[base..base + BAND_LINES]
                .iter_mut()
                .zip(coefficients)
            {
                *out = c * ANALYSIS_SCALE;
            }
        }
    }
    spectra
}

/// One way of coding one subband.
#[derive(Clone, Copy, Default)]
struct Choice {
    /// Quantiser selector; 0 codes nothing.
    selector: u8,
    scale: u8,
    /// Index into [`ROUNDING`].
    rounding: u8,
    /// Bits including the scale factor, under variable- and constant-length
    /// coding.
    bits: [u32; 2],
    /// Squared error left after quantising.
    distortion: f32,
}

/// Rounding offsets tried when quantising. Rounding down a little more than
/// half turns many small levels into zeros, which variable-length coding
/// makes much cheaper than the error it adds.
const ROUNDING: [f32; 2] = [0.5, 0.38];

fn quantise(coefficients: &[f32], choice: &Choice, levels: &mut [i32]) -> f32 {
    let selector = usize::from(choice.selector);
    let step = scale_factor(choice.scale) / MAX_QUANT[selector];
    let limit = MAX_LEVEL[selector];
    let bias = ROUNDING[usize::from(choice.rounding)];
    let mut error = 0f32;
    for (level, &c) in levels.iter_mut().zip(coefficients) {
        let magnitude = ((c.abs() / step) + bias).floor().min(limit as f32) as i32;
        let q = if c < 0.0 { -magnitude } else { magnitude };
        *level = q;
        let e = c - q as f32 * step;
        error += e * e;
    }
    error
}

fn vlc_bits(selector: usize, levels: &[i32]) -> u32 {
    let lengths = VLC_LENGTHS[selector - 1];
    if selector == 1 {
        levels
            .chunks(2)
            .map(|p| u32::from(lengths[pair_symbol(p[0], p[1])]))
            .sum()
    } else {
        levels
            .iter()
            .map(|&q| u32::from(lengths[vlc_value_symbol(q)]))
            .sum()
    }
}

fn clc_bits(selector: usize, count: usize) -> u32 {
    if selector == 1 {
        (count as u32 / 2) * CLC_BITS[1]
    } else {
        count as u32 * CLC_BITS[selector]
    }
}

fn pair_symbol(a: i32, b: i32) -> usize {
    VLC_PAIRS
        .iter()
        .position(|&p| p == (a, b))
        .expect("selector 1 levels are within -1..=1")
}

/// Every way worth considering of coding one subband, as a lower convex hull
/// of (bits, distortion) per coding mode, cheapest first. The first entry
/// always codes nothing.
fn hulls(coefficients: &[f32]) -> [Vec<Choice>; 2] {
    let energy: f32 = coefficients.iter().map(|c| c * c).sum();
    let silent = Choice {
        distortion: energy,
        ..Choice::default()
    };
    let peak = coefficients.iter().fold(0f32, |m, c| m.max(c.abs()));
    if peak == 0.0 {
        return [vec![silent], vec![silent]];
    }
    // Smallest scale factor that holds the peak without clipping.
    let mut ceiling = 0u8;
    while ceiling < 63 && scale_factor(ceiling) < peak {
        ceiling += 1;
    }
    let mut candidates = vec![silent];
    let mut levels = [0i32; 128];
    let levels = &mut levels[..coefficients.len()];
    for selector in 1..8u8 {
        // A slightly smaller scale often wins: clipping the peak costs less
        // than the coarser step spends on everything else.
        for scale in ceiling.saturating_sub(3)..=ceiling.min(62) + 1 {
            for rounding in 0..ROUNDING.len() as u8 {
                let mut choice = Choice {
                    selector,
                    scale,
                    rounding,
                    ..Choice::default()
                };
                choice.distortion = quantise(coefficients, &choice, levels);
                choice.bits = [
                    6 + vlc_bits(usize::from(selector), levels),
                    6 + clc_bits(usize::from(selector), levels.len()),
                ];
                if choice.distortion < energy {
                    candidates.push(choice);
                }
            }
        }
    }
    [0, 1].map(|coding| lower_hull(&candidates, coding))
}

/// The points of `candidates` on the lower convex hull in (bits, distortion).
fn lower_hull(candidates: &[Choice], coding: usize) -> Vec<Choice> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| {
        a.bits[coding]
            .cmp(&b.bits[coding])
            .then(a.distortion.total_cmp(&b.distortion))
    });
    let mut hull: Vec<Choice> = Vec::new();
    for c in sorted {
        if hull.last().is_some_and(|h| c.distortion >= h.distortion) {
            continue;
        }
        while hull.len() >= 2 {
            let (a, b) = (hull[hull.len() - 2], hull[hull.len() - 1]);
            let (ab, ac) = (
                (b.bits[coding] - a.bits[coding]) as f32,
                (c.bits[coding] - a.bits[coding]) as f32,
            );
            // Drop b if it is on or above the line from a to c.
            if (b.distortion - a.distortion) * ac >= (c.distortion - a.distortion) * ab {
                hull.pop();
            } else {
                break;
            }
        }
        hull.push(c);
    }
    hull
}

/// How much each subband's noise matters: the reciprocal of a crude masking
/// threshold built from the energy around it.
fn weights(units: [&[f32]; 2]) -> [f32; CODED_SUBBANDS] {
    let mut energy = [0f32; CODED_SUBBANDS];
    for (i, e) in energy.iter_mut().enumerate() {
        let (first, last) = (SUBBAND_EDGES[i], SUBBAND_EDGES[i + 1]);
        let sum: f32 = units
            .iter()
            .flat_map(|u| &u[first..last])
            .map(|c| c * c)
            .sum();
        *e = sum / (last - first) as f32;
    }
    let mut out = [0f32; CODED_SUBBANDS];
    for i in 0..CODED_SUBBANDS {
        // Energy spreads to neighbouring subbands, falling off with distance.
        let mut spread = energy[i];
        for d in 1..=3 {
            let fall = 0.25f32.powi(d as i32);
            if i >= d {
                spread = spread.max(energy[i - d] * fall);
            }
            if i + d < CODED_SUBBANDS {
                spread = spread.max(energy[i + d] * fall);
            }
        }
        // Noise far below a loud band is inaudible, but not in proportion:
        // compressing the threshold keeps quiet bands from starving.
        out[i] = 1.0 / (spread.powf(MASKING_EXPONENT) + NOISE_FLOOR);
    }
    out
}

/// How strongly the threshold follows the signal: 1 equalises the
/// noise-to-signal ratio across bands, 0 minimises plain squared error.
const MASKING_EXPONENT: f32 = 0.5;

/// Below this the ear hears nothing, whatever the masking.
const NOISE_FLOOR: f32 = 1.0;

/// The choices made for both units of a frame.
struct Allocation {
    picks: [[Choice; CODED_SUBBANDS]; 2],
    clc: [bool; 2],
}

/// Greedy bit allocation: repeatedly make the upgrade that buys the most
/// weighted distortion per bit, until nothing more fits. Each subband moves
/// along its convex hull, so the next point is always its best upgrade.
fn allocate(
    hulls: &[Vec<[Vec<Choice>; 2]>; 2],
    weights: &[f32; CODED_SUBBANDS],
    clc: [bool; 2],
) -> (Allocation, f32) {
    let mut position = [[0usize; CODED_SUBBANDS]; 2];
    let mut coded = [1usize; 2];
    let mut used = JOINT_HEADER_BITS + unit_overhead(6) + unit_overhead(2) + 3 * 2;

    loop {
        let mut best: Option<(f32, usize, usize, usize)> = None;
        for u in 0..2 {
            let coding = usize::from(clc[u]);
            for i in 0..CODED_SUBBANDS {
                let hull = &hulls[u][i][coding];
                let Some(next) = hull.get(position[u][i] + 1) else {
                    continue;
                };
                let current = &hull[position[u][i]];
                let widen = if i >= coded[u] {
                    3 * (i + 1 - coded[u])
                } else {
                    0
                };
                let cost = (next.bits[coding] - current.bits[coding]) as usize + widen;
                if used + cost > BIT_BUDGET {
                    continue;
                }
                let ratio = (current.distortion - next.distortion) * weights[i] / cost as f32;
                if best.is_none_or(|b| ratio > b.0) {
                    best = Some((ratio, u, i, cost));
                }
            }
        }
        let Some((_, u, i, cost)) = best else { break };
        position[u][i] += 1;
        coded[u] = coded[u].max(i + 1);
        used += cost;
    }

    let mut picks = [[Choice::default(); CODED_SUBBANDS]; 2];
    let mut distortion = 0.0;
    for u in 0..2 {
        for i in 0..CODED_SUBBANDS {
            picks[u][i] = hulls[u][i][usize::from(clc[u])][position[u][i]];
            distortion += picks[u][i].distortion * weights[i];
        }
    }
    (Allocation { picks, clc }, distortion)
}

fn encode_frame(units: [&[f32]; 2]) -> [u8; FRAME_BYTES] {
    let hulls = units.map(|unit| {
        (0..CODED_SUBBANDS)
            .map(|i| hulls(&unit[SUBBAND_EDGES[i]..SUBBAND_EDGES[i + 1]]))
            .collect::<Vec<_>>()
    });
    let weights = weights(units);

    // Variable-length coding nearly always wins, but constant-length can for
    // a unit dominated by large levels; try each unit both ways.
    let mut best: Option<(Allocation, f32)> = None;
    for clc in [[false, false], [true, false], [false, true], [true, true]] {
        let candidate = allocate(&hulls, &weights, clc);
        if best.as_ref().is_none_or(|b| candidate.1 < b.1) {
            best = Some(candidate);
        }
    }
    let (allocation, _) = best.expect("four candidates tried");

    let mut mid = BitWriter::new();
    mid.put(u32::from(SOUND_UNIT_ID), 6);
    write_unit(&mut mid, units[0], &allocation.picks[0], allocation.clc[0]);

    let mut side = BitWriter::new();
    side.put(0, 1); // no channel weighting ...
    side.put(7, 3); // ... index 7 means unity
    for _ in 0..4 {
        side.put(3, 2); // matrix selector 3: L = M + S, R = M - S
    }
    side.put(u32::from(JOINT_UNIT_ID), 2);
    write_unit(&mut side, units[1], &allocation.picks[1], allocation.clc[1]);

    let (mid, side) = (mid.into_bytes(), side.into_bytes());
    assert!(
        mid.len() + side.len() <= FRAME_BYTES,
        "allocation overran the frame: {} + {} bytes",
        mid.len(),
        side.len()
    );
    let mut frame = [0u8; FRAME_BYTES];
    frame[..mid.len()].copy_from_slice(&mid);
    for (k, &byte) in side.iter().enumerate() {
        frame[FRAME_BYTES - 1 - k] = byte;
    }
    frame
}

/// Everything in a sound unit after its identifier.
fn write_unit(
    w: &mut BitWriter,
    coefficients: &[f32],
    picks: &[Choice; CODED_SUBBANDS],
    clc: bool,
) {
    w.put((CODED_BANDS - 1) as u32, 2);
    for _ in 0..CODED_BANDS {
        w.put(0, 3); // no gain-control points
    }
    w.put(0, 5); // no tonal components

    let coded = picks
        .iter()
        .rposition(|p| p.selector != 0)
        .map_or(1, |i| i + 1);
    w.put((coded - 1) as u32, 5);
    w.put(u32::from(clc), 1);
    for pick in &picks[..coded] {
        w.put(u32::from(pick.selector), 3);
    }
    for pick in &picks[..coded] {
        if pick.selector != 0 {
            w.put(u32::from(pick.scale), 6);
        }
    }
    let tables = vlc_tables();
    let mut levels = [0i32; 128];
    for (i, pick) in picks.iter().enumerate().take(coded) {
        let s = usize::from(pick.selector);
        if s == 0 {
            continue;
        }
        let (first, last) = (SUBBAND_EDGES[i], SUBBAND_EDGES[i + 1]);
        let levels = &mut levels[..last - first];
        quantise(&coefficients[first..last], pick, levels);
        if s == 1 {
            for p in levels.chunks(2) {
                if clc {
                    let index = |v: i32| {
                        CLC_PAIR_VALUES
                            .iter()
                            .position(|&x| x == v)
                            .expect("in range") as u32
                    };
                    w.put((index(p[0]) << 2) | index(p[1]), 4);
                } else {
                    let (code, length) = tables.code(1, pair_symbol(p[0], p[1]));
                    w.put(code, u32::from(length));
                }
            }
        } else {
            for &q in levels.iter() {
                if clc {
                    w.put_signed(q, CLC_BITS[s]);
                } else {
                    let (code, length) = tables.code(s, vlc_value_symbol(q));
                    w.put(code, u32::from(length));
                }
            }
        }
    }
}
