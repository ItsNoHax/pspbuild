//! Constants of the ATRAC3 bitstream.
//!
//! These are properties of the format, fixed by what every decoder expects.
//! See `docs/AUDIO.md` for where each comes from and how it was checked.

/// PCM samples per channel in one frame.
pub const FRAME_SAMPLES: usize = 1024;

/// Spectral lines per QMF band; four bands make up a frame.
pub const BAND_LINES: usize = 256;

/// The six-bit identifier every sound unit starts with.
pub const SOUND_UNIT_ID: u8 = 0x28;

/// In joint stereo the second sound unit has a two-bit identifier instead.
pub const JOINT_UNIT_ID: u8 = 0b11;

/// Edges of the 32 quantisation units ("subbands") over the 1024 lines.
///
/// Narrow at the bottom, where hearing resolves pitch finely, and wide at the
/// top.
pub const SUBBAND_EDGES: [usize; 33] = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 288, 320,
    352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024,
];

/// Largest magnitude each quantiser selector can represent, plus one half.
///
/// A coefficient is coded as `round(c / scale * MAX_QUANT[sel])`, so the
/// integer range of selector `s` is `±floor(MAX_QUANT[s])`.
pub const MAX_QUANT: [f32; 8] = [0.0, 1.5, 2.5, 3.5, 4.5, 7.5, 15.5, 31.5];

/// Largest integer each selector codes.
pub const MAX_LEVEL: [i32; 8] = [0, 1, 2, 3, 4, 7, 15, 31];

/// Bits per value in constant-length coding. Selector 1 codes pairs, four
/// bits per pair.
pub const CLC_BITS: [u32; 8] = [0, 4, 3, 3, 4, 4, 5, 6];

/// Selector 1 in constant-length coding: two bits per value.
pub const CLC_PAIR_VALUES: [i32; 4] = [0, 1, -2, -1];

/// Selector 1 in variable-length coding: each symbol is a pair of values.
pub const VLC_PAIRS: [(i32, i32); 9] = [
    (0, 0),
    (0, 1),
    (0, -1),
    (1, 0),
    (-1, 0),
    (1, 1),
    (1, -1),
    (-1, 1),
    (-1, -1),
];

/// Code lengths of the seven spectral Huffman tables, by symbol.
///
/// The codes themselves are canonical: assigned in order of increasing length,
/// ties broken by symbol index. Each table satisfies Kraft's equality, which
/// the tests check, so no code is wasted and none is ambiguous.
pub const VLC_LENGTHS: [&[u8]; 7] = [
    &[1, 3, 3, 4, 4, 5, 5, 5, 5],
    &[1, 3, 3, 3, 3],
    &[1, 3, 3, 4, 4, 4, 4],
    &[1, 3, 3, 4, 4, 5, 5, 5, 5],
    &[2, 3, 3, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 4, 4],
    &[
        3, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 4, 4,
    ],
    &[
        3, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 4, 4,
    ],
];

/// The value a symbol of selectors 2 to 7 stands for: 0, 1, -1, 2, -2, ...
pub fn vlc_symbol_value(symbol: usize) -> i32 {
    let magnitude = symbol.div_ceil(2) as i32;
    if symbol % 2 == 1 {
        magnitude
    } else {
        -magnitude
    }
}

/// The symbol that codes `value` under selectors 2 to 7.
pub fn vlc_value_symbol(value: i32) -> usize {
    match value {
        0 => 0,
        v if v > 0 => (v * 2 - 1) as usize,
        v => (-v * 2) as usize,
    }
}

/// Scale factor for index `i`: `2^((i - 15) / 3)`, i.e. 2 dB steps.
pub fn scale_factor(index: u8) -> f32 {
    ((f32::from(index) - 15.0) / 3.0).exp2()
}

/// A canonical Huffman code: `(code, length)` per symbol.
pub fn canonical_codes(lengths: &[u8]) -> Vec<(u32, u8)> {
    let mut order: Vec<usize> = (0..lengths.len()).collect();
    order.sort_by_key(|&s| (lengths[s], s));
    let mut codes = vec![(0u32, 0u8); lengths.len()];
    let mut code = 0u32;
    let mut previous = lengths[order[0]];
    for (i, &symbol) in order.iter().enumerate() {
        let length = lengths[symbol];
        if i > 0 {
            code = (code + 1) << (length - previous);
        }
        previous = length;
        codes[symbol] = (code, length);
    }
    codes
}

/// The frame-length window the decoder applies after each inverse MDCT.
///
/// Built from a raised sine `a(n)`, normalised so that it and the encoder's
/// window [`analysis_window`] reconstruct perfectly when overlapped by half.
pub fn synthesis_window() -> [f32; 2 * BAND_LINES] {
    let a = analysis_window();
    let mut w = [0f32; 2 * BAND_LINES];
    for n in 0..BAND_LINES {
        let (x, y) = (f64::from(a[n]), f64::from(a[BAND_LINES - 1 - n]));
        let v = (x / (0.5 * (x * x + y * y))) as f32;
        w[n] = v;
        w[2 * BAND_LINES - 1 - n] = v;
    }
    w
}

/// The encoder's MDCT window: `sin(π((n + ½)/256 − ½)) + 1` over the rising
/// half, mirrored for the falling half.
pub fn analysis_window() -> [f32; 2 * BAND_LINES] {
    let mut w = [0f32; 2 * BAND_LINES];
    for n in 0..BAND_LINES {
        let v = ((((n as f64 + 0.5) / BAND_LINES as f64) - 0.5) * std::f64::consts::PI).sin() + 1.0;
        w[n] = v as f32;
        w[2 * BAND_LINES - 1 - n] = v as f32;
    }
    w
}

/// One half of the 48-tap QMF prototype. The filter is symmetric.
const QMF_HALF: [f64; 24] = [
    -0.000_014_619_07,
    -0.000_092_054_79,
    -0.000_056_157_569,
    0.000_301_172_69,
    0.000_242_251_9,
    -0.000_852_938_97,
    -0.000_520_557_4,
    0.002_034_016_9,
    0.000_783_338_91,
    -0.004_215_386_2,
    -0.000_756_149_88,
    0.007_840_294_4,
    -0.000_061_169_922,
    -0.013_441_62,
    0.002_462_682_1,
    0.021_736_089,
    -0.007_801_671,
    -0.034_090_221,
    0.018_809_49,
    0.054_326_009,
    -0.043_596_379,
    -0.099_384_367,
    0.132_079_09,
    0.464_241_59,
];

/// The full 48-tap QMF window, scaled by two for synthesis.
pub fn qmf_window() -> [f32; 48] {
    let mut w = [0f32; 48];
    for (i, &h) in QMF_HALF.iter().enumerate() {
        w[i] = (h * 2.0) as f32;
        w[47 - i] = (h * 2.0) as f32;
    }
    w
}

/// Joint-stereo matrix coefficients, as `(left, right)` weights per selector,
/// used only while interpolating between two selectors.
pub const MATRIX_COEFFS: [(f32, f32); 4] = [(0.0, 2.0), (2.0, 2.0), (0.0, 0.0), (1.0, 1.0)];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_tables_are_complete_prefix_codes() {
        for (i, lengths) in VLC_LENGTHS.iter().enumerate() {
            // Kraft equality: a complete code, so every bit pattern decodes.
            let kraft: f64 = lengths.iter().map(|&l| 0.5f64.powi(i32::from(l))).sum();
            assert!((kraft - 1.0).abs() < 1e-12, "table {} kraft {kraft}", i + 1);
        }
        assert_eq!(VLC_LENGTHS[0].len(), VLC_PAIRS.len());
        for (sel, lengths) in VLC_LENGTHS.iter().enumerate().skip(1) {
            assert_eq!(lengths.len() as i32, MAX_LEVEL[sel + 1] * 2 + 1);
        }
    }

    #[test]
    fn canonical_codes_match_known_patterns() {
        let codes = canonical_codes(VLC_LENGTHS[4]);
        assert_eq!(codes[0], (0b00, 2));
        assert_eq!(codes[13], (0b1100, 4));
        assert_eq!(codes[7], (0b11100, 5));
        assert_eq!(codes[12], (0b111111, 6));
        let codes = canonical_codes(VLC_LENGTHS[6]);
        assert_eq!(codes[61], (0b0010, 4));
        assert_eq!(codes[60], (0xFF, 8));
    }

    #[test]
    fn symbol_mapping_round_trips() {
        for v in -31..=31 {
            assert_eq!(vlc_symbol_value(vlc_value_symbol(v)), v);
        }
        assert_eq!(vlc_symbol_value(1), 1);
        assert_eq!(vlc_symbol_value(2), -1);
    }

    #[test]
    fn windows_reconstruct_perfectly() {
        let a = analysis_window();
        let s = synthesis_window();
        for n in 0..BAND_LINES {
            let sum = a[n] * s[n] + a[n + BAND_LINES] * s[n + BAND_LINES];
            assert!((sum - 2.0).abs() < 1e-5, "n {n}: {sum}");
        }
    }
}
