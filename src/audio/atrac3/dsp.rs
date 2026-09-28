//! Transforms: the MDCT pair and the two-band QMF.
//!
//! ATRAC3 splits a frame with a tree of two-band QMFs into four bands of 256
//! samples, then codes each band with a 512-point MDCT overlapped by half.

use super::tables::{BAND_LINES, qmf_window};

const N: usize = BAND_LINES;
const HALF: usize = N / 2;

/// Radix-2 complex FFT of fixed size, with precomputed twiddles.
struct Fft {
    size: usize,
    twiddles: Vec<(f64, f64)>,
    bitrev: Vec<usize>,
}

impl Fft {
    fn new(size: usize) -> Self {
        let bits = size.trailing_zeros();
        let bitrev = (0..size)
            .map(|i| i.reverse_bits() >> (usize::BITS - bits))
            .collect();
        let twiddles = (0..size / 2)
            .map(|k| {
                let a = -2.0 * std::f64::consts::PI * k as f64 / size as f64;
                (a.cos(), a.sin())
            })
            .collect();
        Fft {
            size,
            twiddles,
            bitrev,
        }
    }

    fn run(&self, re: &mut [f64], im: &mut [f64]) {
        for i in 0..self.size {
            let j = self.bitrev[i];
            if j > i {
                re.swap(i, j);
                im.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= self.size {
            let step = self.size / len;
            for start in (0..self.size).step_by(len) {
                for k in 0..len / 2 {
                    let (wr, wi) = self.twiddles[k * step];
                    let (a, b) = (start + k, start + k + len / 2);
                    let tr = re[b] * wr - im[b] * wi;
                    let ti = re[b] * wi + im[b] * wr;
                    re[b] = re[a] - tr;
                    im[b] = im[a] - ti;
                    re[a] += tr;
                    im[a] += ti;
                }
            }
            len *= 2;
        }
    }
}

/// A 256-point DCT-IV, `X[k] = Σ x[n] cos(π/N (n + ½)(k + ½))`, computed
/// through a 128-point complex FFT.
pub struct Dct4 {
    fft: Fft,
    pre: Vec<(f64, f64)>,
    post: Vec<(f64, f64)>,
}

impl Dct4 {
    pub fn new() -> Self {
        let pi = std::f64::consts::PI;
        let pre = (0..HALF)
            .map(|n| {
                let a = -pi * n as f64 / N as f64;
                (a.cos(), a.sin())
            })
            .collect();
        let post = (0..HALF)
            .map(|k| {
                let a = -pi * (k as f64 + 0.25) / N as f64;
                (a.cos(), a.sin())
            })
            .collect();
        Dct4 {
            fft: Fft::new(HALF),
            pre,
            post,
        }
    }

    pub fn run(&self, input: &[f32; N], output: &mut [f32; N]) {
        // Pair even samples with reversed odd ones as one complex sequence.
        let mut re = [0f64; HALF];
        let mut im = [0f64; HALF];
        for n in 0..HALF {
            let (a, b) = (f64::from(input[2 * n]), f64::from(input[N - 1 - 2 * n]));
            let (c, s) = self.pre[n];
            re[n] = a * c - b * s;
            im[n] = a * s + b * c;
        }
        self.fft.run(&mut re, &mut im);
        for k in 0..HALF {
            let (c, s) = self.post[k];
            let r = re[k] * c - im[k] * s;
            let i = re[k] * s + im[k] * c;
            output[2 * k] = r as f32;
            output[N - 1 - 2 * k] = -i as f32;
        }
    }
}

impl Default for Dct4 {
    fn default() -> Self {
        Self::new()
    }
}

/// The transforms, built once.
pub fn dct4() -> &'static Dct4 {
    static DCT: std::sync::OnceLock<Dct4> = std::sync::OnceLock::new();
    DCT.get_or_init(Dct4::new)
}

/// Forward MDCT without windowing or scaling:
/// `X[k] = Σ_{n<512} x[n] cos(π/N (n + ½ + N/2)(k + ½))`.
pub fn mdct(input: &[f32; 2 * N], output: &mut [f32; N]) {
    // Fold the four quarters into one DCT-IV input.
    let mut folded = [0f32; N];
    for j in 0..HALF {
        folded[j] = -input[3 * HALF - 1 - j] - input[3 * HALF + j];
    }
    for j in HALF..N {
        folded[j] = input[j - HALF] - input[3 * HALF - 1 - j];
    }
    dct4().run(&folded, output);
}

/// Inverse MDCT without windowing or scaling: the exact transpose of [`mdct`].
pub fn imdct(input: &[f32; N], output: &mut [f32; 2 * N]) {
    let mut v = [0f32; N];
    dct4().run(input, &mut v);
    output[..HALF].copy_from_slice(&v[HALF..]);
    for n in HALF..3 * HALF {
        output[n] = -v[3 * HALF - 1 - n];
    }
    for n in 3 * HALF..2 * N {
        output[n] = -v[n - 3 * HALF];
    }
}

/// Taps of history a synthesis QMF carries between calls.
pub const QMF_DELAY: usize = 46;

/// The streaming two-band synthesis QMF of one tree node.
#[derive(Clone)]
pub struct QmfSynthesis {
    delay: [f32; QMF_DELAY],
}

impl QmfSynthesis {
    pub fn new() -> Self {
        QmfSynthesis {
            delay: [0.0; QMF_DELAY],
        }
    }

    /// Merge a low and a high band of `n` samples each into `2n` samples.
    pub fn run(&mut self, low: &[f32], high: &[f32], output: &mut [f32]) {
        let n = low.len();
        let window = qmf_window();
        let mut t = vec![0f32; QMF_DELAY + 2 * n];
        t[..QMF_DELAY].copy_from_slice(&self.delay);
        for m in 0..n {
            t[QMF_DELAY + 2 * m] = low[m] + high[m];
            t[QMF_DELAY + 2 * m + 1] = low[m] - high[m];
        }
        for j in 0..n {
            let base = 2 * j;
            let (mut even, mut odd) = (0f32, 0f32);
            for i in (0..48).step_by(2) {
                even += t[base + i] * window[i];
                odd += t[base + i + 1] * window[i + 1];
            }
            output[2 * j] = odd;
            output[2 * j + 1] = even;
        }
        self.delay.copy_from_slice(&t[2 * n..2 * n + QMF_DELAY]);
    }
}

impl Default for QmfSynthesis {
    fn default() -> Self {
        Self::new()
    }
}

/// Two-band analysis of a whole periodic signal: the transpose of
/// [`QmfSynthesis`] run over the same signal in steady state.
///
/// Treating the signal as periodic means a looped SND0 has no seam: the
/// filter history at the first sample is the end of the track, exactly as it
/// is when the XMB wraps around.
pub fn qmf_analysis_periodic(signal: &[f32]) -> (Vec<f32>, Vec<f32>) {
    let length = signal.len();
    debug_assert!(length.is_multiple_of(2));
    let window = qmf_window();
    let mut p = vec![0f32; length];
    let wrap = |i: isize| i.rem_euclid(length as isize) as usize;
    for j in 0..length / 2 {
        let base = 2 * j as isize - QMF_DELAY as isize;
        let (x_even, x_odd) = (signal[2 * j], signal[2 * j + 1]);
        for i in (0..48).step_by(2) {
            p[wrap(base + i as isize)] += window[i] * x_odd;
            p[wrap(base + i as isize + 1)] += window[i + 1] * x_even;
        }
    }
    let low = (0..length / 2).map(|m| p[2 * m] + p[2 * m + 1]).collect();
    let high = (0..length / 2).map(|m| p[2 * m] - p[2 * m + 1]).collect();
    (low, high)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u64) -> Vec<f32> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((state >> 40) as f32 / (1u64 << 24) as f32) - 0.5
            })
            .collect()
    }

    #[test]
    fn dct4_matches_its_definition() {
        let x: [f32; N] = noise(N, 1).try_into().unwrap();
        let mut fast = [0f32; N];
        dct4().run(&x, &mut fast);
        for k in [0usize, 1, 17, 128, 254, 255] {
            let slow: f64 = (0..N)
                .map(|n| {
                    f64::from(x[n])
                        * (std::f64::consts::PI / N as f64 * (n as f64 + 0.5) * (k as f64 + 0.5))
                            .cos()
                })
                .sum();
            assert!((f64::from(fast[k]) - slow).abs() < 1e-3, "k {k}");
        }
    }

    #[test]
    fn mdct_matches_its_definition_and_imdct_is_its_transpose() {
        let x: [f32; 2 * N] = noise(2 * N, 2).try_into().unwrap();
        let mut spectrum = [0f32; N];
        mdct(&x, &mut spectrum);
        let kernel = |n: usize, k: usize| {
            (std::f64::consts::PI / N as f64 * (n as f64 + 0.5 + N as f64 / 2.0) * (k as f64 + 0.5))
                .cos()
        };
        for k in [0usize, 3, 100, 255] {
            let slow: f64 = (0..2 * N).map(|n| f64::from(x[n]) * kernel(n, k)).sum();
            assert!((f64::from(spectrum[k]) - slow).abs() < 1e-3, "k {k}");
        }
        let y: [f32; N] = noise(N, 3).try_into().unwrap();
        let mut time = [0f32; 2 * N];
        imdct(&y, &mut time);
        for n in [0usize, 77, 128, 300, 384, 511] {
            let slow: f64 = (0..N).map(|k| f64::from(y[k]) * kernel(n, k)).sum();
            assert!((f64::from(time[n]) - slow).abs() < 1e-3, "n {n}");
        }
    }

    #[test]
    fn qmf_analysis_is_the_transpose_of_synthesis() {
        // <S(l, h), x> == <(l, h), Sᵀ x> in steady state on a periodic signal.
        let n = 64;
        let (low, high) = (noise(n, 4), noise(n, 5));
        let x = noise(2 * n, 6);
        // Run synthesis over two periods so the second is in steady state.
        let mut q = QmfSynthesis::new();
        let mut out = vec![0f32; 2 * n];
        q.run(&low, &high, &mut out);
        q.run(&low, &high, &mut out);
        let lhs: f64 = out.iter().zip(&x).map(|(a, b)| f64::from(a * b)).sum();
        let (al, ah) = qmf_analysis_periodic(&x);
        let rhs: f64 = low
            .iter()
            .zip(&al)
            .chain(high.iter().zip(&ah))
            .map(|(a, b)| f64::from(a * b))
            .sum();
        assert!((lhs - rhs).abs() < 1e-4, "{lhs} vs {rhs}");
    }
}
