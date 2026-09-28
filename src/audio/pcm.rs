//! PCM conditioning: channel layout, trimming, resampling, low-pass.
//!
//! Samples are `f32` in 16-bit units, so full scale is ±32768.

/// Decoded audio, one vector per channel.
#[derive(Debug, Clone, PartialEq)]
pub struct Pcm {
    pub sample_rate: u32,
    pub channels: Vec<Vec<f32>>,
}

impl Pcm {
    /// Samples per channel.
    pub fn len(&self) -> usize {
        self.channels.first().map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn seconds(&self) -> f64 {
        self.len() as f64 / f64::from(self.sample_rate)
    }

    /// Build from interleaved samples.
    pub fn from_interleaved(sample_rate: u32, channels: usize, samples: &[f32]) -> Pcm {
        let mut out = vec![Vec::with_capacity(samples.len() / channels.max(1)); channels];
        for frame in samples.chunks_exact(channels) {
            for (c, &s) in frame.iter().enumerate() {
                out[c].push(s);
            }
        }
        Pcm {
            sample_rate,
            channels: out,
        }
    }
}

/// Reduce or widen to two channels.
///
/// Mono is duplicated. More than two channels are downmixed assuming the WAVE
/// order (front left, front right, centre, LFE, back left, back right, side
/// left, side right): centre and surrounds fold in at -3 dB, LFE is dropped,
/// and the result is scaled so it cannot clip where the inputs did not.
pub fn to_stereo(pcm: Pcm) -> Pcm {
    let rate = pcm.sample_rate;
    match pcm.channels.len() {
        0 => Pcm {
            sample_rate: rate,
            channels: vec![Vec::new(), Vec::new()],
        },
        1 => {
            let mono = pcm.channels.into_iter().next().expect("one channel");
            Pcm {
                sample_rate: rate,
                channels: vec![mono.clone(), mono],
            }
        }
        2 => pcm,
        n => {
            const H: f32 = std::f32::consts::FRAC_1_SQRT_2;
            // (weight into left, weight into right) per input channel.
            // Quad has no centre; from 5.1 up, the fourth channel is LFE.
            let has_centre = n != 4;
            let surround_start = match n {
                4 => 2,
                3 | 5 => 3,
                _ => 4,
            };
            let map: Vec<(f32, f32)> = (0..n)
                .map(|c| match c {
                    0 => (1.0, 0.0),
                    1 => (0.0, 1.0),
                    2 if has_centre => (H, H),
                    c if c < surround_start => (0.0, 0.0),
                    c if (c - surround_start) % 2 == 0 => (H, 0.0),
                    _ => (0.0, H),
                })
                .collect();
            let left_total: f32 = map.iter().map(|m| m.0).sum();
            let right_total: f32 = map.iter().map(|m| m.1).sum();
            let len = pcm.channels[0].len();
            let mut left = vec![0f32; len];
            let mut right = vec![0f32; len];
            for (channel, &(wl, wr)) in pcm.channels.iter().zip(&map) {
                for i in 0..len {
                    left[i] += channel[i] * wl / left_total;
                    right[i] += channel[i] * wr / right_total;
                }
            }
            Pcm {
                sample_rate: rate,
                channels: vec![left, right],
            }
        }
    }
}

/// Keep `duration` seconds starting at `start`.
pub fn trim(pcm: &mut Pcm, start: f64, duration: Option<f64>) {
    let rate = f64::from(pcm.sample_rate);
    let len = pcm.len();
    let first = ((start * rate).round() as usize).min(len);
    let last = duration.map_or(len, |d| (first + (d * rate).round() as usize).min(len));
    for channel in &mut pcm.channels {
        channel.truncate(last);
        channel.drain(..first);
    }
}

/// Zeroth-order modified Bessel function, for the Kaiser window.
fn bessel_i0(x: f64) -> f64 {
    let mut sum = 1.0;
    let mut term = 1.0;
    let half = x / 2.0;
    for k in 1..50 {
        term *= (half / k as f64).powi(2);
        sum += term;
        if term < sum * 1e-17 {
            break;
        }
    }
    sum
}

fn kaiser(x: f64, beta: f64) -> f64 {
    if x.abs() >= 1.0 {
        0.0
    } else {
        bessel_i0(beta * (1.0 - x * x).sqrt()) / bessel_i0(beta)
    }
}

fn sinc(x: f64) -> f64 {
    if x.abs() < 1e-12 {
        1.0
    } else {
        let p = std::f64::consts::PI * x;
        p.sin() / p
    }
}

/// Band-limited resampling with a Kaiser-windowed sinc.
///
/// The passband runs to 19 kHz or 90% of the lower Nyquist rate, whichever
/// is lower, with 90 dB rejection beyond the lower Nyquist rate. The kernel is
/// tabulated finely and interpolated, which keeps the error far below the
/// 16-bit floor. The signal is treated as periodic, like the encoder treats
/// it, so a looped track stays seamless.
pub fn resample(pcm: &Pcm, rate: u32) -> Pcm {
    if pcm.sample_rate == rate || pcm.is_empty() {
        return Pcm {
            sample_rate: rate,
            channels: pcm.channels.clone(),
        };
    }
    let from = f64::from(pcm.sample_rate);
    let to = f64::from(rate);
    let nyquist = from.min(to) / 2.0;
    let pass = (nyquist * 0.9).min(19_000.0);
    // Cutoff and transition as fractions of the input rate.
    let cutoff = (pass + nyquist) / 2.0 / from;
    let transition = (nyquist - pass) / from;
    let beta = 8.96;
    // Half-length of the kernel in input samples, from Kaiser's estimate.
    let half = ((90.0 - 8.0) / (2.285 * 2.0 * std::f64::consts::PI * transition) / 2.0).ceil()
        as usize
        + 1;

    const STEPS: usize = 512;
    let table: Vec<f64> = (0..=half * STEPS + 1)
        .map(|i| {
            let x = i as f64 / STEPS as f64;
            2.0 * cutoff * sinc(2.0 * cutoff * x) * kaiser(x / half as f64, beta)
        })
        .collect();
    let kernel = |x: f64| -> f64 {
        let p = x.abs() * STEPS as f64;
        let i = p as usize;
        if i + 1 >= table.len() {
            return 0.0;
        }
        let f = p - i as f64;
        table[i] * (1.0 - f) + table[i + 1] * f
    };

    let len = pcm.len();
    let out_len = ((len as f64) * to / from).round().max(1.0) as usize;
    let ratio = from / to;
    let channels = pcm
        .channels
        .iter()
        .map(|channel| {
            (0..out_len)
                .map(|k| {
                    let t = k as f64 * ratio;
                    let centre = t.floor() as isize;
                    let mut acc = 0.0;
                    for j in centre - half as isize + 1..=centre + half as isize {
                        let sample = channel[j.rem_euclid(len as isize) as usize];
                        acc += f64::from(sample) * kernel(t - j as f64);
                    }
                    acc as f32
                })
                .collect()
        })
        .collect();
    Pcm {
        sample_rate: rate,
        channels,
    }
}

/// Where the low-pass starts to cut, in Hz.
///
/// The top QMF band starts at 44100 / 8 × 3 = 16537.5 Hz and is never coded,
/// so anything above it is lost anyway. Filtering first keeps what is left of
/// it from folding back into the band below through the QMF's transition.
pub const LOWPASS_PASS_HZ: f64 = 15_500.0;

/// Where the low-pass reaches full rejection, in Hz.
pub const LOWPASS_STOP_HZ: f64 = 16_500.0;

/// Linear-phase FIR low-pass, applied as a periodic convolution so the loop
/// point sees the same filter as every other sample.
pub fn lowpass(pcm: &mut Pcm) {
    let rate = f64::from(pcm.sample_rate);
    let cutoff = (LOWPASS_PASS_HZ + LOWPASS_STOP_HZ) / 2.0 / rate;
    let transition = (LOWPASS_STOP_HZ - LOWPASS_PASS_HZ) / rate;
    let beta = 7.86; // 80 dB
    let half =
        ((80.0 - 8.0) / (2.285 * 2.0 * std::f64::consts::PI * transition) / 2.0).ceil() as usize;
    let taps: Vec<f32> = (0..=half)
        .map(|i| {
            let x = i as f64;
            (2.0 * cutoff * sinc(2.0 * cutoff * x) * kaiser(x / (half as f64 + 1.0), beta)) as f32
        })
        .collect();
    for channel in &mut pcm.channels {
        let len = channel.len();
        if len == 0 {
            continue;
        }
        // Extend periodically on both sides so the inner loop needs no wrap.
        let padded: Vec<f32> = (0..len + 2 * half)
            .map(|i| channel[(i + len * (half / len + 1) - half) % len])
            .collect();
        for (i, out) in channel.iter_mut().enumerate() {
            let c = i + half;
            let mut acc = taps[0] * padded[c];
            for (k, &tap) in taps.iter().enumerate().skip(1) {
                acc += tap * (padded[c - k] + padded[c + k]);
            }
            *out = acc;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(rate: u32, hz: f64, seconds: f64, amplitude: f32) -> Vec<f32> {
        let n = (f64::from(rate) * seconds) as usize;
        (0..n)
            .map(|i| {
                amplitude
                    * (2.0 * std::f64::consts::PI * hz * i as f64 / f64::from(rate)).sin() as f32
            })
            .collect()
    }

    fn rms(x: &[f32]) -> f64 {
        (x.iter().map(|&v| f64::from(v).powi(2)).sum::<f64>() / x.len() as f64).sqrt()
    }

    #[test]
    fn mono_is_duplicated_and_surround_is_folded_down() {
        let mono = Pcm {
            sample_rate: 8000,
            channels: vec![vec![1.0, 2.0]],
        };
        let stereo = to_stereo(mono);
        assert_eq!(stereo.channels, vec![vec![1.0, 2.0], vec![1.0, 2.0]]);

        // 5.1 of a constant: every output stays within the input's range.
        let surround = Pcm {
            sample_rate: 8000,
            channels: vec![vec![1000.0; 4]; 6],
        };
        let folded = to_stereo(surround);
        assert_eq!(folded.channels.len(), 2);
        for &v in &folded.channels[0] {
            assert!(v <= 1000.0 + 1e-3 && v > 700.0, "{v}");
        }
    }

    #[test]
    fn trim_cuts_where_asked() {
        let mut pcm = Pcm {
            sample_rate: 10,
            channels: vec![(0..100).map(|i| i as f32).collect(); 2],
        };
        trim(&mut pcm, 1.0, Some(2.0));
        assert_eq!(pcm.len(), 20);
        assert_eq!(pcm.channels[0][0], 10.0);
        assert_eq!(pcm.channels[1][19], 29.0);
    }

    #[test]
    fn resampling_keeps_a_tone_and_its_level() {
        let input = Pcm {
            sample_rate: 48_000,
            channels: vec![tone(48_000, 1000.0, 1.0, 10_000.0)],
        };
        let out = resample(&input, 44_100);
        assert_eq!(out.len(), 44_100);
        let expected = tone(44_100, 1000.0, 1.0, 10_000.0);
        let err: Vec<f32> = out.channels[0]
            .iter()
            .zip(&expected)
            .map(|(a, b)| a - b)
            .collect();
        let snr = 20.0 * (rms(&expected) / rms(&err)).log10();
        assert!(snr > 80.0, "resampled tone SNR {snr:.1} dB");
    }

    #[test]
    fn resampling_rejects_what_would_alias() {
        // 23 kHz at 48 kHz has no place below 22.05 kHz.
        let input = Pcm {
            sample_rate: 48_000,
            channels: vec![tone(48_000, 23_000.0, 0.5, 10_000.0)],
        };
        let out = resample(&input, 44_100);
        let level = 20.0 * (rms(&out.channels[0]) / (10_000.0 / 2f64.sqrt())).log10();
        assert!(level < -80.0, "aliased tone at {level:.1} dB");
    }

    #[test]
    fn lowpass_keeps_the_passband_and_removes_the_top_band() {
        for (hz, keep) in [
            (1000.0, true),
            (15_000.0, true),
            (17_000.0, false),
            (20_000.0, false),
        ] {
            let mut pcm = Pcm {
                sample_rate: 44_100,
                channels: vec![tone(44_100, hz, 0.5, 10_000.0)],
            };
            let before = rms(&pcm.channels[0]);
            lowpass(&mut pcm);
            let gain = 20.0 * (rms(&pcm.channels[0]) / before).log10();
            if keep {
                assert!(gain.abs() < 0.1, "{hz} Hz changed by {gain:.2} dB");
            } else {
                assert!(gain < -70.0, "{hz} Hz only {gain:.1} dB down");
            }
        }
    }
}
