# SND0.AT3: XMB background music

`SND0.AT3` is the music the XMB plays while a game's icon is selected. It
loops only if the file carries a loop point in the form §2.1 describes. This document describes what the XMB accepts, why each rule exists,
and how pspbuild meets them. Where a claim rests on a real file or on
hardware, that is stated.

> **Only playback on a PSP proves an SND0 works.** Everything below is
> offline evidence. A file that ffmpeg decodes, whose header matches a retail
> file byte for byte and which `sceAtrac` accepts can still be silent in the
> XMB. The four-band file described in §3.2 passed all three.

## 1. What pspbuild does

```text
WAV / FLAC / Ogg Vorbis / MP3 / ATRAC3
  -> PCM -> stereo -> trim -> 44.1 kHz -> low-pass 15.5 kHz
  -> ATRAC3 LP4, joint stereo, three QMF bands
  -> RIFF/WAVE (fmt, fact, smpl, data) with a loop point -> strict validation
  -> SND0.AT3
```

```sh
pspbuild audio snd0 theme.flac -o SND0.AT3      # convert
pspbuild audio inspect SND0.AT3                  # explain and validate
pspbuild build-mg game.prx --snd0 theme.mp3      # convert while building
```

`--snd0` in `build-mg` accepts an existing `SND0.AT3` too. If it passes the
validator (§5) it is used byte for byte. An ATRAC3 file the XMB would reject,
such as one that codes four bands, is decoded and encoded afresh, and
`-v` says why. `build-eg` takes no `--snd0`: an EG build carries whatever
`SND0.AT3` the UMD has.

pspbuild will not write an encoded file that fails its own strict
validation.

## 2. The container

An SND0 is a RIFF/WAVE file. pspbuild writes four chunks: `fmt `, `fact`,
`smpl`, then `data`.

| offset | bytes | field | value |
| --- | --- | --- | --- |
| 0x00 | 4 | `RIFF` | |
| 0x04 | 4 | RIFF size | file size - 8 |
| 0x08 | 4 | `WAVE` | |
| 0x0C | 8 | `fmt ` chunk header | size 32 |
| 0x14 | 2 | format tag | `0x0270`, ATRAC3 |
| 0x16 | 2 | channels | 2 |
| 0x18 | 4 | sample rate | 44100 |
| 0x1C | 4 | byte rate | 8268 (66144 bps) |
| 0x20 | 2 | block align | 192 |
| 0x22 | 2 | bits per sample | 0 |
| 0x24 | 2 | extension size | 14 |
| 0x26 | 14 | ATRAC3 extension | `01 00 00 10 00 00 01 00 01 00 01 00 00 00` |
| 0x34 | 8 | `fact` chunk header | size 8 |
| 0x3C | 4 | samples | length of the loop, *L* |
| 0x40 | 4 | delay | 1024 |
| 0x44 | 8 | `smpl` chunk header | size 60 |
| 0x4C | 60 | `smpl` body | one forward loop, samples 1024 to 1024 + *L* - 1, forever |
| 0x88 | 8 | `data` chunk header | size = frames x 192 |
| 0x90 | | frames | |

The `fmt ` chunk is byte for byte that of a known-good file, which plays in
the XMB of a PSP Slim on 6.61 with ARK. Its extension reads as seven
little-endian words: 1, a 32-bit 0x1000, joint stereo (1), joint stereo
again (1), 1 and 0. Sony's own LP2 file has the same words, except that both
joint-stereo words are 0.

The `smpl` body is laid out as in Sony's own SND0: manufacturer and product
0, sample period 22676 ns, MIDI unity note 60, no pitch fraction or SMPTE
offset, one loop, and 24 in the sampler-data field. The loop record is cue
point 0, type 0 (forward), start, end, fraction 0, play count 0 (forever).

### 2.1 Looping needs `fact` and `smpl` together

These three layouts were played in the XMB of a PSP Slim (6.61, ARK), each
with the same 55 s of music:

| layout | result |
| --- | --- |
| `fmt `, `data` only | plays once, then stops |
| `smpl` loop over samples 0 to *N* - 1, no `fact` | **plays nothing** |
| `fact` = (*L*, 1024), `smpl` loop 1024 to 1024 + *L* - 1 | **loops cleanly** |

Sony's retail SND0 has the third form, with a delay of 1143: `fact` =
(1075012, 1143) and a loop from 1143 to 1076154. The delay counts decoded
samples before the first sample of the track; the loop starts there and ends
on the last one. A `fact` count of exactly frames x 1024 is wrong: it leaves no
room for the delay.

pspbuild writes the third form with a delay of one frame (1024 samples):

- The first frame is the lead-in. It is decoded from an empty decoder, and
  it is exactly the part the loop never returns to.
- The stream holds the track as a cycle: stream sample *n* is track sample
  *n* - 1024, wrapped around. So the lead-in is the end of the track, and the
  audio after the loop end is its start. Wherever the decoder crosses the
  seam, the samples around it are the ones that belong there.
- One spare frame follows the frame holding the loop end, so the decoder has
  what comes after it.

**Other rules, and why:**

- **RIFF/WAVE only.** OMA and RealMedia containers hold the same codec, but
  they do not play as SND0.
- **44.1 kHz stereo.** The XMB has no resampler for SND0, and SND0 is never
  mono.

## 3. The codec

ATRAC3 codes 1024 samples per channel per frame. A tree of two-band QMF
filters splits each frame into four bands of 256 samples. Each band goes
through a 512-point MDCT that overlaps the next block by half. The 1024
spectral lines are grouped into 32 quantisation units, 8 lines wide at the
bottom and 128 at the top. Each unit carries a scale factor (2 dB steps) and
a quantiser selector (0 to 7). The levels are Huffman coded or fixed-length
coded, chosen per unit.

### 3.1 Bitrate: LP4, joint stereo

pspbuild writes **LP4**: 66 kbps, 192-byte frames, joint stereo. In joint
stereo one frame holds two sound units. The mid unit is read forwards from
byte 0. The side unit is stored byte-reversed from the last byte, behind
twelve bits of stereo parameters. pspbuild writes them as "no weighting"
(`0`, `111`) and matrix selector 3 in all four bands, i.e. L = M + S and
R = M - S. That makes the last byte of every frame `0x7F`, as in the known-good
file.

**LP2 (132 kbps) is a warning, not an error.** The evidence conflicts. Homebrew
LP2 files have been seen not to play. But the only retail SND0 at hand, shared
by three Hatsune Miku *Dreamy Theater* connection apps (NPJH90121, NPJH90213,
NPJH90292), is LP2: 384-byte frames, two independent channels, with `fact`
and `smpl` chunks. Sony shipped it for the XMB. So LP2 itself cannot be what
breaks playback. The four-band rule below is the likelier explanation: an
encoder that is not written for the XMB has no reason to leave the fourth band
empty, and at 132 kbps it has the bits to fill it. pspbuild still writes LP4,
because LP4 is what has been proven on hardware.

### 3.2 Three bands, never four

Every sound unit starts with a six-bit id (`0x28`) and a two-bit count of
coded QMF bands minus one. So the first byte of a frame is `0xA0` to `0xA3`.

- **A frame that codes four bands (`0xA3`) makes the XMB play nothing.** It
  shows no error. A file of such frames decodes in ffmpeg, has a correct
  header and is accepted by `sceAtrac`, and is still silent in the XMB.
- Every frame of the known-good file is `0xA2`: three bands.
- The retail LP2 file uses one, two and three bands (794, 48 and 209 frames in
  the first channel) and never four.

The fourth band starts at 44100 / 8 x 3 = 16537.5 Hz. Because that band is
never coded, pspbuild low-passes the input at 15.5 kHz first (80 dB down by
16.5 kHz). That leaves nothing above it for the QMF's transition region to fold
back into the third band.

The encoder holds this rule by construction. It only ever computes spectra
for three bands (`encoder::CODED_BANDS`), so there is nothing to code in a
fourth. The validator checks every frame anyway.

### 3.3 Length and size

At most **55 s** and **500 KB** (500000 bytes). At LP4 the time limit binds
first: 2368 frames is 54.98 s and 454,800 bytes, and one more frame is over
55 s. Two of those frames are the lead-in and the spare, so the longest loop
is 2366 frames, 54.94 s. A longer input is cut to its first 54.94 s, with a
warning. Use `--start`/`--duration` to choose a different section.

### 3.4 Looping

With the loop point of §2.1 in place:

- **pspbuild never fades either end.** A fade would put a dip at the loop
  point.
- **The loop is exactly the input.** It runs for the input's own length, not
  a whole number of frames, so there is no padding and no gap at the seam.
- **The encoder treats the stream as periodic**, and the stream holds the
  track as a cycle (§2.1). The seam is coded like any other point.
- **The encoder adds no delay of its own.** Its analysis is the exact
  transpose of the decoder's synthesis, so decoded stream sample *n* is exactly
  the encoder's input sample *n*. The only delay is the deliberate
  one-frame lead-in.
- The resampler and low-pass are also periodic.
- An MP3 input's encoder delay and padding are trimmed using the LAME/Lavc
  header. Otherwise a looped MP3 would gain a gap of silence at the seam.
- Decoding an ATRAC3 input keeps only the samples its `fact` chunk names, so
  re-encoding a looped SND0 does not fold its lead-in into the loop.

## 4. Encoder and decoder

Both are written in Rust for pspbuild, under its MIT licence (§8).

**Encoder** (`src/audio/atrac3/encoder.rs`):

- Mid/side, then the QMF tree and MDCT as the transpose of the synthesis. The
  MDCT uses the raised-sine analysis window that is biorthogonal to the
  decoder's synthesis window.
- For each quantisation unit, candidates across all seven selectors, a few
  scale factors around the one that just holds the peak, and two rounding
  offsets. Only the points on the lower convex hull of (bits, distortion) are
  kept.
- A greedy allocation across both units makes the upgrade that buys the most
  weighted distortion per bit, until the 1522-bit budget is spent. Each unit
  is tried in both Huffman and fixed-length coding.
- Distortion is weighted by a crude masking threshold: the energy spread from
  neighbouring units, raised to 0.5. An exponent of 1 would equalise
  noise-to-signal ratio, and 0 would minimise plain squared error.
- Not used: gain control (pre-echo suppression on transients) and tonal
  components. Both are valid ATRAC3 and the decoder handles them. Leaving them
  out is a quality limitation, not a format one.

**Decoder** (`src/audio/atrac3/decoder.rs`) is complete: both stereo modes,
gain control, tonal components and joint-stereo matrixing and weighting. On
the known-good file and the retail file it agrees with ffmpeg to 131 dB, i.e.
to float rounding, in both channels. No available file varies the
joint-stereo matrix or weighting from frame to frame, so that path is not
checked against a reference.

## 5. The validator

`pspbuild audio inspect`, the check after every encode, and the SND0 checks in
`pspbuild inspect` and `pspbuild verify` all use the same code. It reports every
chunk and the fmt fields. It decodes every frame and counts coded bands per
unit.

**Errors: the XMB will not play it.** `verify` fails and `audio inspect` exits
non-zero.

- not RIFF/WAVE, a broken chunk structure, or no `fmt `/`data`
- format tag other than `0x0270`
- sample rate other than 44100 Hz
- channel count other than 2
- block align other than 192 (LP4) or 384 (LP2)
- data not a whole number of frames
- any sound unit coding four bands, named by frame: *"frame 17 codes four QMF
  bands; the XMB will not play this"*
- any frame that does not decode
- a loop point (`smpl`) without a `fact` chunk: the XMB plays nothing
- longer than 55 s, or larger than 500 KB

**Warnings: differs from the hardware-proven profile.** These fail only with
`--strict`, which is what pspbuild applies to its own output.

- LP2
- no loop point: the XMB plays the file once and stops
- a `fact` chunk without a loop point
- a loop that is not `fact` delay to delay + samples - 1, or that does not
  repeat forever, or a `fact` that claims more samples than the frames hold
- any chunk besides `fmt `, `fact`, `smpl` and `data`
- LP4 without the joint-stereo flag
- a byte rate that does not match the block align
- an fmt chunk that differs from the known-good one

The plan behind this work called for "first byte of every frame is `0xA2`" and
"no `fact` chunk" as hard rules. The retail file breaks both and was shipped
by Sony. The hard rules are *never four bands* and *no loop without `fact`*.
The `fact` chunk turned out to be required for looping (§2.1). The exact `0xA2`
profile is what pspbuild writes.

## 6. Inputs

| format | decoder | licence |
| --- | --- | --- |
| WAV (8 to 32-bit PCM, float) | `hound` | Apache-2.0 |
| FLAC | `claxon` | Apache-2.0 |
| Ogg Vorbis | `lewton` | MIT or Apache-2.0 |
| MP3 | `nanomp3` (pure Rust, from minimp3) | MIT or Apache-2.0 |
| ATRAC3 | pspbuild's own | MIT |

**Not supported:**

- **AAC / M4A.** There is no permissively licensed pure-Rust decoder.
  `symphonia` has one, but it is MPL-2.0, and shelling out to ffmpeg would
  make it a build-time requirement. pspbuild says so and stops. Convert to
  FLAC or WAV first.
- **Opus.** No permissive pure-Rust decoder either.
- **ATRAC3plus** and other codecs in a WAVE file. The XMB's SND0 player is
  ATRAC3.

Mono is duplicated to both channels. More than two channels are folded down
from the WAVE order: centre and surrounds at -3 dB, LFE dropped, scaled so
nothing that did not clip before clips now. Vorbis's channel order is mapped
to WAVE's first. Any rate from 4 kHz to 384 kHz is resampled with a
Kaiser-windowed sinc: 90 dB stopband, passband to 19 kHz or 90% of the lower
Nyquist rate.

## 7. Quality, as measured

Frame validity is necessary but not sufficient, so the tests measure quality.
Each test signal goes through the whole pipeline, and the loop the `fact`
chunk names is decoded. It is then compared with the low-passed input. Per-band figures split
reference and error with the codec's own QMF bank. The floors in
`tests/audio.rs` sit about 1 to 2 dB below these values.

| signal (2 s) | SNR | band 0 (0 to 5.5 kHz) | band 1 (5.5 to 11 kHz) | band 2 (11 to 16.5 kHz) |
| --- | --- | --- | --- | --- |
| log sine sweep 50 Hz to 15 kHz | 32.9 dB | 33.1 | 33.2 | 30.1 |
| pink noise, independent channels | 9.8 dB | 12.5 | 2.4 | 0.0 |
| synthetic drum loop | 18.2 dB | 22.8 | 7.7 | 6.4 |
| A-major chord | 34.5 dB | 34.5 | 7.1 | 2.2 |

The chord has almost no energy above band 0, so its upper-band figures mean
little. Pink noise is the worst case: at 66 kbps no bits are left for its
third band, which is dropped.

On real music, 6 s of each file was decoded and re-encoded, and compared with
the decoded original:

| source | SNR |
| --- | --- |
| the known-good SND0 (orchestral) | 23.0 dB |
| the retail LP2 SND0 (dense pop, 132 kbps source) | 13.2 dB |

When ffmpeg is installed, the tests also decode pspbuild's output with it. It
must agree with pspbuild's decoder to better than 100 dB. It agrees to about
132 dB.

**What was tried.** Numbers are from the full tracks.

| change | known-good music | retail music | chord |
| --- | --- | --- | --- |
| first version: masking exponent 0.7, one scale per selector | 19.3 dB | 10.9 dB | 32.1 dB |
| exponent 0 (plain squared error) | 21.6 | 15.1 | 32.1 |
| exponent 1 (flat noise-to-signal) | 15.4 | 7.4 | 32.1 |
| exponent 0.5 | 20.9 | 13.2 | 32.1 |
| + convex-hull allocation, wider scale search, deadzone rounding | **22.4** | **13.5** | **32.3** |

Exponent 0 gives the best overall SNR, but it starves the upper bands: the
retail track's third band fell to 0.9 dB. 0.5 is the compromise. SNR is not
loudness-weighted, so listen before trusting any of this. Gain control is the
obvious next step for transients.

**The tests test the encoder.** As a check, the encoder was changed to code a
fourth band (`CODED_BANDS = 4`). Then 11 of the 27 tests in `tests/audio.rs`
and 5 of the 11 in `tests/audio_cli.rs` failed. That is every test that
encodes, either because `make_snd0` refused to write the output or because
the direct frame-byte check caught it. The constant was then restored.

## 8. Licensing

pspbuild is MIT, and the audio code keeps it that way:

- The ATRAC3 encoder, decoder and container code were written for pspbuild
  from descriptions of the format and from observing real files. Other ATRAC3
  implementations' source code was not consulted or copied. The format
  constants in `tables.rs` are properties of the bitstream: the Huffman code
  lengths, the unit edges, the QMF prototype and the window. Each is checked,
  by Kraft's equality for the codes and by bit-exact black-box agreement with
  ffmpeg on real files for the rest.
- ffmpeg is only an optional black-box oracle in the tests. It is never
  linked, vendored or required, and the tests skip it when it is absent.
- Every dependency is permissively licensed. `deny.toml` holds the allowlist
  (MIT, Apache-2.0, BSD, ISC, Zlib, Unlicense, CC0), and
  `cargo deny check licenses` enforces it. There is one scoped exception:
  `unicode-ident` also carries the permissive Unicode-3.0 licence for its
  data tables. It is a build-time dependency of the derive macros.

## 9. Testing on a PSP

Hardware is the only real proof. To check a build:

1. Convert and inspect:
   `pspbuild audio snd0 theme.flac -o SND0.AT3 && pspbuild audio inspect SND0.AT3`.
   The verdict should be *playable; matches the profile pspbuild writes*, and
   the loop should read *samples 1024 to …, forever*.
2. Build with it: `pspbuild build-mg game.prx --snd0 SND0.AT3 -o EBOOT.PBP`,
   then `pspbuild verify EBOOT.PBP`. Expect `VALID: SND0.AT3 ...`.
3. Copy to `ms0:/PSP/GAME/<folder>/EBOOT.PBP`. Remove any stale copy, since the
   XMB caches icons and sounds per folder.
4. Highlight the game in the XMB and wait a second or two. Music should start.
   Silence with no error is the four-band failure, or some new one.
5. Leave it past the end of the track. It should loop without a gap or click.
   Stopping instead means the loop point is missing (§2.1).
6. Check the volume and stereo image against the source. Listen for pre-echo
   on sharp transients, the known weakness (§4).
7. Negative control: `pspbuild audio inspect` an SND0 known to be silent. It
   should say NOT PLAYABLE. If an SND0 that pspbuild passes is silent on
   hardware, the validator is missing a rule. Note the model and firmware.
