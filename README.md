# pspbuild

PSP EBOOT toolkit in Rust: encrypt PRX modules, build `EBOOT.PBP` containers, inspect or verify PSP executables, and convert music to XMB background audio.

- Performs KIRK cryptography locally; no external tools or runtime dependencies.
- Generates `~PSP` headers from the payload instead of copying fixed-size templates.
- Output boots on a retail PSP running official firmware (MG and EG).
- Native ATRAC3 encoder for `SND0.AT3`; no ffmpeg or Sony tools.

## Features

| Feature | Description |
| --- | --- |
| `encrypt` | Encrypt a PRX, or the `DATA.PSP` of an existing `EBOOT.PBP` |
| `build-mg` | Build a homebrew (`CATEGORY=MG`) EBOOT from a module |
| `build-eg` | Build a signed Store-format (`CATEGORY=EG`, NPDRM) EBOOT from a UMD image |
| `inspect` | Describe a PBP, UMD image, or PRX, including whether the XMB can play its `SND0.AT3` |
| `verify` | Check an encrypted PRX or MG EBOOT: header SHA-1, CMACs, decryption, module, `SND0.AT3` |
| `extract` | Write each PBP section to a directory |
| `decrypt` | Recover the original module from an encrypted PRX or MG EBOOT |
| `audio snd0` | Convert WAV, FLAC, Ogg Vorbis or MP3 to an `SND0.AT3` |
| `audio inspect` | Explain an AT3 and check it against what the XMB plays |

## Installation

```sh
cargo install --path .
```

## Usage

```sh
# MG: homebrew EBOOT from a module
pspbuild build-mg game.prx -o EBOOT.PBP --title "My Game" --icon0 ICON0.PNG

# EG: signed Store-format EBOOT from a UMD image
pspbuild build-eg game.iso -o EBOOT.PBP --content-id UL0000-ULUS10380_00-0000000000000000

# Encrypt a PRX, or the DATA.PSP of an EBOOT
pspbuild encrypt game.prx -o game.enc.prx
pspbuild encrypt EBOOT.PBP -o signed/EBOOT.PBP

# Inspect, verify, extract, decrypt
pspbuild inspect EBOOT.PBP
pspbuild verify EBOOT.PBP
pspbuild extract EBOOT.PBP -o extracted/ --decrypt
pspbuild decrypt EBOOT.PBP -o game.prx

# XMB background music, while building or on its own
pspbuild build-mg game.prx --snd0 theme.mp3 --snd0-start 30 --snd0-duration 40
pspbuild audio snd0 theme.flac -o SND0.AT3
pspbuild audio inspect SND0.AT3
```

Run `pspbuild <command> --help` for all options.

`encrypt`, `build-mg`, `decrypt` and `audio snd0` are silent on success; pass `-v` for details on stderr. All commands exit non-zero on failure.

### Options

| Command | Option | Description |
| --- | --- | --- |
| `encrypt`, `build-mg` | `--no-compress` | Do not gzip the payload |
| `build-mg` | `-t, --title` | XMB title (default: module name) |
| `build-mg` | `--system-version` | `PSP_SYSTEM_VER` value |
| `build-mg` | `--base <FILE>` | Start from an existing EBOOT, keeping its other sections |
| `build-mg` | `--icon0`, `--icon1`, `--pic0`, `--pic1`, `--snd0` | Media sections. `--snd0` also takes WAV, FLAC, Ogg Vorbis or MP3 and converts it; a playable `SND0.AT3` is kept as-is |
| `build-mg` | `--snd0-start`, `--snd0-duration` | Seconds; choose the section of `--snd0` to keep (at most 55 s) |
| `build-eg` | `--content-id <ID>` | Required. Also derives the fixed version key |
| `build-eg` | `--no-compress` | Store every block uncompressed |
| `build-eg` | `--startdat <PNG>` | Boot screen image |
| `build-eg` | `--opnssmp <FILE>` | `OPNSSMP.BIN` module |
| `extract` | `--decrypt` | Also write `DATA.PSP.dec` (MG only) |
| `audio snd0` | `-o`, `--start`, `--duration` | Output (default `SND0.AT3` beside the input) and section |
| `audio inspect` | `--strict` | Also fail on anything `pspbuild` would not write, e.g. LP2 or a missing loop point |

### Example output

```console
$ pspbuild build-eg game.iso --content-id UL0000-ULUS10380_00-0000000000000000
Title:               LEGO® Batman™: The Videogame
Content ID:          UL0000-ULUS10380_00-0000000000000000
Image size:          1136689152 bytes
Blocks:              34689 of 32768 bytes, 22934 (66%) compressed
DATA.PSAR:           603135408 bytes
Wrote EBOOT.PBP (603693744 bytes)
```

```console
$ pspbuild inspect EBOOT.PBP
Format:              PBP container
Total size:          431844 bytes
Container version:   0x00010000
Category:            MG
Title:               Angle Zero
Firmware required:   1.00

Sections:
  PARAM.SFO    offset 0x00000028         288 bytes  PARAM.SFO
  ICON0.PNG    offset 0x00000148       17186 bytes  PNG image
  ICON1.PMF    empty
  PIC0.PNG     empty
  PIC1.PNG     offset 0x0000446A      101102 bytes  PNG image
  SND0.AT3     offset 0x0001CF58      165756 bytes  RIFF/AT3 audio
  DATA.PSP     offset 0x000456D4      147472 bytes  PSP PRX (encrypted)
  DATA.PSAR    empty

Executable:
  Format:            PSP PRX (encrypted)
  Encrypted:         yes
  Compression:       yes
  Payload size:      498752 bytes
  Module name:       AngleZero
  Entry point:       0x00010258
  Tag:               0xADF305F0
```

A PBP with an `SND0.AT3` also gets an `SND0.AT3:` block, the same report as `audio inspect`:

```console
$ pspbuild audio inspect SND0.AT3
File size:           13008 bytes
Chunks:
  fmt   offset 0x0000000C          32 bytes
  fact  offset 0x00000034           8 bytes
  smpl  offset 0x00000044          60 bytes
  data  offset 0x00000088       12864 bytes
Codec:               ATRAC3 (0x0270)
Sample rate:         44100 Hz
Channels:            2
Bitrate:             66144 bps (LP4), 192-byte frames
Stereo:              joint
fmt chunk:           identical to a known-good LP4 SND0
Frames:              67 (1.56 s)
Coded QMF bands:     3 bands in 67
  side channel:      3 bands in 67
Loop:                samples 1024 to 67173 (1.50 s), forever
Verdict:             playable; matches the profile pspbuild writes
```

### Build system integration

```cmake
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/EBOOT.PBP
    COMMAND pspbuild build-mg $<TARGET_FILE:game> -o EBOOT.PBP --title "My Game"
    DEPENDS game
)
```

## Library

The CLI is a thin wrapper over the library.

```rust
use pspbuild::mg::{MgEbootRequest, build_mg_eboot};

let module = std::fs::read("game.prx")?;
let eboot = build_mg_eboot(&MgEbootRequest {
    module: &module,
    title: Some("My Game"),
    compress: true,
    ..Default::default()
})?;
std::fs::write("EBOOT.PBP", &eboot.data)?;

let snd0 = pspbuild::audio::make_snd0(&std::fs::read("theme.flac")?, &Default::default())?;
std::fs::write("SND0.AT3", &snd0.data)?;
```

| Module | Contents |
| --- | --- |
| crate root | `encrypt_prx`, `decrypt_prx`, `verify_prx`, `inspect_prx` |
| `mg` | `build_mg_eboot` |
| `eg` | `build_eg_eboot` (streaming) |
| `inspect` | File detection and reports |
| `pbp`, `sfo`, `iso` | Container, parameter table, ISO9660 reader |
| `psp`, `kirk`, `crypto` | `~PSP` header, KIRK commands, AES/CMAC/SHA-1/ECDSA |
| `npdrm` | NPUMDIMG, BB-MAC, BB-Cipher, LZRC, PGD, `DATA.PSP` |
| `audio` | `make_snd0`, `inspect_at3`; `atrac3` encoder/decoder, `riff`, `input`, `pcm` |

## Security paths

`CATEGORY` in `PARAM.SFO` selects the firmware's security path. The two are separate pipelines; `pspbuild` never falls back from one to the other.

| Category | `DATA.PSP` | `DATA.PSAR` | Signed |
| --- | --- | --- | --- |
| `MG` | Encrypted `~PSP` PRX | empty | no |
| `EG` | NPDRM licence stub | `NPUMDIMG` archive | ECDSA |

## Limitations

- Emits one PRX tag, `0xADF305F0`.
- `mod_attribute` bit `0x0200` is always set; firmware refuses encrypted modules without it.
- At most four segments per module.
- EG supports fixed-key content IDs only; supplied version keys (`KEYS.BIN`) are not supported.
- `inspect`, `verify`, `decrypt` and `extract --decrypt` do not open NPDRM (EG) executables.
- Hardware-tested on one PSP Slim on official firmware.
- SND0 output plays and loops cleanly on one PSP Slim (6.61, ARK); other models are untested ([AUDIO.md §9](docs/AUDIO.md) has a checklist).
- SND0 input: WAV, FLAC, Ogg Vorbis, MP3, ATRAC3. No AAC/M4A or Opus: no permissively licensed pure-Rust decoder. Longer input is cut to its first 54.94 s.
- SND0 encoder has no gain control; sharp transients may pre-echo.

See [COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Documentation

| Document | Contents |
| --- | --- |
| [PBP.md](docs/PBP.md) | `EBOOT.PBP` container and `PARAM.SFO` |
| [ISO.md](docs/ISO.md) | UMD images (ISO9660) |
| [FORMAT.md](docs/FORMAT.md) | Encrypted PRX: `~PSP` header, KIRK CMD1 |
| [MG.md](docs/MG.md) | MG pipeline |
| [EG.md](docs/EG.md) | EG pipeline |
| [NPUMDIMG.md](docs/NPUMDIMG.md) | EG archive format |
| [KEYS.md](docs/KEYS.md) | Categories, tags and keys |
| [AUDIO.md](docs/AUDIO.md) | `SND0.AT3`: XMB rules, ATRAC3 encoder, measurements |
| [COMPATIBILITY.md](docs/COMPATIBILITY.md) | Test results and known gaps |

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo deny check licenses   # permissive licences only; see deny.toml
```

Tests that need copyrighted fixtures (retail UMDs, Sony EBOOTs) skip when absent; retail SND0s are read from EBOOTs in `plans/`. Audio tests use ffmpeg as an optional oracle and skip that check without it. Place them in `plans/` (gitignored) or set:

| Variable | Purpose |
| --- | --- |
| `PSPBUILD_TEST_ISO` | UMD image |
| `PSPBUILD_TEST_EG_PBP` | EG `EBOOT.PBP` |
| `PSPBUILD_TEST_SLOW=1` | Enable full-archive build tests |

Cross-check against PPSSPP's decrypter:

```sh
scripts/cross-validate.sh /path/to/ppsspp [module.prx]
```

## License

MIT. See [LICENSE](LICENSE). All dependencies are permissively licensed (`deny.toml`); the ATRAC3 codec is `pspbuild`'s own code.

The KIRK and NPDRM keys included are long-published and present in every open-source PSP tool and emulator.
