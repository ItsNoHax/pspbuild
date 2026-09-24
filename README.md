# pspbuild

PSP EBOOT toolkit in Rust: encrypt PRX modules, build `EBOOT.PBP` containers, and inspect or verify PSP executables.

- Performs KIRK cryptography locally; no external tools or runtime dependencies.
- Generates `~PSP` headers from the payload instead of copying fixed-size templates.
- Output boots on a retail PSP running official firmware (MG and EG).

## Features

| Feature | Description |
| --- | --- |
| `encrypt` | Encrypt a PRX, or the `DATA.PSP` of an existing `EBOOT.PBP` |
| `build-mg` | Build a homebrew (`CATEGORY=MG`) EBOOT from a module |
| `build-eg` | Build a signed Store-format (`CATEGORY=EG`, NPDRM) EBOOT from a UMD image |
| `inspect` | Describe a PBP, UMD image, or PRX |
| `verify` | Check an encrypted PRX or MG EBOOT: header SHA-1, CMACs, decryption, module |
| `extract` | Write each PBP section to a directory |
| `decrypt` | Recover the original module from an encrypted PRX or MG EBOOT |

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
```

Run `pspbuild <command> --help` for all options.

`encrypt`, `build-mg` and `decrypt` are silent on success; pass `-v` for details on stderr. All commands exit non-zero on failure.

### Options

| Command | Option | Description |
| --- | --- | --- |
| `encrypt`, `build-mg` | `--no-compress` | Do not gzip the payload |
| `build-mg` | `-t, --title` | XMB title (default: module name) |
| `build-mg` | `--system-version` | `PSP_SYSTEM_VER` value |
| `build-mg` | `--base <FILE>` | Start from an existing EBOOT, keeping its other sections |
| `build-mg` | `--icon0`, `--icon1`, `--pic0`, `--pic1`, `--snd0` | Media sections |
| `build-eg` | `--content-id <ID>` | Required. Also derives the fixed version key |
| `build-eg` | `--no-compress` | Store every block uncompressed |
| `build-eg` | `--startdat <PNG>` | Boot screen image |
| `build-eg` | `--opnssmp <FILE>` | `OPNSSMP.BIN` module |
| `extract` | `--decrypt` | Also write `DATA.PSP.dec` (MG only) |

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
| [COMPATIBILITY.md](docs/COMPATIBILITY.md) | Test results and known gaps |

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Tests that need copyrighted fixtures (retail UMDs, Sony EBOOTs) skip when absent. Place them in `plans/` (gitignored) or set:

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

MIT. See [LICENSE](LICENSE).

The KIRK and NPDRM keys included are long-published and present in every open-source PSP tool and emulator.
