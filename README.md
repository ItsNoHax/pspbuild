# pspbuild

A comprehensive PSP EBOOT toolkit for encrypting PRX modules, building homebrew `EBOOT.PBP` containers, and inspecting or verifying PSP executables.

A from-scratch Rust implementation that performs KIRK cryptography locally with no runtime dependencies. The tool generates encrypted PRX headers dynamically from the input payload rather than relying on fixed-capacity templates.

## Features

- **Encrypt PRX modules** — Convert plaintext modules to encrypted PRX format compatible with retail PSP firmware
- **Build EBOOT.PBP containers** — Create homebrew (MG) or Store-format (EG/NPDRM) packages from modules or UMD images
- **Inspect files** — Examine PBP containers, UMD images, and encrypted PRX modules with detailed structure analysis
- **Verify integrity** — Validate container structure, header hashes, CMAC tags, and payload integrity
- **Extract and decrypt** — Unpack containers and recover original modules
- **Library API** — All functionality available as a Rust library for integration into other tools

## Installation

```sh
cargo install --path .
```

Produces a standalone binary with no external runtime dependencies.

## Usage

```sh
# Build a homebrew EBOOT.PBP from a module (MG category)
pspbuild build-mg game.prx -o EBOOT.PBP --title "My Game" --icon0 ICON0.PNG

# Build a Store-format EBOOT.PBP from a UMD image (EG category)
pspbuild build-eg game.iso -o EBOOT.PBP --title "My Game"

# Encrypt a PRX module or EBOOT.PBP (replaces DATA.PSP section)
pspbuild encrypt game.prx -o game.enc.prx
pspbuild encrypt EBOOT.PBP -o signed/EBOOT.PBP

# Inspect file structure and contents
pspbuild inspect EBOOT.PBP
pspbuild inspect game.iso

# Verify container integrity
pspbuild verify EBOOT.PBP

# Extract container contents
pspbuild extract EBOOT.PBP -o extracted/ --decrypt

# Decrypt an EBOOT.PBP to recover the original module
pspbuild decrypt EBOOT.PBP -o game.prx
```

Normal execution produces no stdout output and exits with a non-zero code on failure, making it suitable for build scripts. Use `--verbose` for detailed output on stderr.

### Example Output

```console
$ pspbuild -v build-mg game.prx --title "My Game"
Category:         MG
Title:            My Game
Input size:       498752 bytes
Compression:      enabled
DATA.PSP size:    147472 bytes
  PARAM.SFO    360 bytes
  DATA.PSP     147472 bytes
Output size:      147872 bytes
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

## Build System Integration

```cmake
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/EBOOT.PBP
    COMMAND pspbuild build-mg $<TARGET_FILE:game> -o EBOOT.PBP --title "My Game"
    DEPENDS game
)
```

## Library Usage

The CLI is a thin wrapper; the core functionality is available as a library:

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

Public APIs include `encrypt_prx`, `decrypt_prx`, `verify_prx`, `inspect::inspect`, and the format layers (`pbp`, `sfo`, `psp::header`, `psp::tag`, `kirk`, `crypto`) for building custom tools.

## MG and EG Security Paths

The `CATEGORY` field in `PARAM.SFO` determines which security pipeline the firmware uses. These are distinct pipelines, not interchangeable options:

- **MG (Memory Stick Games)** — Homebrew applications. `DATA.PSP` contains an encrypted PRX with no signature chain. Fully implemented.
- **EG (Extended Games / NPDRM)** — Store-format downloads. `DATA.PSP` holds a signed NPDRM license stub and `DATA.PSAR` contains an `NPUMDIMG` encrypted ISO. Fully implemented: `build-eg` creates signed containers that boot on official firmware, validated against genuine Sony Store archives.

`pspbuild` enforces the correct pipeline for each container type and never silently falls back between them.

## Documentation

The `docs/` directory describes the PSP formats themselves:

- [PBP.md](docs/PBP.md) — `EBOOT.PBP` container and `PARAM.SFO` structure
- [ISO.md](docs/ISO.md) — PSP UMD images: ISO9660 layout as used on disc
- [FORMAT.md](docs/FORMAT.md) — Encrypted PRX format: `~PSP` header, KIRK CMD1 container
- [MG.md](docs/MG.md) — MG security path end-to-end
- [EG.md](docs/EG.md) — EG/NPDRM path: building signed Store containers from UMD images
- [NPUMDIMG.md](docs/NPUMDIMG.md) — EG archive format: header, block table, block cryptography
- [KEYS.md](docs/KEYS.md) — Key/tag matrix and the relationship between category, tag, key, and format
- [COMPATIBILITY.md](docs/COMPATIBILITY.md) — Tested platforms, firmware versions, and known gaps

**Recommended reading order:** Start with [PBP.md](docs/PBP.md) for the container, then [FORMAT.md](docs/FORMAT.md) for the executable format, then [MG.md](docs/MG.md) for how they integrate. [KEYS.md](docs/KEYS.md) serves as a reference.

## Known Limitations

- **One header bit is enforced:** `mod_attribute` always has bit `0x0200` set (OR-ed into the module's own attributes). Retail firmware will not load an encrypted module without it. The semantic meaning of this bit is undocumented.
- **Single hardware validation:** Tested on a PSP Slim running official firmware for both MG and EG paths. Other models and firmware revisions are unverified.
- **Single tag scheme:** Only tag `0xADF305F0` (the 2.80 demo scheme) is emitted. This scheme's header carries no signature.
- **Maximum four segments:** Limited by the `~PSP` header's segment descriptor capacity.

## Development

```sh
cargo test              # Crypto vectors, format, property, and CLI tests
cargo clippy --all-targets
```

The cryptographic layer is validated against published standards (NIST SP 800-38A for AES, RFC 4493 for CMAC, FIPS 180-1 for SHA-1) rather than self-referential tests.

## License

MIT. See [LICENSE](LICENSE).

The KIRK constants are the long-published PSP keys found in every open-source PSP tool and emulator.