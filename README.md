# pspbuild

A PSP EBOOT toolkit: encrypt PRX modules, build homebrew `EBOOT.PBP`
containers, and inspect or verify what you or anyone else produced.

A from-scratch Rust replacement for the PSPSDK `PrxEncrypter` tool and the PBP
handling around it. It implements the required KIRK cryptography locally, has no
runtime dependencies, and — the reason it exists — **sizes its output from the
actual payload instead of from a fixed-capacity template**.

```text
700 KiB PRX  ->  pspbuild     ->  ~700 KiB encrypted PRX
700 KiB PRX  ->  legacy tool  ->    5.3 MiB encrypted PRX
```

Output is confirmed booting on a retail PSP Slim running official firmware.

## The size problem

The legacy encrypter ships three prebuilt header templates and picks the
smallest one that the input fits into. Every size field, and the integrity
hashes covering them, are copied verbatim out of that template — so the output
is padded to the template's capacity, not to the payload.

Measured on a real module:

| | size |
| --- | ---: |
| original module | 498,752 |
| legacy `PrxEncrypter` | 5,583,952 |
| `pspbuild` | 147,472 |

AES and CMAC do not expand data; AES-CBC rounds up to the next 16-byte block
and that is all. The multi-megabyte growth was entirely the fixed templates.

This tool generates the header instead. Every size-dependent field is computed,
and the integrity hashes are computed over the result, so the output is exactly:

```text
0x150 bytes of header  +  align16(payload size)
```

For why that is possible — the format only protects the header with an unkeyed
SHA-1 and CMACs under a published key, so nothing needs to be copied from a
signed original — see [docs/FORMAT.md](docs/FORMAT.md).

## Installation

```sh
cargo install --path .
```

The result is a standalone binary. No Python, CMake, OpenSSL or runtime
environment is required.

## Usage

```sh
# Build a homebrew EBOOT.PBP from a module
pspbuild build-mg game.prx -o EBOOT.PBP --title "My Game" --icon0 ICON0.PNG

# Encrypt a module, or an EBOOT.PBP (its DATA.PSP section is replaced)
pspbuild encrypt-prx game.prx -o game.enc.prx
pspbuild encrypt-prx EBOOT.PBP -o signed/EBOOT.PBP

# Show what a file is and what is inside it
pspbuild inspect EBOOT.PBP
pspbuild inspect game.iso        # UMD images too, without loading them

# Check the container, the header hash, both CMAC tags and the payload
pspbuild verify EBOOT.PBP

# Unpack a container
pspbuild extract EBOOT.PBP -o extracted/ --decrypt

# Recover the original module
pspbuild decrypt EBOOT.PBP -o game.prx
```

`encrypt` remains an alias for `encrypt-prx`, so existing build scripts keep
working.

Normal runs print nothing on stdout and exit non-zero on failure, so the tool
drops straight into a build script. `--verbose` writes to stderr only.

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

### Inspection

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

## Build-system integration

```cmake
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/EBOOT.PBP
    COMMAND pspbuild build-mg $<TARGET_FILE:game> -o EBOOT.PBP --title "My Game"
    DEPENDS game
)
```

## Library

The CLI is a thin wrapper; the same functionality is available directly.

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

`encrypt_prx`, `decrypt_prx`, `verify_prx` and `inspect::inspect` are public, as
are the format layers (`pbp`, `sfo`, `psp::header`, `psp::tag`, `kirk`,
`crypto`) for tools that need them.

## MG and EG

`CATEGORY` in `PARAM.SFO` decides which security path the firmware runs, and the
two are genuinely different pipelines rather than options on one.

- **MG** — memory-stick games, i.e. homebrew. `DATA.PSP` is an encrypted PRX and
  there is no signature anywhere in the chain. **Implemented.**
- **EG** — downloaded games. `DATA.PSP` is a signed NPDRM licence stub and
  `DATA.PSAR` holds an `NPUMDIMG` encrypted ISO. **Implemented**: `build-eg`
  turns a UMD image into a signed container, compressed by default, and it
  boots on official firmware. The format was checked against four genuine Sony
  Store archives rather than only against a reimplementation. See
  [docs/EG.md](docs/EG.md).

`pspbuild` refuses to run one pipeline against a container that asks for the
other, and never silently falls back between them.

## Documentation

[docs/](docs/) describes the formats themselves rather than the code:
[PBP.md](docs/PBP.md), [ISO.md](docs/ISO.md), [FORMAT.md](docs/FORMAT.md),
[MG.md](docs/MG.md), [EG.md](docs/EG.md), [KEYS.md](docs/KEYS.md) and
[COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Known limitations

- **One header bit is forced.** `mod_attribute` always has bit `0x0200` set,
  OR-ed into the module's own attributes: retail firmware will not load an
  encrypted module without it. Isolated on hardware one field at a time, so
  everything else is derived from the input. What the bit means is not known —
  see [docs/FORMAT.md](docs/FORMAT.md#8-the-one-field-the-firmware-insists-on).
- **Tested on one console.** A PSP Slim on official firmware, MG and EG alike.
  Other models and firmware revisions are unverified.
- **One tag.** Only `0xADF305F0` (the 2.80 demo scheme) is emitted. This is the
  scheme the legacy templates used, and the one whose header carries no
  signature.
- **At most four segments**, which is what a `~PSP` header can describe.

## Development

```sh
cargo test        # crypto vectors, format, property and CLI tests
cargo clippy --all-targets
```

The crypto layer is tested against published vectors (NIST SP 800-38A for AES,
RFC 4493 for CMAC, FIPS 180-1 for SHA-1) rather than against itself.

## License

MIT. See [LICENSE](LICENSE).

The KIRK constants are the long-published PSP keys found in every open-source
PSP tool and emulator.
