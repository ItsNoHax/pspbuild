# prx-encrypter

Encrypt PSP PRX modules into PSP-compatible encrypted PRX files.

A from-scratch Rust replacement for the PSPSDK `PrxEncrypter` tool. It
implements the required KIRK cryptography locally, has no runtime dependencies,
and — the reason it exists — **sizes its output from the actual payload instead
of from a fixed-capacity template**.

```text
700 KiB PRX  ->  prx-encrypter  ->  ~700 KiB encrypted PRX
700 KiB PRX  ->  legacy tool    ->   5.3 MiB encrypted PRX
```

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
| `prx-encrypter` | 147,472 |

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
# Encrypt (output defaults to game.enc.prx)
prx-encrypter encrypt game.prx -o game.enc.prx

# Show what a file is, encrypted or not
prx-encrypter inspect game.enc.prx

# Check the header hash, both CMAC tags, and the decrypted payload
prx-encrypter verify game.enc.prx

# Recover the original module
prx-encrypter decrypt game.enc.prx -o game.dec.prx
```

Options for `encrypt`:

```text
-o, --output <FILE>   output path (default: <input>.enc.<ext>)
    --no-compress     skip gzip compression of the payload
    --format <FMT>    psp (default) or pspemu
-v, --verbose         report each stage on stderr
```

Normal runs print nothing on stdout and exit non-zero on failure, so the tool
drops straight into a build script. `--verbose` writes to stderr only.

```console
$ prx-encrypter -v encrypt game.prx
Input size:       498752 bytes
Compression:      enabled
Payload size:     147126 bytes
Encrypted size:   147136 bytes
Output size:      147472 bytes
```

## Build-system integration

```cmake
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/game.enc.prx
    COMMAND prx-encrypter encrypt $<TARGET_FILE:game> -o game.enc.prx
    DEPENDS game
)
```

## Library

The CLI is a thin wrapper; the same functionality is available directly.

```rust
use prx_encrypter::{EncryptOptions, encrypt_prx, verify_prx};

let module = std::fs::read("game.prx")?;
let encrypted = encrypt_prx(&module, &EncryptOptions::default())?;
std::fs::write("game.enc.prx", &encrypted.data)?;

verify_prx(&encrypted.data)?;
```

`inspect_prx`, `verify_prx` and `decrypt_prx` are also public, as are the
format layers (`psp::header`, `psp::tag`, `kirk`, `crypto`) for tools that need
them.

## Format overview

```text
0x000  ~PSP header       0x150 bytes  metadata, wrapped keys, sizes, tag, SHA-1
0x150  payload           aligned      AES-128-CBC, zero IV
```

Internally the payload sits inside a KIRK CMD1 container whose header is folded
into the `~PSP` header rather than stored separately. Authentication is a SHA-1
over the header plus two AES-CMAC tags — one over the header region, one over
the header and the entire payload.

## Compatibility

Files produced by the PSPSDK reference tool are parsed, verified and decrypted
correctly; this is covered by a test against a reference-produced fixture.

Output is validated against PPSSPP's own `PrxDecrypter` — an independent
implementation — which accepts the files and recovers the input byte for byte:

```sh
scripts/cross-validate.sh /path/to/ppsspp /path/to/module.prx
```

Output is deterministic: the per-module keys are derived from the payload rather
than randomly generated, so the same input always yields identical bytes.

## Known limitations

- **Not verified on PSP hardware.** Correctness is established against the
  format and against an independent software decrypter. If you test on a real
  console, please report results.
- **One tag.** Only `0xADF305F0` (the 2.80 demo scheme) is emitted. This is the
  scheme the legacy templates used, and the one whose header carries no
  signature.
- **PSPemu/PBOOT is not implemented.** `--format pspemu` fails with a clear
  message rather than producing something untested.
- **`devkit_version` is a fixed 3.71.** The input ELF has no equivalent field
  and genuine modules vary widely, so it appears unconstrained.
- **At most four segments**, which is what a `~PSP` header can describe.

## Development

```sh
cargo test        # 127 tests: crypto vectors, format, property and CLI tests
cargo clippy --all-targets
```

The crypto layer is tested against published vectors (NIST SP 800-38A for AES,
RFC 4493 for CMAC, FIPS 180-1 for SHA-1) rather than against itself.

## License

MIT. See [LICENSE](LICENSE).

The KIRK constants are the long-published PSP keys found in every open-source
PSP tool and emulator.
