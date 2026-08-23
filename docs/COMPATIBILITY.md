# Compatibility

What has actually been tested, and what has not.

## 1. Hardware

| target | result |
| --- | --- |
| PSP Slim, official firmware | MG EBOOT boots — single **and** multi-segment |
| other PSP models | untested |
| other firmware revisions | untested |

A compressed, dynamically sized MG EBOOT built by this tool boots on a retail
PSP Slim running official firmware. That is one console. Nothing here should be
read as a claim about the whole PSP line.

Three boot tests, each answering something the others could not:

| build | what it established |
| --- | --- |
| AngleZero, `prx-encrypter/v1` | the format and header fields are right at all |
| AngleZero, `pspbuild/v1` | the re-keyed output is valid; `build-mg` works end to end |
| `APE ACADEMY 2` rebuilt here | **multi-segment modules load** — see [FORMAT.md §8a](FORMAT.md) |

The third is the one that closed a real open question. AngleZero has a single
segment, so no amount of testing it could say anything about `seg_size[1]`.
Rebuilding a genuine two-segment Sony module and booting it did.

Two header fields were isolated on that hardware by varying one at a time
against an otherwise byte-identical build:

- `mod_attribute` must have bit `0x0200` set, OR-ed into the module's own
  attributes, or the firmware refuses to load the module. What the bit means is
  not known.
- `seg_size` must be the segment's `p_filesz`, not `p_memsz`. Using `p_memsz`
  produced a hard crash.

See [FORMAT.md §8](FORMAT.md).

## 2. Emulator

Output is validated against PPSSPP's `PrxDecrypter`, an independent
implementation of the same format. It accepts the files and recovers the input
byte for byte.

```sh
scripts/cross-validate.sh /path/to/ppsspp /path/to/module.prx
```

PPSSPP acceptance is useful but not sufficient on its own — an emulator's
decryptor is more permissive than the firmware's loader. It is a necessary
check, not a passing grade.

## 3. Legacy tools

| tool | direction | status |
| --- | --- | --- |
| PSPSDK `PrxEncrypter` | its output → `pspbuild` | parsed, verified and decrypted correctly |
| PSPSDK `PrxEncrypter` | `pspbuild` output → it | not applicable; it has no decrypt mode |
| **Sony's own tooling** | its output → `pspbuild` | **fully verified and decrypted** |
| `ebootsigner` | either | not differential-tested |
| `sign_np` | either | not applicable; EG is unimplemented |

### 3.1 Against Sony

Retail Sony builds encrypted under `0xADF305F0` — the same tag this tool emits
— are the best fixtures available. `pspbuild` verifies them completely: header
SHA-1, both CMAC tags, and a full decrypt to a valid PSP module. Sony computed
those tags and this crate re-derived them, so passing means the KIRK container
and field layout agree with the real format rather than merely with themselves.

Re-encrypting each module reproduces Sony's `psp_size` exactly and matches
every header field the loader derives from the ELF. The two that differ are
explained in [FORMAT.md §8a](FORMAT.md).

`tests/genuine.rs` discovers whatever EBOOTs are present in `plans/` and
asserts *rules* derived from each module's own ELF rather than constants from
one file, so adding a fixture strengthens the checks without any edits. Two are
currently available (`APE ACADEMY 2`, `MotoGP`), and both confirm the same two
divergences.

A useful negative result: a downloadable **demo** is still `CATEGORY=MG` with
an empty `DATA.PSAR`. It is not an NPDRM container and carries no `NPUMDIMG`,
so it is no help to the EG work. See [EG.md §1.1](EG.md).

A fixture produced by the reference tool is checked into `tests/fixtures/` and
covered by `tests/compatibility.rs`, so foreign-file handling is a real test
rather than a self-consistency check.

`pspbuild` output is deliberately *not* byte-identical to `PrxEncrypter`
output, and cannot be: the legacy tool pads to a template's capacity and forges
a CMAC to match it. The comparison that matters is the logical one — same input
in, same module out — which is what the cross-validation covers.

## 4. Reproducibility

Output is deterministic. The per-module keys are derived from the payload
rather than randomly generated, so the same input always produces identical
bytes. This is a local design choice, not a format requirement; see
[KEYS.md §1](KEYS.md).

### 4.1 The derivation domain was bumped

The key-derivation domain is `pspbuild/v1`. It was `prx-encrypter/v1` until the
rename, and bumping it changed every output byte: rebuilding the AngleZero
EBOOT produces the same 431,844 bytes as before, of which 146,690 differ.

That is the expected signature of a re-key rather than a format change. Sizing
and structure are untouched — only the per-module keys, and therefore the
ciphertext, key block and hashes, are new. Confirmed by decrypting both builds:
the recovered payloads are byte-identical.

`prx::builder` pins the domain and its three derived keys in a test, so a future
accidental change fails loudly instead of silently producing a differently-keyed
build.

### 4.2 What this cost

Hardware validation does not carry across a domain bump: the boot test that
confirmed the old build said nothing about the new one. A fresh EBOOT was built
on `pspbuild/v1` and **booted on the retail Slim**, so the current output is
validated on its own terms rather than inheriting an older result.

Worth keeping in mind for the next bump. The independent checks — PPSSPP,
`verify`, round-tripping — all passed for the *old* build too, and they also
passed for builds the console rejected during header development. They are
necessary and not sufficient; only a boot test settles it.

## 5. Known limitations

- **One tag.** Only `0xADF305F0` is emitted. See [KEYS.md §2](KEYS.md).
- **At most four segments**, which is what a `~PSP` header can describe.
- **PSPemu/PBOOT is not implemented.** `--format pspemu` fails with a clear
  message rather than producing something untested.
- **The EG path is not implemented.** `build-eg` fails with a clear message.
  See [EG.md](EG.md).

## 6. Test coverage

```sh
cargo test                      # unit, property, CLI and compatibility tests
cargo clippy --all-targets
```

The crypto layer is tested against published vectors — NIST SP 800-38A for AES,
RFC 4493 for CMAC, FIPS 180-1 for SHA-1 — rather than against itself. Format
handling is covered by round-trip, corruption and truncation tests: every
single-byte corruption of a header must be caught, and truncating a container at
every possible length must not panic.
