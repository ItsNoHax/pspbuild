# Compatibility

## 1. Hardware

| Target | MG | EG |
| --- | --- | --- |
| PSP Slim, official firmware | boots (single- and multi-segment) | boots (compressed and uncompressed) |
| PSP 3000, OFW 6.61 | used for the `DISC_ID` test ([PBP.md §3.2](PBP.md)) | untested |
| Other models / firmware | untested | untested |

SND0 audio ([AUDIO.md](AUDIO.md)):

| Target | Result |
| --- | --- |
| PSP Slim, 6.61 + ARK | an LP4 SND0 from an external encoder plays; `pspbuild`'s header is byte-identical to it |
| any | SND0 encoded by `pspbuild audio snd0`: **untested** |

### 1.1 MG boot tests

| Build | Establishes |
| --- | --- |
| AngleZero, key domain `prx-encrypter/v1` | Header format and fields |
| AngleZero, key domain `pspbuild/v1` | Current key derivation; `build-mg` end to end |
| `APE ACADEMY 2` rebuilt | Multi-segment modules ([FORMAT.md §8](FORMAT.md)) |

Header fields isolated on hardware: `mod_attribute` bit `0x0200` and `seg_size[0] = p_filesz` ([FORMAT.md §7–8](FORMAT.md)).

### 1.2 EG boot tests

A LEGO Batman UMD built with `build-eg`, on official firmware (NPDRM checks active):

| Container | Result |
| --- | --- |
| Uncompressed (1.14 GB) | boots, game runs |
| One byte flipped at `DATA.PSAR + 0xD8` (signature) | refused, `80010087` |
| Byte restored (`cmp`-identical to the first) | boots |
| Compressed (604 MB, 66% of blocks) | boots |

With the flipped byte, `pspbuild`'s verifier reports only the archive signature invalid, so the firmware verifies the NPUMDIMG signature. The compressed boot confirms the firmware's LZRC decoder accepts `pspbuild`'s encoder output.

Booting reads only some of the 34,689 blocks. `the_whole_image_reconstructs_and_parses` decodes every block and reparses the image.

## 2. Emulator

PPSSPP's `PrxDecrypter` decrypts `pspbuild` output to the original module:

```sh
scripts/cross-validate.sh /path/to/ppsspp [module.prx]
```

PPSSPP is more permissive than the firmware (it accepted builds the console rejected), so this check is necessary but not sufficient.

## 3. Reference tools and Sony files

| Source | Direction | Result |
| --- | --- | --- |
| PSPSDK `PrxEncrypter` | its output → `pspbuild` | verified, decrypted (`tests/compatibility.rs`) |
| Sony MG builds (`APE ACADEMY 2`, `MotoGP`) | → `pspbuild` | verified, decrypted; re-encryption matches `psp_size` and derived fields (`tests/genuine.rs`) |
| `sign_np` | EG output compared | section offsets and size match with `--no-compress` (`tests/archive.rs`) |
| Sony EG archives (4) | → `pspbuild` | signatures verify; fixed-key archive fully recomputed ([NPUMDIMG.md §7](NPUMDIMG.md)) |
| `ebootsigner` | — | not tested |
| Sony SND0 (LP2, 3 connection apps) | → `pspbuild` | playable, 3 warnings; decoder agrees with ffmpeg to 131 dB (`tests/audio.rs`) |
| Known-good LP4 SND0 | → `pspbuild` | passes strict; fmt chunk identical to `pspbuild`'s |
| ffmpeg | `pspbuild` SND0 → ffmpeg | decodes identically to `pspbuild`'s decoder (~132 dB) |

`pspbuild` MG output is not byte-identical to `PrxEncrypter` output by design ([FORMAT.md §5](FORMAT.md)).

## 4. Reproducibility

- MG output is deterministic: per-module keys are derived from the payload with domain `pspbuild/v1`.
- EG output is not: `header_key` and header padding are random.

Changing the key domain changes every ciphertext byte without changing structure. The rename from `prx-encrypter/v1` changed 146,690 of 431,844 bytes in the AngleZero EBOOT; both builds decrypt to the same payload, and the new build was boot-tested separately.

## 5. Limitations

- One PRX tag, `0xADF305F0` ([KEYS.md §2](KEYS.md)).
- At most four segments.
- EG: fixed-key content IDs only; supplied version keys are not supported.
- EG: `STARTDAT` and `OPNSSMP` are not boot-tested.
- PSPemu / `PBOOT.PBP` is out of scope.
- SND0: encoder output not yet played on hardware; no gain control (transients may pre-echo); no AAC/M4A or Opus input.

## 6. Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check licenses
```

- Crypto: NIST SP 800-38A (AES), RFC 4493 (CMAC), FIPS 180-1 (SHA-1).
- Format: round-trip, every single-byte header corruption detected, truncation at every length without panic.
- Fixture tests (`genuine`, `iso`, `npdrm`, `archive`) skip when fixtures are absent; see the [README](../README.md#development).
- Audio (`audio`, `audio_cli`): golden tests against Sony and known-good SND0s, negative tests per validator rule, quality floors on four test signals, and ffmpeg as an optional oracle.

CI runs build and tests on Linux, macOS and Windows, plus `cargo fmt --check`, clippy with `-D warnings`, and `cargo deny check licenses`.
