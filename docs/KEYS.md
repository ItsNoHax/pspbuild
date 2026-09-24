# Categories, tags and keys

| Concept | Meaning | Example | Type |
| --- | --- | --- | --- |
| Category | Security path the firmware runs | `MG`, `UG`, `EG`, `ME` | [`sfo::Category`](../src/sfo.rs) |
| Tag | Crypto scheme identifier in a `~PSP` header | `0xADF305F0` | [`psp::tag::TagInfo`](../src/psp/tag.rs) |
| Key | Key material | `KIRK1_KEY` | [`kirk::keys`](../src/kirk/keys.rs) |
| Format | Structure of a blob | PRX, NPUMDIMG, PGD | [`inspect::FileFormat`](../src/inspect.rs) |

A category does not imply a tag, a tag selects a key slot, and a format can appear under several categories.

## 1. MG operations

In execution order.

| # | Operation | Algorithm | Key | KIRK | Source |
| --- | --- | --- | --- | --- | --- |
| 1 | Key stream expansion (0x90 bytes) | AES-128-CBC decrypt | slot `0x60` | 7 | [`psp::tag`](../src/psp/tag.rs) |
| 2 | Key block unmask | XOR with (1) | — | — | [`psp::tag`](../src/psp/tag.rs) |
| 3 | Header field cipher (0x60 bytes) | AES-128-CBC | slot `0x60` | 4/7 | [`psp::tag`](../src/psp/tag.rs) |
| 4 | Per-module key wrap | AES-128-CBC | `KIRK1_KEY` | 1 | [`kirk::commands`](../src/kirk/commands.rs) |
| 5 | Payload encryption | AES-128-CBC, zero IV | per-module AES | 1 | [`kirk::commands`](../src/kirk/commands.rs) |
| 6 | Header MAC | AES-CMAC | per-module CMAC | 1 | [`crypto::cmac`](../src/crypto/cmac.rs) |
| 7 | Data MAC | AES-CMAC | per-module CMAC | 1 | [`crypto::cmac`](../src/crypto/cmac.rs) |
| 8 | Header digest | SHA-1, unkeyed | — | — | [`crypto::sha1`](../src/crypto/sha1.rs) |
| 9 | Per-module key derivation | SHA-1, truncated | domain `pspbuild/v1` | — | [`prx::builder`](../src/prx/builder.rs) |

- (8): the header is unsigned; `0xD4..0x12C` must be zero ([FORMAT.md §4](FORMAT.md)).
- (9): deriving keys from the payload makes output deterministic. Changing the domain string re-keys every build and invalidates prior hardware results; a test pins the string and its outputs.

## 2. Tags

| Tag | Scheme | Key slot | Signature region | Supported |
| --- | --- | --- | --- | --- |
| `0xADF305F0` | 2.80 demo | `0x60` | zero | **yes** |
| `0xC0CB167C` | Retail UMD `EBOOT.BIN` | — | — | read header only |
| `0x0DAA06F0` | `ME` PSOne launcher | — | — | read header only |
| `0xD91624F0` | — | — | non-zero | no |
| `0x457B1EF0` | — | — | non-zero | no |

Only `0xADF305F0` is emitted or decrypted. An unknown tag is an error.

## 3. MG keys

| Name | Use | Size | Source |
| --- | --- | --- | --- |
| `KIRK1_KEY` | Wraps per-module keys | 16 | KIRK engine |
| KIRK 4/7 slots `0x4B`, `0x5D`, `0x60`, `0x61` | Tag key stream / cipher | 16 each | KIRK engine |
| Per-module AES key | Payload encryption | 16 | Derived (§1, 9) |
| Per-module CMAC key | Header and data MAC | 16 | Derived (§1, 9) |

Key bytes are never printed at any verbosity; a CLI test enforces this. Unknown slots are errors.

## 4. EG (AMCTRL / NPDRM)

### 4.1 Operations

| Step | Operation | Key |
| --- | --- | --- |
| Header body | BB-Cipher type 1 mode 2, seed 0 | `header_key` ⊕ `version_key` |
| Block data | BB-Cipher type 1 mode 2, seed `offset >> 4` | `header_key` ⊕ `version_key` |
| Header hash | BB-MAC type 3 over `0x00..0xC0` | `version_key` |
| Block MAC | BB-MAC type 3 over encrypted block | `version_key` |
| `data_key` | BB-MAC type 3 over block table | `version_key` |
| `version_key` | BB-MAC type 1 over padded content ID, then AES | `NPDRM_FIXED_KEY`, `NPDRM_ENC_KEYS[n]` |
| Header signature | ECDSA over SHA-1(`0x00..0xD8`) | NPUMDIMG private key |
| `DATA.PSP` signature | ECDSA over `PARAM.SFO` \|\| content ID | NPUMDIMG private key |

See [NPUMDIMG.md](NPUMDIMG.md).

### 4.2 Keys

| Key | Use | Size | Source |
| --- | --- | --- | --- |
| KIRK 4/7 slot `0x38` | BB-MAC cipher | 16 | KIRK engine |
| KIRK 4/7 slot `0x39` | BB-Cipher key derivation | 16 | KIRK engine |
| KIRK 4/7 slot `0x63` | BB-Cipher keystream | 16 | KIRK engine |
| `AMCTRL_KEY1`–`3` | XOR whitening constants (not AES keys) | 16 each | AMCTRL |
| `NPDRM_FIXED_KEY` | Fixed-key BB-MAC finalisation | 16 | AMCTRL |
| `NPDRM_ENC_KEYS[0..3]` | Fixed-key final AES step | 3 × 16 | AMCTRL |
| `NPUMDIMG_PRIVATE_KEY` | ECDSA signing | 20 | Published |
| `NPUMDIMG_PUBLIC_KEY` | ECDSA verification, `x \|\| y` | 40 | Published |
| `version_key` | Content key | 16 | Derived (fixed-key) or supplied |
| `header_key` | Archive cipher key | 16 | Random per build |
| `data_key` | Block table commitment | 16 | Computed |

A test checks that the private key times the base point equals the public key.

BB-MAC type 2 and BB-Cipher type 2 are not implemented: they use KIRK command 5, keyed by the console's fuse ID.

All keys here are long-published. Signing code is not constant-time; see [`crypto::ec`](../src/crypto/ec.rs).
