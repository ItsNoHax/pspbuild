# Key and tag matrix

Four concepts get conflated in PSP tooling, and this project keeps them
deliberately distinct. Read this section before the tables.

| concept | what it is | example | represented by |
| --- | --- | --- | --- |
| **CATEGORY** | a routing decision — which security path the firmware runs | `MG`, `UG`, `EG`, `ME` | [`sfo::Category`](../src/sfo.rs) |
| **TAG** | a cryptographic format identifier stored in the file | `0xADF305F0` | [`psp::tag::TagInfo`](../src/psp/tag.rs) |
| **KEY** | actual cryptographic material | `KIRK1_KEY` | [`kirk::keys`](../src/kirk/keys.rs) |
| **FORMAT** | what a blob structurally is | PRX, NPUMDIMG, PGD | [`inspect::FileFormat`](../src/inspect.rs) |

They are not interchangeable. A category does not imply a tag; a tag selects a
key *slot* rather than being one; a format can appear under more than one
category. Treating "MG uses key X" as the whole story is exactly the confusion
this table exists to prevent.

## 1. Cryptographic operations — MG path

Every operation in the implemented pipeline, in the order it runs.

| # | operation | input | output | algorithm | key | KIRK cmd | source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | key stream expansion | tag seed, 0x90 bytes | 0x90-byte XOR mask | AES-128-CBC decrypt | KIRK 4/7 slot `0x60` | 7 | [`tag::expand_seed`](../src/psp/tag.rs) |
| 2 | key block unmask | on-disk key block | KIRK key block | XOR with (1) | — | — | [`psp::tag`](../src/psp/tag.rs) |
| 3 | header field cipher pass | 0x60-byte region | scrambled/unscrambled | AES-128-CBC | KIRK 4/7 slot `0x60` | 4 / 7 | [`psp::tag`](../src/psp/tag.rs) |
| 4 | per-module key wrap | derived AES + CMAC keys | wrapped key block | AES-128-CBC | `KIRK1_KEY` | 1 | [`kirk::commands`](../src/kirk/commands.rs) |
| 5 | payload encryption | gzip or raw module | ciphertext | AES-128-CBC, zero IV | per-module AES key | 1 | [`kirk::commands`](../src/kirk/commands.rs) |
| 6 | header MAC | KIRK header region | 16-byte tag | AES-CMAC | per-module CMAC key | 1 | [`crypto::cmac`](../src/crypto/cmac.rs) |
| 7 | data MAC | header + entire payload | 16-byte tag | AES-CMAC | per-module CMAC key | 1 | [`crypto::cmac`](../src/crypto/cmac.rs) |
| 8 | header integrity | 0x150-byte header | 20-byte digest | SHA-1, **unkeyed** | none | — | [`crypto::sha1`](../src/crypto/sha1.rs) |
| 9 | per-module key derivation | payload + size | 3 × 16-byte keys | SHA-1, truncated | domain string | — | [`prx::builder`](../src/prx/builder.rs) |

Two entries deserve emphasis:

- **(8) is unkeyed.** The header carries no signature. The would-be signature
  region at `0xD4..0x12C` is required to be all zero for this scheme. This is
  the fact that makes dynamic sizing possible at all — see
  [FORMAT.md §4](FORMAT.md).
- **(9) is a local choice, not a format requirement.** The per-module keys are
  wrapped with a published key and so provide no secrecy. Deriving them from
  the payload rather than randomly makes output reproducible. The domain string
  is `pspbuild/v1`; it feeds every output byte, so bumping it re-keys every
  build and discards any hardware validation done before it. A test pins both
  the string and the keys it derives, so that can only happen deliberately. See
  [COMPATIBILITY.md §4.1](COMPATIBILITY.md).

## 2. Tags

| tag | scheme | seed slot | KIRK 4/7 key | signature region | supported |
| --- | --- | --- | --- | --- | --- |
| `0xADF305F0` | 2.80 demo | `0x60` | slot `0x60` | must be zero | **yes** |
| `0xC0CB167C` | retail UMD `EBOOT.BIN` | — | — | — | no |
| `0x0DAA06F0` | `ME` PSOne classic launcher | — | — | — | no |
| `0xD91624F0` | — | — | — | differs | no |
| `0x457B1EF0` | — | — | — | differs | no |
| others | — | — | — | — | no |

The two middle rows were observed directly rather than taken from a list:
`0xC0CB167C` on a retail UMD's `EBOOT.BIN`, and `0x0DAA06F0` on the launcher
stub inside three PSOne classics. Both are recorded because knowing a tag
exists is useful even without the key material for it — `pspbuild` reads their
headers and reports their metadata, then refuses to decrypt.

Only `0xADF305F0` is emitted. It is the scheme the PSPSDK templates used and
the one whose header carries no signature. Other tags take different KIRK paths
and some genuinely do require a signature, so the reasoning in section 1 does
**not** transfer to them. An unrecognised tag is a clean error, never a
best-effort decryption under the wrong key.

## 3. Keys

| name | purpose | format | algorithm | source |
| --- | --- | --- | --- | --- |
| `KIRK1_KEY` | wraps the per-module keys in a CMD1 header | 16 bytes | AES-128 | published KIRK engine |
| KIRK 4/7 slot `0x4B` | tag key stream / cipher pass | 16 bytes | AES-128 | published KIRK engine |
| KIRK 4/7 slot `0x5D` | as above | 16 bytes | AES-128 | published KIRK engine |
| KIRK 4/7 slot `0x60` | used by tag `0xADF305F0` | 16 bytes | AES-128 | published KIRK engine |
| KIRK 4/7 slot `0x61` | as above | 16 bytes | AES-128 | published KIRK engine |
| per-module AES key | encrypts the payload | 16 bytes | AES-128 | derived, see (9) above |
| per-module CMAC key | authenticates header and data | 16 bytes | AES-CMAC | derived, see (9) above |

These are the long-published PSP keys present in every open-source PSP tool and
emulator. They are not secrets in any meaningful sense, but they are still key
material: **nothing in this crate prints key bytes**, at any verbosity, and a
CLI test asserts that verbose output does not leak them.

Only the key slots this tool needs are present. An unknown slot is an error
rather than a silent wrong-key operation.

## 4. EG path

Not established. See [EG.md](EG.md) for the open questions — NPDRM tags, per-title
key derivation, BB-MAC, BB-Cipher and the ECDSA parameters are all unknowns
pending fixtures, and are deliberately absent from the tables above rather than
guessed at.

The NPUMDIMG private key referenced in the project plan is **not** in this
repository and would need to be supplied.
