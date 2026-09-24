# NPUMDIMG

The archive in an EG `DATA.PSAR`: a UMD image split into fixed-size blocks, each encrypted and MAC'd, behind a signed 256-byte header.

Derived from `sign_np` output and `sign_np.h`, then checked against four genuine Sony Store archives (§7). Implemented in [`src/npdrm`](../src/npdrm).

## 1. Layout

```text
0x000               header         256 bytes
0x100               block table    iso_blocks × 0x20
0x100 + table_size  blocks
```

```text
block_size = block_basis × 2048 = 32768   (block_basis = 0x10)
iso_blocks = ceil(iso_size / block_size)
table_size = iso_blocks × 0x20
```

Uncompressed reference:

| Quantity | Value |
| --- | ---: |
| ISO size | 1,136,689,152 |
| `iso_blocks` | 34,689 |
| `table_size` | 1,110,048 |
| `DATA.PSAR` | 1,137,799,456 = `0x100 + table_size + ISO size` |

## 2. Header

Offsets are absolute within `DATA.PSAR`.

```text
0x00  u8[8]   magic        "NPUMDIMG"
0x08  u32     np_flags
0x0C  u32     block_basis  0x10
0x10  u8[48]  content_id   ASCII, NUL-padded
0x40  u8[96]  body         BB-Cipher encrypted (§2.2)
0xA0  u8[16]  header_key
0xB0  u8[16]  data_key
0xC0  u8[16]  header_hash  BB-MAC over 0x00..0xC0
0xD0  u8[8]   padding      random
0xD8  u8[40]  ecdsa_sig    R || S over SHA-1(0x00..0xD8)
```

```text
00000000: 4e50 554d 4449 4d47 0300 0001 1000 0000  NPUMDIMG........
00000010: 554c 3030 3030 2d55 4c55 5331 3033 3830  UL0000-ULUS10380
00000020: 5f30 302d 3030 3030 3030 3030 3030 3030  _00-000000000000
00000030: 3030 3030 0000 0000 0000 0000 0000 0000  0000............
```

### 2.1 `np_flags`

| Bits | Meaning |
| --- | --- |
| `0x01000000` | Derive the version key from the content ID |
| low byte | Derivation variant, 1–3 |

| Value | Meaning | Seen in |
| --- | --- | --- |
| `0x01000003` | Fixed key, variant 3 | Sony (1 archive), `pspbuild` |
| `0x00000003` | Supplied key | Sony (3 archives) |
| `0x00000002` | Supplied key | `sign_np` only |

### 2.2 Body (`0x40..0xA0`)

Field names from `sign_np.h`.

| Offset | Field | Value |
| --- | --- | --- |
| 0x40 | `sector_size` u16 | `0x0800` |
| 0x42 | `unk_2` u16 | `0xE001` if image > 1 GiB, else `0xE000` |
| 0x44 | `unk_4` u32 | 0 |
| 0x48 | `unk_8` u32 | `0x1010` |
| 0x4C | `unk_12` u32 | 0 |
| 0x50 | `unk_16` u32 | 0 |
| 0x54 | `lba_start` u32 | 0 |
| 0x58 | `unk_24` u32 | 0 |
| 0x5C | `nsectors` u32 | `min(lba_end, 0x6C0BF)` |
| 0x60 | `unk_32` u32 | 0 |
| 0x64 | `lba_end` u32 | `iso_blocks × block_basis − 1` |
| 0x68 | `unk_40` u32 | `0x01003FFE` |
| 0x6C | `block_entry_offset` u32 | `0x100` |
| 0x70 | `disc_id` char[16] | e.g. `ULUS-10380` |
| 0x80 | `header_start_offset` u32 | 0 |
| 0x84–0x9F | `unk_68`…`unk_92`, `bbmac_param` | 0 |

- **`nsectors`** saturates at `0x6C0BF` (single-layer UMD capacity, 864 MiB). `lba_end` does not. Reference (1.08 GiB): `lba_end` 555,023, `nsectors` 442,559. `NPJH90232` (191 MiB): both 97,903.
- **`unk_2`** is a size flag, not a compression flag. `NPJH90232` is compressed and has `0xE000`.
- **`disc_id`** is `content_id[7..11] + "-" + content_id[11..16]`, matching `UMD_DATA.BIN` ([ISO.md §5.1](ISO.md)).
- `unk_8` and `unk_40` match Sony's archives; their meaning is unknown.

## 3. Header crypto

1. Write the header with `header_key` and `data_key`; `header_hash` zero.
2. Fill `padding` (0xD0, 8 bytes) with random bytes.
3. BB-Cipher **type 1, mode 2** over `0x40..0xA0`, `header_key` + `version_key`, seed 0.
4. BB-MAC **type 3** over `0x00..0xC0`, keyed by `version_key` → `header_hash`.
5. SHA-1 over `0x00..0xD8`.
6. ECDSA-sign with the NPUMDIMG private key → `0xD8` as `R || S`.

Notes:

- The digest is not length-prefixed. The 4-byte `0xD8` prefix in `sign_np`'s buffer is a KIRK command header. Only the unprefixed digest verifies Sony's signatures.
- Type 2 of either primitive needs KIRK command 5 (fuse-ID key) and cannot run off-console. Mode 1 generates `header_key` rather than accepting one.
- Because `header_key` and `padding` are random, two builds differ in `0x40..0xFF` and every block. Tests compare decrypted fields and geometry instead of bytes.

## 4. Keys

| Key | Size | Origin |
| --- | --- | --- |
| `version_key` | 16 | Supplied, or derived from `content_id` and `np_flags` |
| `header_key` | 16 | Random per build |
| `data_key` | 16 | BB-MAC type 3 over the finished block table, keyed by `version_key` |
| NPUMDIMG private | 20 | Published |
| NPUMDIMG public | 40 | Published, `x \|\| y` |

`data_key` depends on every block, so the header is finalised last.

### 4.1 Fixed key (`sceNpDrmGetFixedKey`)

```text
key = BB-MAC type 1 over content_id NUL-padded to 0x30, finalised with NPDRM_FIXED_KEY
key = AES-ECB(NPDRM_ENC_KEYS[(np_flags & 0xFF) - 1], key)   if low byte is 1..=3
```

Implemented in [`npdrm::fixed_key`](../src/npdrm/fixed_key.rs). Verified against `sign_np`'s reported key and by authenticating real headers.

### 4.2 Primitives

| Primitive | Construction |
| --- | --- |
| BB-MAC | AES-CMAC (RFC 4493) under KIRK slot `0x38`, then up to two block encryptions |
| BB-Cipher | Counter-mode keystream (slots `0x39`, `0x63`); self-inverse; seed is the data's position |

`sign_np`'s `sceDrmBBMacUpdate` drops 16 buffered bytes when its buffer is exactly full and the next update is ≤ 16 bytes. NPUMDIMG is unaffected (one update per MAC). `pspbuild` does not reproduce the bug; a test records it.

### 4.3 ECDSA curve

```text
p = FFFFFFFF FFFFFFFF 00000001 FFFFFFFF FFFFFFFF
a = p - 3
b = A68BEDC3 3418029C 1D3CE33B 9A321FCC BB9E0F0B
n = FFFFFFFF FFFFFFFE FFFFB5AE 3C523E63 944F2127
G = (128EC425 6487FD8F DF64E243 7BC0A1F6 D5AFDE2C,
     5958557E B1DB0012 60425524 DBC379D5 AC5F4ADF)
```

Tests check `a = p − 3`, `G` on the curve, `nG = O`, and private × `G` = public. Signatures are standard ECDSA; `R` and `S` are 20-byte big-endian. KIRK commands 12, 13, 16 and 17 use this curve; command 1 uses different `b`, `n`, `G` over the same `p`.

`sign_np` wraps the private key with `encrypt_kirk16_private` before signing and KIRK unwraps it; off-console these cancel. `pspbuild` signs with the plain scalar.

## 5. Block table

One 0x20-byte entry per block at `0x100`:

```text
0x00  u8[16]  mac     BB-MAC type 3 of the encrypted block, version_key
0x10  u32     offset  within DATA.PSAR
0x14  u32     size    stored size
0x18  u32     0
0x1C  u32     0
```

Each entry is then obfuscated in place (self-inverse, keyless):

```c
k0 = p[0]^p[1];  k1 = p[1]^p[2];
k2 = p[0]^p[3];  k3 = p[2]^p[3];
p[4] ^= k3;  p[5] ^= k1;  p[6] ^= k2;  p[7] ^= k0;
```

## 6. Blocks

For each block:

1. Read `block_size` bytes; zero-pad the last.
2. LZRC-compress. Keep it if under 90% of `block_size` (`RATIO_LIMIT`); round up to 16 bytes.
3. BB-Cipher type 1, mode 2, `header_key` + `version_key`, seed `offset >> 4`.
4. BB-MAC type 3 into the table entry.
5. Write, padded to 16 bytes.

A block is compressed iff its `size < block_size`. The header has no archive-wide compression flag.

Compression ratio on Sony's `NPJH90232` blocks: 30.6% (Sony: 30.7%). Only the decoder is fixed by the format; `pspbuild`'s encoder keeps the whole block addressable, where `sign_np` uses a 65,280-byte window.

## 7. Validation against Sony

Four genuine Store archives:

| Content ID | `np_flags` | Key |
| --- | --- | --- |
| `JP0177-NPJH90121_00-PS3DIVADLCDTC001` | `0x00000003` | supplied |
| `JP0177-NPJH90213_00-HMPDDT2CA0000000` | `0x00000003` | supplied |
| `JP0177-NPJH90292_00-HMPDDTEXCA000000` | `0x00000003` | supplied |
| `JP0082-NPJH90232_00-0000000000000000` | `0x01000003` | fixed |

| Claim | Evidence |
| --- | --- |
| Curve, key, signature encoding | All four signatures verify |
| Signed range `0x00..0xD8`, no prefix | Same; prefixed digest fails |
| Fixed-key derivation | `NPJH90232` header authenticates |
| BB-MAC, BB-Cipher, header hash | `NPJH90232` `header_hash` recomputes |
| Block table and obfuscation | 6,119 entries form a contiguous map |
| `data_key` | Recomputes |
| Block MACs, LZRC decoder | All blocks decrypt; 4,216 compressed blocks expand to 32,768 bytes; image parses as ISO9660 |

## 8. Unknowns

- Whether the zero body fields are required.
- Meaning of `unk_8` and `unk_40`.
- Supplied-key archives can be verified but not decrypted without `KEYS.BIN`.
