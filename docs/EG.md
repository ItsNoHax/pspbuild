# EG pipeline

`CATEGORY=EG`: a PSP UMD image repackaged as a signed NPDRM `EBOOT.PBP`, the format of PSP Store downloads and `sign_np` output.

```console
$ pspbuild build-eg game.iso --content-id UL0000-ULUS10380_00-0000000000000000
Title:               LEGO® Batman™: The Videogame
Content ID:          UL0000-ULUS10380_00-0000000000000000
Image size:          1136689152 bytes
Blocks:              34689 of 32768 bytes, 22934 (66%) compressed
DATA.PSAR:           603135408 bytes
Wrote EBOOT.PBP (603693744 bytes)
```

Status:

- Boots on a retail PSP Slim on official firmware, compressed and uncompressed. A one-byte signature corruption is refused ([COMPATIBILITY.md §1.1](COMPATIBILITY.md)).
- With `--no-compress`, section offsets and total size match `sign_np`; only fields the format requires to be random differ.
- Format checked against four genuine Sony Store archives ([NPUMDIMG.md §7](NPUMDIMG.md)).

## 1. Container

```text
PARAM.SFO   disc's own, CATEGORY UG → EG
ICON0.PNG   \
ICON1.PMF    |
PIC0.PNG     |  copied from /PSP_GAME when present
PIC1.PNG     |
SND0.AT3    /
DATA.PSP    signed licence stub (+ STARTDAT, OPNSSMP)
DATA.PSAR   NPUMDIMG archive of the whole image, 0x100-aligned
```

PBP version is `0x00010001`.

## 2. Pipeline

```text
UMD image
 └─ ISO9660 reader          PARAM.SFO, media, disc ID
     └─ blocks              32 KiB, optional LZRC, BB-Cipher, BB-MAC
         └─ block table     per-block MAC, offset, size; obfuscated
             └─ data_key    BB-MAC over the finished table
                 └─ header  BB-Cipher body, BB-MAC hash, ECDSA signature
                     └─ DATA.PSAR
DATA.PSP                    ECDSA over PARAM.SFO || content_id
EBOOT.PBP                   CATEGORY=EG
```

Order constraints:

- `PARAM.SFO` is relabelled before `DATA.PSP` is signed, since the signature covers it.
- `DATA.PSAR` is streamed; a 1 GiB image is not held in memory.

## 3. Identifying an EG EBOOT

An EG container has all of:

- `PARAM.SFO` with `CATEGORY=EG`
- `DATA.PSAR` starting with `NPUMDIMG`
- `DATA.PSP` that is an NPDRM stub, not a `~PSP` PRX

| File | Category | Why it is not EG |
| --- | --- | --- |
| Downloadable demo (`APE ACADEMY 2`, `MotoGP`) | `MG` | Plain encrypted PRX, empty `DATA.PSAR` |
| Firmware update (`661.PBP`) | `MG` | `DATA.PSAR` is an update archive |
| UMD ISO | `UG` | Not a PBP |
| PSOne classic | `ME` | `DATA.PSAR` is `PSISOIMG0000` |

`pspbuild inspect` shows both: `Category: EG` and a `DATA.PSAR` row identified as `NPUMDIMG`.

## 4. `DATA.PSP`

| Part | Offset | Contents | Source |
| --- | --- | --- | --- |
| Licence stub | 0 | Signature, content ID, `np_flags`, zeros; 0x594 bytes | [`npdrm::data_psp`](../src/npdrm/data_psp.rs) |
| `STARTDAT` | `0x594 + 0xC` | Boot-screen PNG behind a 0x50-byte header | [`npdrm::startdat`](../src/npdrm/startdat.rs) |
| `OPNSSMP` | recorded at `0x30` | Module in a PGD container | [`npdrm::pgd`](../src/npdrm/pgd.rs) |

`STARTDAT` fields match all four Sony containers. The PGD header and its DNAS MAC (BB-MAC type 1, published key) verify on the three Sony containers that carry `OPNSSMP`.

The `OPNSSMP` body key is not established: Sony's samples are supplied-key titles and cannot be decrypted, and `sign_np` uses a random, unstored key. `pspbuild` uses the archive's version key.

## 5. Keys

- `--content-id` sets the content ID and, for fixed-key titles, derives the version key ([NPUMDIMG.md §4.1](NPUMDIMG.md)). It must match the ID the container will be distributed under.
- `header_key` and header padding are random per build, so output is not byte-reproducible.
- Supplied version keys (`KEYS.BIN`, bound to a Store account) are not supported.

## 6. Separation from MG

MG and EG share the PBP container and KIRK primitives only. `Pbp::require_category` prevents either pipeline from running on the other's container.

## 7. Open items

- Hardware coverage: one console, one firmware, one disc.
- Supplied version keys.
- No container with `STARTDAT` or `OPNSSMP` has been boot-tested.
