# UMD images

A PSP UMD image is ISO9660. Verified against *LEGO Batman: The Videogame* (`ULUS-10380`, 1,136,689,152 bytes).

## 1. Volume descriptors

```text
sector 16  type 0x01  primary volume descriptor
sector 17  type 0xFF  terminator
```

No Joliet, no Rock Ridge. Names are uppercase 8.3.

## 2. Primary volume descriptor

```text
0x00  u8      type               0x01
0x01  u8[5]   standard id        "CD001"
0x06  u8      version            0x01
0x08  u8[32]  system identifier  "PSP GAME"
0x28  u8[32]  volume identifier  often blank
0x50  u32×2   volume space size  both-endian, in blocks
0x80  u16×2   logical block size both-endian, 2048
0x9C  u8[34]  root directory record
```

```text
00008000: 0143 4430 3031 0100 5053 5020 4741 4d45  .CD001..PSP GAME
00008050: 1078 0800 0008 7810                      volume size, both-endian
```

`0x00087810` × 2048 = 1,136,689,152, the file size. `pspbuild` checks the volume size against the file length, since EG encrypts the volume.

Both-endian fields are stored little-endian then big-endian. `pspbuild` rejects the image if the halves disagree.

## 3. Directory records

```text
0x00  u8      record length       0 = pad to next sector
0x01  u8      extended attr length
0x02  u32×2   extent LBA          both-endian
0x0A  u32×2   data length         both-endian, bytes
0x12  u8[7]   recording date
0x19  u8      flags               bit 1 = directory
0x1A  u8      file unit size
0x1B  u8      interleave gap
0x1C  u16×2   volume sequence number
0x20  u8      name length
0x21  ...     name
```

- A zero length byte means padding to the next 2048-byte boundary, not end of directory.
- Names carry a `;1` suffix. `pspbuild` strips it and matches case-insensitively.
- `.` and `..` are the single bytes `0x00` and `0x01`, and are skipped.

## 4. Limits on untrusted input

| Bound | Value | Reason |
| --- | --- | --- |
| Directory depth | 16 | Cyclic records |
| Total entries | 200,000 | Bounded allocation |
| Directory extent | 16 MiB | Bounded allocation |
| Record length | ≥ 33, within extent | Out-of-bounds slices |
| Name length | Within record | Out-of-bounds slices |

## 5. PSP layout

```text
/UMD_DATA.BIN                disc identification
/PSP_GAME/PARAM.SFO          parameter table
/PSP_GAME/ICON0.PNG          XMB icon
/PSP_GAME/ICON1.PMF          animated icon
/PSP_GAME/PIC0.PNG           background overlay
/PSP_GAME/PIC1.PNG           background
/PSP_GAME/SND0.AT3           XMB audio (often absent)
/PSP_GAME/SYSDIR/EBOOT.BIN   encrypted module
/PSP_GAME/SYSDIR/BOOT.BIN    unencrypted module
/PSP_GAME/USRDIR/...         game data
```

Assets map one-to-one to PBP sections. `read_optional` distinguishes an absent file from an unreadable one.

### 5.1 `UMD_DATA.BIN`

48 bytes, pipe-separated:

```text
ULUS-10380|B9A094E266C83E96|0001|G
disc id    16 hex digits    ver  type
```

### 5.2 `PARAM.SFO`

A disc declares `CATEGORY=UG`. `build-eg` rewrites it to `EG`.

```text
BOOTABLE         1
CATEGORY         UG
DISC_ID          ULUS10380
DISC_NUMBER      1
DISC_TOTAL       1
DISC_VERSION     1.00
PARENTAL_LEVEL   4
PSP_SYSTEM_VER   4.05
REGION           32768
TITLE            LEGO® Batman™: The Videogame
```

This table round-trips byte for byte through `sfo::Sfo`.

### 5.3 `EBOOT.BIN`

A `~PSP` module under tag `0xC0CB167C`. `pspbuild` reads its header but does not decrypt it. See [KEYS.md §2](KEYS.md).

## 6. Memory

`Iso` is generic over `Read + Seek`. The directory tree is read on open; file contents on demand. Inspecting the 1.13 GB reference disc peaks under 3 MB resident. The CLI detects file type from a `FileFormat::detect_prefix()`-byte prefix.
