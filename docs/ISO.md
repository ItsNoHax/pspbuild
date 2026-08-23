# PSP UMD images

A PSP game disc image is plain ISO9660. Everything here was verified against a
retail UMD: *LEGO Batman: The Videogame* (`ULUS-10380`), 1,136,689,152 bytes.

## 1. What a UMD uses, and what it does not

The volume descriptor set is short:

```text
sector 16   type 0x01   primary volume descriptor
sector 17   type 0xFF   terminator
```

That is the whole set. There is **no Joliet supplementary descriptor** and no
Rock Ridge, so the primary descriptor and its uppercase 8.3 names are all a
reader needs. This is why `pspbuild`'s reader is as small as it is — the
features that make general-purpose ISO9660 readers complicated are simply not
present.

## 2. Primary volume descriptor

```text
0x00  u8      type              0x01
0x01  u8[5]   standard id       "CD001"
0x06  u8      version           0x01
0x08  u8[32]  system identifier "PSP GAME"
0x28  u8[32]  volume identifier often blank
0x50  u32×2   volume space size both-endian, in logical blocks
0x80  u16×2   logical block size both-endian, always 2048
0x9C  u8[34]  root directory record
```

From the retail disc:

```text
00008000: 0143 4430 3031 0100 5053 5020 4741 4d45  .CD001..PSP GAME
...
00008050: 1078 0800 0008 7810                      volume size, both-endian
```

`0x00087810` = 555,024 blocks × 2048 = 1,136,689,152 bytes, which is exactly the
file size. That agreement matters: the EG pipeline encrypts *the volume*, so an
image whose descriptor disagrees with its own length would produce an archive
covering the wrong number of sectors. `pspbuild` has a test asserting it.

### 2.1 Both-endian fields

ISO9660 stores its integers twice, little-endian then big-endian. `pspbuild`
reads both halves and rejects the image if they disagree, rather than trusting
the little-endian one. A reader that ignores the big-endian copy will silently
accept a corrupted descriptor.

## 3. Directory records

```text
0x00  u8      record length          0 means "pad to the next sector"
0x01  u8      extended attr length
0x02  u32×2   extent LBA             both-endian
0x0A  u32×2   data length            both-endian, in bytes
0x12  u8[7]   recording date
0x19  u8      flags                  bit 1 set = directory
0x1A  u8      file unit size
0x1B  u8      interleave gap
0x1C  u16×2   volume sequence number
0x20  u8      name length
0x21  ...     name
```

Three behaviours a reader has to get right:

- **A zero length byte is padding, not an end.** Records never straddle a
  sector, so a directory extent pads with zeros to the next 2048 boundary and
  continues. Treating zero as "end of directory" truncates the listing.
- **Names carry a `;1` version suffix.** `EBOOT.BIN;1` and `EBOOT.BIN` are the
  same file. `pspbuild` strips the suffix and matches case-insensitively.
- **`.` and `..` are one-byte names of `0x00` and `0x01`.** Skipping `..` is
  also what stops a recursive walk from looping forever.

## 4. Hostile and malformed images

The reader is given files it did not create, so the walk is bounded on every
axis that an image can lie about:

| bound | value | why |
| --- | --- | --- |
| directory depth | 16 | a record can point at its own parent, describing a cycle |
| total entries | 200,000 | otherwise a corrupt extent dictates the allocation |
| directory extent | 16 MiB | same |
| record length | ≥ 33 and within the extent | a short record would slice out of bounds |
| name length | must fit inside its record | a 255-byte name in a 34-byte record would not |

A one-byte record length cannot exceed a 2048-byte extent on its own, so the
extent-overrun check only fires on a densely packed directory. It is tested by
shrinking the root extent rather than by pretending the common case triggers it.

## 5. The PSP layout

```text
/UMD_DATA.BIN                    disc identification
/PSP_GAME/PARAM.SFO              parameter table
/PSP_GAME/ICON0.PNG              XMB icon
/PSP_GAME/ICON1.PMF              animated icon
/PSP_GAME/PIC0.PNG               background, upper layer
/PSP_GAME/PIC1.PNG               background
/PSP_GAME/SND0.AT3               XMB audio            often absent
/PSP_GAME/SYSDIR/EBOOT.BIN       the encrypted module
/PSP_GAME/SYSDIR/BOOT.BIN        its unencrypted twin
/PSP_GAME/USRDIR/...             game data
```

Assets map one-to-one onto PBP sections, which is what the EG pipeline needs
them for. `SND0.AT3` is missing from the reference disc, so "absent" is a normal
result and the reader distinguishes it from "unreadable" with a separate
`read_optional`.

### 5.1 `UMD_DATA.BIN`

48 bytes, pipe-separated:

```text
ULUS-10380|B9A094E266C83E96|0001|G
   disc id      16 hex digits  ver  type
```

### 5.2 `PARAM.SFO` on a disc

A UMD's category is **`UG`** — UMD Game — not `MG` or `EG`. Neither of the two
security paths applies to the disc itself; `EG` is what the *output* of a
conversion declares. This is exactly the distinction
[KEYS.md](KEYS.md) opens with: a category is a routing decision, and the routing
for a disc is different from the routing for a repackaged download.

The retail table, read by `pspbuild inspect`:

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

It re-emits byte for byte through `sfo::Sfo`, non-ASCII title included. That is
the strongest check the `PARAM.SFO` code gets, because the input is a table Sony
produced rather than one this crate generated — see [PBP.md §4.1](PBP.md) for
why preserving each entry's reserved size is what makes it possible.

### 5.3 `EBOOT.BIN`

The retail `EBOOT.BIN` is a `~PSP` encrypted module, but under tag
`0xC0CB167C`, not the `0xADF305F0` this tool emits. `pspbuild` reads its header
and reports its metadata, and **refuses to decrypt it** rather than attempting
the one key it holds against a scheme that does not use it. See
[KEYS.md §2](KEYS.md).

## 6. Memory

A UMD runs to 1.8 GB, so the reader never loads one. The directory tree is read
at open time and file contents on demand; `Iso` is generic over
`Read + Seek`. Inspecting the 1.13 GB reference disc peaks at under 3 MB of
resident memory.

The CLI classifies a file by reading only `FileFormat::detect_prefix()` bytes —
enough to reach the `CD001` at sector 16 — so it never has to read a file to
find out whether it is too big to read.
