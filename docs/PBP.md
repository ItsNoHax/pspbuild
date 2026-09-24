# PBP container and `PARAM.SFO`

`EBOOT.PBP` is the file the XMB launches: a 0x28-byte offset table followed by eight concatenated sections. Byte dumps below are from a homebrew EBOOT that boots on a retail PSP Slim.

## 1. Header

```text
0x00  u8[4]  magic      00 50 42 50   "\0PBP"
0x04  u32    version    0x00010000 (MG), 0x00010001 (EG)
0x08  u32    offset[0]  PARAM.SFO
0x0C  u32    offset[1]  ICON0.PNG
0x10  u32    offset[2]  ICON1.PMF
0x14  u32    offset[3]  PIC0.PNG
0x18  u32    offset[4]  PIC1.PNG
0x1C  u32    offset[5]  SND0.AT3
0x20  u32    offset[6]  DATA.PSP
0x24  u32    offset[7]  DATA.PSAR
0x28         section data
```

```text
00000000: 0050 4250 0000 0100 2800 0000 4801 0000   .PBP....(...H...
00000010: 6a44 0000 6a44 0000 6a44 0000 58cf 0100   jD..jD..jD..X...
00000020: d456 0400 e496 0600                       .V......
```

### 1.1 Section lengths

There is no length field. A section runs from its offset to the next section's offset; the last runs to end of file.

- An empty section has the same offset as the next one (`PIC0.PNG` above).
- Trailing bytes become part of `DATA.PSAR`.
- Offsets must be non-decreasing. `pspbuild` rejects a table that goes backwards.

### 1.2 Alignment

The container imposes none; sections are packed back to back. EG containers align `DATA.PSAR` to 0x100 (see [EG.md](EG.md)).

## 2. Sections

| # | Name | Contents | Required |
| --- | --- | --- | --- |
| 0 | `PARAM.SFO` | Parameter table (§3) | yes |
| 1 | `ICON0.PNG` | XMB icon, 144×80 | no |
| 2 | `ICON1.PMF` | Animated icon (PSMF) | no |
| 3 | `PIC0.PNG` | Background overlay | no |
| 4 | `PIC1.PNG` | Background, 480×272 | no |
| 5 | `SND0.AT3` | Background audio (RIFF/AT3) | no |
| 6 | `DATA.PSP` | Executable | yes |
| 7 | `DATA.PSAR` | Data archive | EG/ME |

`DATA.PSP` and `DATA.PSAR` depend on `CATEGORY`:

| Category | Kind | `DATA.PSP` | `DATA.PSAR` |
| --- | --- | --- | --- |
| `MG` | Homebrew, demos | Encrypted `~PSP` PRX ([FORMAT.md](FORMAT.md)) | empty |
| `EG` | PSP game from the Store | NPDRM licence stub | `NPUMDIMG` |
| `ME` | PSOne classic | NPDRM licence stub | `PSISOIMG0000` |

`UG` is the category inside a retail UMD's own `PARAM.SFO`; it never appears in a PBP.

## 3. `PARAM.SFO`

Key/value table. `CATEGORY` selects the security path.

```text
0x00  u8[4]  magic             00 50 53 46   "\0PSF"
0x04  u32    version           0x00000101
0x08  u32    key_table_start
0x0C  u32    data_table_start
0x10  u32    entry_count
0x14         index[entry_count]
```

Index entry, 16 bytes:

```text
0x00  u16  key_offset    relative to key_table_start
0x02  u16  format        0x0004 raw, 0x0204 UTF-8, 0x0404 u32
0x04  u32  data_len      bytes used, including NUL for strings
0x08  u32  data_max_len  bytes reserved
0x0C  u32  data_offset   relative to data_table_start
```

```text
00000000: 0050 5346 0101 0000 9400 0000 e800 0000   .PSF............
00000010: 0800 0000 0000 0404 0400 0000 0400 0000   ................
00000020: 0000 0000 0900 0402 0300 0000 0400 0000   ................
```

### 3.1 Layout rules

- Entries are sorted by key; index, key table and data table share that order.
- Keys are NUL-terminated. The key table is NUL-padded so the data table is 4-byte aligned.
- Each value occupies `data_max_len` bytes.
- `data_max_len` is chosen by the writer and cannot be derived from the value (`"MG\0"` is 3 bytes in a 4-byte slot; `TITLE` reserves 128). `pspbuild` preserves it so tables round-trip byte for byte.

### 3.2 MG keys

| Key | Format | Value | Notes |
| --- | --- | --- | --- |
| `BOOTABLE` | u32 | 1 | Required to launch |
| `CATEGORY` | UTF-8 | `MG` | |
| `DISC_ID` | UTF-8 | `UCJS10041` | Required; 12-byte slot |
| `DISC_VERSION` | UTF-8 | `1.00` | Required; 8-byte slot |
| `MEMSIZE` | u32 | 0 | |
| `PARENTAL_LEVEL` | u32 | 1 | |
| `PSP_SYSTEM_VER` | UTF-8 | `1.00` | Minimum firmware |
| `REGION` | u32 | 32768 | All regions |
| `TITLE` | UTF-8 | | XMB title |

Removing `DISC_ID`/`DISC_VERSION` from an otherwise working MG EBOOT makes OFW 6.61 (PSP 3000) report "the data is corrupted". `UCJS10041` matches `cargo-psp`'s `mksfo` default.

## 4. Implementation

| Module | Behaviour |
| --- | --- |
| [`pbp::parser`](../src/pbp/parser.rs) | Validates every offset before slicing |
| [`pbp::builder`](../src/pbp/builder.rs) | Recomputes the offset table from section contents |
| [`sfo`](../src/sfo.rs) | Preserves `data_max_len` and raw format per entry, including unknown keys |
| `Pbp::require_category` | Rejects a container of the wrong category for a pipeline |
