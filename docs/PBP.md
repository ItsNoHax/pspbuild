# The PBP container and `PARAM.SFO`

`EBOOT.PBP` is the file the PSP's XMB launches. It is a trivial archive — a
header of offsets followed by eight concatenated blobs — wrapping the things
the firmware needs: a parameter table saying what the title is and which
security path to run, some artwork, the executable, and optionally a bulk data
archive.

Everything below was checked against real files. The byte dumps are from a
homebrew `EBOOT.PBP` that boots on a retail PSP Slim.

## 1. The container

```text
0x00  u8[4]   magic       00 50 42 50   "\0PBP"
0x04  u32     version     0x00010000
0x08  u32     offset[0]   PARAM.SFO
0x0C  u32     offset[1]   ICON0.PNG
0x10  u32     offset[2]   ICON1.PMF
0x14  u32     offset[3]   PIC0.PNG
0x18  u32     offset[4]   PIC1.PNG
0x1C  u32     offset[5]   SND0.AT3
0x20  u32     offset[6]   DATA.PSP
0x24  u32     offset[7]   DATA.PSAR
0x28          section data
```

From a real EBOOT:

```text
00000000: 0050 4250 0000 0100 2800 0000 4801 0000   .PBP....(...H...
00000010: 6a44 0000 6a44 0000 6a44 0000 58cf 0100   jD..jD..jD..X...
00000020: d456 0400 e496 0600                       .V......
```

| field | value | meaning |
| --- | --- | --- |
| magic | `00 50 42 50` | `"\0PBP"` |
| version | `0x00010000` | the only value observed |
| offset[0] | `0x00000028` | `PARAM.SFO`, immediately after the header |
| offset[1] | `0x00000148` | `ICON0.PNG` |
| offset[2] | `0x0000446A` | `ICON1.PMF` |
| offset[3] | `0x0000446A` | `PIC0.PNG` — equal to the previous, so empty |
| offset[4] | `0x0000446A` | `PIC1.PNG` |
| offset[5] | `0x0001CF58` | `SND0.AT3` |
| offset[6] | `0x000456D4` | `DATA.PSP` |
| offset[7] | `0x000696E4` | `DATA.PSAR` |

### 1.1 There are no lengths

This is the single most important property of the format. A section's length is
*derived*: it runs from its own offset to the next section's offset, and the
last section runs to the end of the file.

Three consequences follow, and all three are load-bearing:

- **An empty section is two equal offsets.** `PIC0.PNG` above is absent, and
  the way you know is that offset[3] equals offset[4]. There is no presence
  flag and no zero-length marker.
- **Nothing may be appended to the file.** Trailing bytes are indistinguishable
  from `DATA.PSAR` contents, because that section is defined as "everything
  from offset[7] onwards".
- **Sections must be in ascending order.** An offset table that goes backwards
  would give a section a negative length. `pspbuild` rejects such a file rather
  than saturating the subtraction, since a container that claims it is one of
  the few things a hostile input can do here.

### 2. Alignment and padding

There is none. Sections start immediately after one another, at whatever offset
that lands on. `PARAM.SFO` starts at 0x28, which is not aligned to anything in
particular, and the sections after it inherit whatever alignment the preceding
sizes produce.

This is why the container itself imposes no size floor: an EBOOT is exactly
0x28 bytes plus the sum of its sections. Any padding in a real EBOOT came from
whatever built the sections, not from the container.

### 3. The sections

| # | name | contents | required |
| --- | --- | --- | --- |
| 0 | `PARAM.SFO` | parameter table, section 4 below | yes |
| 1 | `ICON0.PNG` | XMB icon, 144x80 PNG | no |
| 2 | `ICON1.PMF` | animated icon, PSMF video | no |
| 3 | `PIC0.PNG` | upper background layer | no |
| 4 | `PIC1.PNG` | background, 480x272 PNG | no |
| 5 | `SND0.AT3` | XMB background audio, RIFF/AT3 | no |
| 6 | `DATA.PSP` | the executable | yes |
| 7 | `DATA.PSAR` | bulk archive | EG only |

What `DATA.PSP` and `DATA.PSAR` actually hold depends on `CATEGORY`:

| CATEGORY | what it is | DATA.PSP | DATA.PSAR |
| --- | --- | --- | --- |
| `MG` | homebrew and demos | encrypted `~PSP` PRX, see [FORMAT.md](FORMAT.md) | empty |
| `EG` | PSP game from the Store | NPDRM container | `NPUMDIMG` |
| `ME` | PSOne classic from the Store | NPDRM container | `PSISOIMG0000` |

`UG` also exists but never appears in a PBP — it is what a retail UMD's own
`PARAM.SFO` declares, inside the ISO. See [EG.md §1.1](EG.md) for the full
comparison, which is the thing to read before assuming a given file is EG.

## 4. `PARAM.SFO`

A flat key/value table. The firmware reads it before anything else, and
`CATEGORY` is the field that decides which security path runs — so this table is
not decoration, it is a routing decision.

```text
0x00  u8[4]  magic             00 50 53 46   "\0PSF"
0x04  u32    version           0x00000101
0x08  u32    key_table_start   offset of the key table
0x0C  u32    data_table_start  offset of the data table
0x10  u32    entry_count
0x14         index[entry_count]
```

Each index entry is 16 bytes:

```text
0x00  u16  key_offset      relative to key_table_start
0x02  u16  format          0x0004 raw, 0x0204 UTF-8, 0x0404 u32
0x04  u32  data_len        bytes actually used, NUL included for strings
0x08  u32  data_max_len    bytes reserved in the data table
0x0C  u32  data_offset     relative to data_table_start
```

The key table is a run of NUL-terminated names; the data table is a run of
values, each occupying `data_max_len` bytes regardless of how many it uses.

From the same real EBOOT:

```text
00000000: 0050 5346 0101 0000 9400 0000 e800 0000   .PSF............
00000010: 0800 0000 0000 0404 0400 0000 0400 0000   ................
00000020: 0000 0000 0900 0402 0300 0000 0400 0000   ................
```

- header: key table at `0x94`, data table at `0xE8`, 8 entries
- entry 0: key at `+0x0000` (`BOOTABLE`), format `0x0404` (u32), 4 bytes used of
  4 reserved, value at `+0x0000`
- entry 1: key at `+0x0009` (`CATEGORY`), format `0x0204` (UTF-8), **3 bytes
  used of 4 reserved**, value at `+0x0004` — the string `"MG"` plus its NUL

### 4.1 `data_max_len` is not derivable

Entry 1 is the reason `pspbuild` stores `data_max_len` alongside the value
rather than recomputing it. `"MG\0"` is three bytes, but the file reserves four.
`TITLE` reserves 128 bytes for a title that is usually far shorter. Nothing in
the value tells you the reservation; whoever wrote the file chose it.

A parser that normalised reservations would round-trip a real `PARAM.SFO` into
something a byte or two different at a dozen offsets. Keeping the field is what
lets `pspbuild build-mg --base` rebuild an existing EBOOT and land on
byte-identical output.

### 4.2 Layout rules

- Entries are sorted by key. The index, key table and data table are all in the
  same order.
- The key table is padded with NULs so that the data table starts 4-byte
  aligned. In the dump above the keys occupy 82 bytes from `0x94`, ending at
  `0xE6`, and two padding bytes push the data table to `0xE8`.

### 4.3 Keys an MG homebrew EBOOT sets

| key | format | value | why |
| --- | --- | --- | --- |
| `BOOTABLE` | u32 | 1 | the launcher refuses to start it otherwise |
| `CATEGORY` | UTF-8 | `MG` | selects the memory-stick-game security path |
| `MEMSIZE` | u32 | 0 | the module does not request extra RAM |
| `PARENTAL_LEVEL` | u32 | 1 | least restrictive |
| `PSP_SYSTEM_VER` | UTF-8 | `1.00` | minimum firmware |
| `REGION` | u32 | 32768 | the "all regions" bitmask |
| `TITLE` | UTF-8 | shown in the XMB | |

Retail discs additionally carry `DISC_ID`, `DISC_VERSION` and similar. Those are
preserved when rebuilding on an existing container but never invented.

## 5. What `pspbuild` does with this

- [`pbp::parser`](../src/pbp/parser.rs) validates every offset before slicing.
- [`pbp::builder`](../src/pbp/builder.rs) recomputes the whole offset table from
  section contents, so replacing a section can never leave a stale offset.
- [`sfo`](../src/sfo.rs) keeps `data_max_len` and the raw format code per entry,
  so any table round-trips exactly, including keys this crate has no typed
  reading for.
- `Pbp::require_category` refuses to let a pipeline run against a container that
  asks for the other one. See [MG.md](MG.md).
