# ICON1.PMF: the animated XMB icon

`ICON1.PMF` is the video the XMB plays in place of `ICON0.PNG` while a game's
icon is selected. ffmpeg can demux PMF but has no muxer for it, so pspbuild
writes the container itself.

> **Only a PSP proves an ICON1 works.** The console's decoder is stricter than
> ffmpeg's, which decodes files the XMB will not animate.

## 1. What pspbuild does

```text
any video -> ffmpeg/libx264 -> H.264 Annex B -> access units -> PSMF -> ICON1.PMF
H.264 Annex B ----------------------------------^
```

```sh
pspbuild video icon1 icon.mp4 -o ICON1.PMF      # encode and mux
pspbuild video icon1 icon.h264 -o ICON1.PMF     # mux an existing stream
pspbuild build-mg game.prx --icon1 icon.mp4     # convert while building
```

The input is classified by its first bytes: `PSMF` is passed through, an
Annex B start code (`00 00 01` or `00 00 00 01`) is muxed as-is, and anything
else is handed to ffmpeg. Encoding is the one place pspbuild runs an external
tool: no pure-Rust H.264 encoder writes the CABAC Main-profile stream below.

## 2. The reference

Every rule copies a Sony-authored 144 × 80 icon,
`pspautotests/tests/video/pmf/test.pmf` in the PPSSPP repository. The index
layout was also checked against a second, independently authored ICON1.

## 3. The video stream

ffmpeg scales to 144 × 80 at 29.97 fps (`30000/1001`), `yuv420p`, and encodes
with libx264, CRF 18:

| Property | Value | x264 setting |
| --- | --- | --- |
| Profile, level | Main, 2.1, CABAC | `-profile:v main -level 2.1` |
| Pictures | I and P only, one reference frame | `bframes=0:ref=1:weightp=0` |
| GOP | 59 frames, fixed | `keyint=59:min-keyint=59:scenecut=0` |
| Delimiters | an access-unit delimiter before every picture | `aud=1` |
| SEI | buffering period and picture timing | `nal-hrd=vbr:pic-struct=1:force-cfr=1` |
| VBV | 600 kbit/s, 600 kbit, well inside the 85 KiB P-STD buffer | `vbv-maxrate=600:vbv-bufsize=600` |

x264's user-data-unregistered SEI (its version string) is dropped when muxing;
Sony's streams carry none. A muxed Annex B stream must already follow these
rules: the muxer checks only that it opens with a delimiter and an IDR picture
and that every picture fits the 16-bit index, and it always describes a
144 × 80 icon in the header.

## 4. The container

A 2048-byte header, then 2048-byte MPEG-2 program-stream packs.

### 4.1 Header

| Offset | Value |
| --- | --- |
| `0x00` | `PSMF0014` |
| `0x08` | header size, 2048 (big-endian) |
| `0x0C` | stream size: the packs, in bytes |
| `0x50` | `0x3E`, first PTS (90000) and last PTS as 6-byte values, mux rate 25000, 90000, `01 01` |
| `0x6A` | `0x24`, first and last PTS again, then `00 01`, `00 00 00 12`, `00 01` |
| `0x82` | `e0 00 20 55` (video stream `0xE0`, P-STD buffer `0x55` KiB), eight zero bytes |
| `0x8E` | width / 16, height / 16, `00 00` |

The last PTS is `90000 + frames × 3003`.

### 4.2 Packs

Each pack starts with a 14-byte pack header: an SCR and mux rate 25000
(units of 50 bytes/s). The SCR starts at 3044236 (27 MHz) and advances
44236.8 ticks per pack, the time one pack takes at the mux rate. A pack is
never sent earlier than 76850 ticks (90 kHz) before the DTS of the picture its
first video byte belongs to, as in the reference.

Every GOP starts a new pack, which carries in order:

1. the system header `00 00 01 bb 00 0c 80 c3 51 80 f0 7f b9 e0 55 bd e0 08`;
2. a private-stream-2 (`0xBF`) index of the GOP;
3. a video PES (`0xE0`) with PTS, DTS and a P-STD buffer extension (85 KiB).

Later packs carry one video PES. It gets a PTS and DTS when an access unit
starts in it at least 16 frames after the last stamped one; DTS is PTS minus
one frame. The GOP's last pack is filled with a padding stream (`0xBE`), or
with PES stuffing bytes when fewer than six bytes are left.

### 4.3 GOP index

```text
01 e0
4 × u16   pack (relative to the GOP) holding the last byte of each of the
          first four pictures; repeated last value for shorter GOPs
00 00 00 00
u16       2 + 4 × pictures
u16       pictures
pictures × (u16 flag, u16 size)   flag 0x0080 on all but the last picture
```

## 5. Verification

The muxer reproduces the hardware-tested icons of the project it was ported
from byte for byte: given the same Annex B stream, its output matches the
earlier Python muxer, whose icons animate in the XMB of a PSP Slim (6.61,
ARK). To check a new file offline:

```sh
ffprobe -v error -count_frames -show_entries stream=profile,level,nb_read_frames ICON1.PMF
```

That shows ffmpeg can decode it, not that the XMB will.
