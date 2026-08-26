# pspbuild documentation

These documents describe the PSP formats themselves, not the code that
implements them. Where a claim was established empirically — on hardware, or
against a real file — that is stated.

| document | covers |
| --- | --- |
| [PBP.md](PBP.md) | the `EBOOT.PBP` container and `PARAM.SFO`, byte by byte |
| [ISO.md](ISO.md) | PSP UMD images: ISO9660 as a disc actually uses it, and the PSP layout |
| [FORMAT.md](FORMAT.md) | the encrypted PRX: the `~PSP` header, the KIRK CMD1 container, and why dynamic sizing is possible |
| [MG.md](MG.md) | the MG security path end to end, and how it differs from the legacy tools |
| [EG.md](EG.md) | the EG/NPDRM path: what is known, what is not, and what would unblock it |
| [NPUMDIMG.md](NPUMDIMG.md) | the EG archive format, byte by byte — header, block table, block crypto — checked against genuine Sony archives |
| [KEYS.md](KEYS.md) | the key/tag matrix, and the distinction between category, tag, key and format |
| [COMPATIBILITY.md](COMPATIBILITY.md) | what has been tested, on what, and what has not |

## Where the PRX and KIRK specifications live

The project plan lists `PRX.md` and `KIRK.md` as separate documents. Both
subjects are covered in [FORMAT.md](FORMAT.md), which was written first and
treats them together — the `~PSP` header and the KIRK CMD1 container it wraps
are hard to explain apart, since the header's whole purpose is to scatter the
KIRK header's fields. Splitting them would mean two documents that each only
make sense with the other open.

[NPUMDIMG.md](NPUMDIMG.md) now exists: the archive format is specified, derived
from a reference archive and confirmed by differential runs. Its cryptographic
primitives are implemented in `src/npdrm` and verified against a real archive's
header; nothing yet *writes* an archive.

`NPDRM.md` is still folded into [EG.md](EG.md). BB-MAC, BB-Cipher and the fixed
key are now characterised, but they are documented where they are used —
[NPUMDIMG.md §3 and §4](NPUMDIMG.md) — rather than in a file of their own,
since NPUMDIMG is so far the only thing that uses them.

## Reading order

Start with [PBP.md](PBP.md) for the container, then [FORMAT.md](FORMAT.md) for
what goes inside it, then [MG.md](MG.md) for how the two fit together.
[KEYS.md](KEYS.md) is a reference rather than a narrative.
