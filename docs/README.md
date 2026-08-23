# pspbuild documentation

These documents describe the PSP formats themselves, not the code that
implements them. Where a claim was established empirically — on hardware, or
against a real file — that is stated.

| document | covers |
| --- | --- |
| [PBP.md](PBP.md) | the `EBOOT.PBP` container and `PARAM.SFO`, byte by byte |
| [FORMAT.md](FORMAT.md) | the encrypted PRX: the `~PSP` header, the KIRK CMD1 container, and why dynamic sizing is possible |
| [MG.md](MG.md) | the MG security path end to end, and how it differs from the legacy tools |
| [EG.md](EG.md) | the EG/NPDRM path: what is known, what is not, and what would unblock it |
| [KEYS.md](KEYS.md) | the key/tag matrix, and the distinction between category, tag, key and format |
| [COMPATIBILITY.md](COMPATIBILITY.md) | what has been tested, on what, and what has not |

## Where the PRX and KIRK specifications live

The project plan lists `PRX.md` and `KIRK.md` as separate documents. Both
subjects are covered in [FORMAT.md](FORMAT.md), which was written first and
treats them together — the `~PSP` header and the KIRK CMD1 container it wraps
are hard to explain apart, since the header's whole purpose is to scatter the
KIRK header's fields. Splitting them would mean two documents that each only
make sense with the other open.

`NPDRM.md` and `NPUMDIMG.md` are likewise folded into [EG.md](EG.md) for now.
There is not yet a specification to put in them; what exists is a list of open
questions, and spreading that across three files would overstate how much is
settled. They should be split out once the reverse engineering produces
something worth separating.

## Reading order

Start with [PBP.md](PBP.md) for the container, then [FORMAT.md](FORMAT.md) for
what goes inside it, then [MG.md](MG.md) for how the two fit together.
[KEYS.md](KEYS.md) is a reference rather than a narrative.
