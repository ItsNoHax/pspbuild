# Documentation

Format specifications for the files `pspbuild` reads and writes. Claims verified on hardware or against genuine Sony files are marked as such.

| Document | Contents |
| --- | --- |
| [PBP.md](PBP.md) | `EBOOT.PBP` container and `PARAM.SFO` |
| [ISO.md](ISO.md) | UMD images: ISO9660 subset and PSP layout |
| [FORMAT.md](FORMAT.md) | Encrypted PRX: `~PSP` header, KIRK CMD1, validated fields |
| [MG.md](MG.md) | MG pipeline |
| [EG.md](EG.md) | EG pipeline: UMD image to signed NPDRM EBOOT |
| [NPUMDIMG.md](NPUMDIMG.md) | EG archive: header, block table, BB-MAC, BB-Cipher, ECDSA |
| [KEYS.md](KEYS.md) | Categories, tags and keys |
| [AUDIO.md](AUDIO.md) | `SND0.AT3`: XMB rules and why, ATRAC3 encoder, decoder, validator |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Hardware, emulator and reference-tool results |

Suggested order: PBP → FORMAT → MG, then EG → NPUMDIMG. KEYS is reference material.
