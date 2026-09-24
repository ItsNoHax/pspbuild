# MG pipeline

`CATEGORY=MG`: homebrew, demos, anything launched from `ms0:/PSP/GAME/`. No step requires a private key.

```text
PRX
 └─ gzip (optional)
     └─ KIRK CMD1      AES-128-CBC + two AES-CMAC tags
         └─ ~PSP       0x150-byte header
             └─ DATA.PSP
                 └─ EBOOT.PBP   PARAM.SFO CATEGORY=MG
```

## 1. Stages

| Stage | Output | Reference |
| --- | --- | --- |
| Compression | gzip stream, used only if smaller | |
| KIRK CMD1 | Ciphertext + CMACs | [FORMAT.md §3](FORMAT.md) |
| `~PSP` header | 0x150 bytes | [FORMAT.md §2](FORMAT.md) |
| `PARAM.SFO` | Parameter table | [PBP.md §3](PBP.md) |
| PBP | `EBOOT.PBP` | [PBP.md §1](PBP.md) |

## 2. `DATA.PSP` size

```text
0x150 + align16(payload size)
```

A 498,752-byte module becomes 147,472 bytes (compressed). `PrxEncrypter` produces 5,583,952 bytes for the same input.

## 3. `PARAM.SFO`

- `CATEGORY` is always set to `MG`, including when `--base` supplies an EG container. The built container is re-read and checked.
- All other keys from a `--base` container are kept. `TITLE` and `PSP_SYSTEM_VER` are overwritten only when given.
- Without `--base`, the table in [PBP.md §3.2](PBP.md) is written, including `DISC_ID` and `DISC_VERSION`.

## 4. `DATA.PSAR`

Empty. A `--base` container's `DATA.PSAR` is carried through.

## 5. Comparison

| | `PrxEncrypter` | `ebootsigner` | `pspbuild` |
| --- | --- | --- | --- |
| Header | 3 fixed templates | Fixed template | Computed |
| Output size | Template capacity | Template capacity | `0x150 + align16(payload)` |
| Compression | Template-dependent | Yes | When smaller |
| CMAC | Forged | Forged | Computed |
| PBP | No | Rebuilds | Rebuilds |
| `PARAM.SFO` | — | Untouched | Category enforced |
| Deterministic | Yes | Yes | Yes |

## 6. Constraints

- Tag `0xADF305F0` only.
- `mod_attribute` bit `0x0200` forced ([FORMAT.md §7](FORMAT.md)).
- At most four segments.

## 7. Verification

```console
$ pspbuild verify EBOOT.PBP
VALID: PBP container structure
VALID: ~PSP header SHA-1
VALID: ~PSP metadata structure
VALID: declared sizes match the file
VALID: KIRK header and data CMAC
VALID: gzip payload decompresses
VALID: recovered size matches elf_size
VALID: recovered payload is a valid PSP module
Recovered size:      498752 bytes
Module name:         AngleZero
VERIFIED
```

See [COMPATIBILITY.md](COMPATIBILITY.md) for external validation.
