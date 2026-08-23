# The MG path

`CATEGORY=MG` is a memory-stick game. Homebrew, demos and anything else that
runs from `ms0:/PSP/GAME/` takes this path.

It is the simpler of the two security paths by a wide margin, and the reason is
worth stating plainly: **there is no signature anywhere in it.** An MG EBOOT is
a PBP container whose `DATA.PSP` is an encrypted PRX, and the PRX's integrity
rests on a hash and two MACs computed under keys that have been public for
nearly two decades. Nothing in the chain requires a private key.

```text
PRX
 └─ optional gzip
     └─ KIRK CMD1 container       AES-128-CBC + two AES-CMAC tags
         └─ ~PSP header           0x150 bytes, header fields + wrapped keys
             └─ DATA.PSP
                 └─ EBOOT.PBP     with PARAM.SFO CATEGORY=MG
```

## 1. What each stage contributes

| stage | input | output | detail |
| --- | --- | --- | --- |
| compression | module | gzip stream | optional; skipped if it does not shrink |
| KIRK CMD1 | payload | AES-CBC ciphertext + MACs | [FORMAT.md §3](FORMAT.md) |
| `~PSP` header | sizes, keys, module metadata | 0x150 bytes | [FORMAT.md §2](FORMAT.md) |
| `PARAM.SFO` | title, category | parameter table | [PBP.md §4](PBP.md) |
| PBP | sections | `EBOOT.PBP` | [PBP.md §1](PBP.md) |

The cryptographic half is documented in [FORMAT.md](FORMAT.md), which covers the
`~PSP` header layout, the KIRK CMD1 container, what the firmware actually
validates, and why the output can be sized from the payload instead of copied
from a template. This document covers the container half and the pipeline
decisions.

## 2. `DATA.PSP` sizing

The legacy `PrxEncrypter` ships three prebuilt header templates and picks the
smallest the input fits into, copying its size fields and integrity hashes
verbatim. The output is therefore padded to the template's capacity. A 498,752
byte module became 5,583,952 bytes.

`pspbuild` computes the header. The output is:

```text
0x150 bytes of header  +  align16(payload size)
```

and nothing else. The same module becomes 147,472 bytes — smaller than the
input, because the payload was compressed first.

This is only possible because the `~PSP` header for tag `0xADF305F0` carries no
signature; every input to every check is either data we choose or key material
that is published. [FORMAT.md §4–6](FORMAT.md) works through why.

## 3. `PARAM.SFO` and category enforcement

`build_mg_eboot` writes `CATEGORY=MG` and then re-reads the container it just
produced to confirm it says `MG`, failing if it does not.

That check is not redundant. `--base` lets a build start from an existing
container, and an existing container may be an EG one. Inheriting its
`PARAM.SFO` unchanged would produce a file whose `CATEGORY` points the firmware
at the NPDRM path while `DATA.PSP` holds a plain encrypted PRX. The category is
therefore always overwritten, never inherited.

Everything else in a base container's `PARAM.SFO` *is* inherited, including keys
this crate has no opinion about, because a homebrew project may depend on them.
Only `CATEGORY` is forced; `TITLE` and `PSP_SYSTEM_VER` are overwritten only
when the caller asked.

## 4. `DATA.PSAR`

Empty. `DATA.PSAR` is where the EG path puts its `NPUMDIMG` archive, and the MG
path has no equivalent. A base container's `DATA.PSAR` is carried through if
present, but nothing in this pipeline creates one.

## 5. `PrxEncrypter` vs `ebootsigner` vs `pspbuild`

| | PSPSDK `PrxEncrypter` | `ebootsigner` | `pspbuild` |
| --- | --- | --- | --- |
| header source | one of 3 fixed templates | fixed template | computed |
| output size | template capacity | template capacity | 0x150 + align16(payload) |
| compression | template-dependent | yes | when it shrinks |
| CMAC | forged to collide with the template | as `PrxEncrypter` | computed over the real data |
| PBP handling | none, PRX only | rebuilds the container | rebuilds the container |
| `PARAM.SFO` | untouched | untouched | category enforced |
| determinism | yes | yes | yes, keys derived from the payload |

The forged CMAC in the legacy tools is the giveaway. It exists because those
tools assume the header bytes cannot be recomputed, so they arrange for a
collision against the template instead. They can be recomputed, which removes
the need for both the forgery and the template.

## 6. Known constraints

- **One tag.** Only `0xADF305F0`, the 2.80 demo scheme, is emitted. Other tags
  use different KIRK paths and some do require a signature.
- **`mod_attribute` bit `0x0200` is forced**, OR-ed into the module's own
  attributes. Retail firmware will not load an encrypted module without it.
  Isolated on hardware one field at a time; what the bit means is not known.
  See [FORMAT.md §8](FORMAT.md).
- **At most four segments**, which is what a `~PSP` header can describe.
- **Tested on one console**, a PSP Slim on official firmware.

## 7. Verification

`pspbuild verify` reconstructs the KIRK container from the `~PSP` header,
checks the header SHA-1 and both CMAC tags, decrypts, decompresses, and
re-parses the result as a PSP module. Every one of those steps is a real check
against the file's own claims:

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
```

Output is additionally cross-checked against PPSSPP's independent
`PrxDecrypter` implementation, and against a fixture produced by the PSPSDK
reference tool. See [COMPATIBILITY.md](COMPATIBILITY.md).
