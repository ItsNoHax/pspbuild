# The EG path — specification status

`CATEGORY=EG` is an emulated/downloaded game: a PSP ISO repackaged as a single
`EBOOT.PBP` under NPDRM, the form PSN titles and `sign_np` output take.

**This path is not implemented.** `pspbuild build-eg` exists and fails with a
message saying so. This document exists to record what would have to be
established first, and — more usefully — what is currently *unknown*, so the
work can start from an honest baseline rather than from a port of `sign_np`
whose behaviour nobody has checked.

## 1. Why it is not implemented yet

The plan this project follows is explicit that reverse engineering comes before
implementation, and that legacy tools are behavioural references rather than
authoritative specifications. That phase cannot be completed from the material
currently on hand:

| needed | status |
| --- | --- |
| known-good EG `EBOOT.PBP` fixtures | **still not available** — none in the repo or on disk |
| `sign_np` source | not vendored |
| `ebootsigner` source | not vendored |
| PSPSDK `PrxEncrypter` source | available, but MG-only |
| `libkirk` / PPSSPP KIRK | available via the existing `kirk` module |
| a PSP ISO to test against | **available** — a retail UMD, see [ISO.md](ISO.md) |
| an ISO9660 reader | **implemented**, validated against that disc |

The input side is now done. `pspbuild` reads a real UMD, enumerates it, pulls
out every `PSP_GAME` asset and serves raw sectors, without loading the image
into memory. What that unblocks is section 4.1 below; what it does not unblock
is everything downstream of it.

The remaining blocker is unchanged and is the important one: **without at least
one known-good EG EBOOT there is no way to validate a single structure in
section 3.** Writing an `NpUmdImgHeader` with named fields would produce
something that compiles, passes its own tests, and has never been checked
against a file the PSP accepts. That is worse than an unimplemented command,
because it looks finished.

## 2. Shape of the pipeline

The overall flow is well attested in public documentation and in the behaviour
of existing tools:

```text
PSP ISO
 └─ ISO9660 reader                extract PSP_GAME assets and EBOOT.BIN   DONE
     └─ NP table                  per-block offsets, sizes, MACs
         └─ block encryption      the ISO in fixed-size encrypted blocks
             └─ NPUMDIMG          header + NP table + encrypted blocks
                 └─ BB-MAC        header authentication
                     └─ ECDSA     signature over the header
                         └─ DATA.PSAR
                             └─ EBOOT.PBP  with DATA.PSP (NPDRM) and CATEGORY=EG
```

The container half is understood — it is an ordinary PBP, documented in
[PBP.md](PBP.md), with `CATEGORY=EG`, an NPDRM `DATA.PSP` and an `NPUMDIMG` in
`DATA.PSAR`. `pspbuild inspect` already identifies all of that:

```console
$ pspbuild inspect EBOOT.PBP
Format:              PBP container
Category:            EG
Sections:
  DATA.PSP     offset 0x0004A1B8       12608 bytes  unrecognised
  DATA.PSAR    offset 0x0004D2F8   612495360 bytes  NPUMDIMG (NPDRM UMD image)
Executable:          EG DATA.PSP is an NPDRM container; not supported yet
```

Everything below that line is where the specification stops.

## 3. Open questions

These are the things that must be answered with byte-level certainty, against
fixtures, before any of it is implemented. They are listed as questions rather
than as a specification because that is what they currently are.

### 3.1 NPUMDIMG

- Exact header layout and the meaning of every field. No unexplained offsets.
- Where the header ends and the NP table begins.
- Block size, and whether it is fixed or recorded in the header.
- How the last, partial block is handled.
- Which byte ranges the MAC and the signature each cover.

### 3.2 NP table

- Entry layout, and what is stored per block: offset, size, flags, MAC.
- Whether entries are themselves encrypted, and under what key.
- How the table size relates to the ISO size, so it can be generated rather
  than templated.

### 3.3 Key derivation and tags

- The NPDRM tag values in play, and what selects between them.
- How the per-title key derives from the content ID, the tag, or both.
- Which KIRK command performs each step.

The distinction the plan insists on matters most here: `CATEGORY` is a routing
decision, a *tag* is a cryptographic format identifier, and a *key* is the
material itself. They are not interchangeable, and a table conflating them
would be actively misleading. See [KEYS.md](KEYS.md).

### 3.4 BB-MAC and BB-Cipher

- Initialisation, update and finalisation, including the finalisation variants.
- Whether BB-Cipher is genuinely distinct from the KIRK AES path already
  implemented, and if so exactly how.

Neither should be assumed equivalent to a primitive already in this crate until
that has been demonstrated against known answers.

### 3.5 ECDSA

- The curve, point and scalar representation, and endianness.
- The signature representation, which must match the PSP's rather than a
  generic Rust ECDSA library's defaults.
- Exactly which bytes are signed.

The plan notes that a recovered NPUMDIMG private key is available and that
genuine signing is therefore the goal rather than fake-signing. That key is not
in this repository, and would need to be supplied. Whatever is produced, every
generated signature must be verified before it is emitted.

### 3.6 `DATA.PSP`, PGD, STARTDAT, OPNSSMP

- Which of these are mandatory and which are conditional on content.
- Their structures, as named types rather than one opaque byte array.
- Whether EG `EBOOT.BIN` processing shares anything with MG PRX encryption. It
  must be assumed not to until shown otherwise.

## 4. What would unblock this

In rough order of value:

1. **One known-good EG `EBOOT.PBP`.** Everything else can be validated against
   it. Two, from different titles, would separate per-title values from
   constants. This is now the *only* thing blocking section 3.
2. **The NPUMDIMG private key**, if genuine signing is wanted. It is not in this
   repository.
3. `sign_np` and `ebootsigner` sources, as behavioural references — useful for
   generating differential test cases, not as a specification to copy.

With (1) alone, most of section 3 becomes answerable: `pspbuild` already has the
PBP parser, the ISO reader, the inspection tooling and the KIRK primitives
needed to take a real file apart and check each hypothesis against it.

### 4.1 What the ISO reader already provides

Available now, and enough to build the input half of the pipeline against:

- `Iso::open` on a retail UMD, with the volume descriptor checked against the
  file's real length.
- `read_file` / `read_optional` for the `PSP_GAME` assets that become PBP
  sections, distinguishing "absent" from "unreadable" — `SND0.AT3` is missing
  from the reference disc, so that distinction is not hypothetical.
- `read_blocks` for raw sectors, which is how the archive will be built.
- Disc identification from `UMD_DATA.BIN`.

What it deliberately does not do is guess at what happens to those sectors next.

## 5. Design commitment

When this is implemented it will be a separate pipeline from MG, not a mode of
it. They share the PBP container and the KIRK primitives and nothing else. The
category check in `Pbp::require_category` exists so that neither can silently
run against the other's container, and that guarantee should survive the EG
implementation rather than being relaxed to accommodate it.
