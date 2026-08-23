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
| known-good EG `EBOOT.PBP` fixtures | **not available** — none in the repo or on disk |
| `sign_np` source | not vendored |
| `ebootsigner` source | not vendored |
| PSPSDK `PrxEncrypter` source | available, but MG-only |
| `libkirk` / PPSSPP KIRK | available via the existing `kirk` module |
| a PSP ISO to test against | **not available** |

Without at least one known-good EG EBOOT there is no way to validate a single
structure in this document. Writing an `NpUmdImgHeader` with named fields would
produce something that compiles, passes its own tests, and has never been
checked against a file the PSP accepts. That is worse than an unimplemented
command, because it looks finished.

## 2. Shape of the pipeline

The overall flow is well attested in public documentation and in the behaviour
of existing tools:

```text
PSP ISO
 └─ ISO9660 reader                extract PSP_GAME assets and EBOOT.BIN
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
   constants.
2. **A small PSP ISO** to run a candidate pipeline over.
3. **The NPUMDIMG private key**, if genuine signing is wanted.
4. `sign_np` and `ebootsigner` sources, as behavioural references — useful for
   generating differential test cases, not as a specification to copy.

With (1) alone, most of section 3 becomes answerable: `pspbuild` already has the
PBP parser, the inspection tooling and the KIRK primitives needed to take a real
file apart and check each hypothesis against it.

## 5. Design commitment

When this is implemented it will be a separate pipeline from MG, not a mode of
it. They share the PBP container and the KIRK primitives and nothing else. The
category check in `Pbp::require_category` exists so that neither can silently
run against the other's container, and that guarantee should survive the EG
implementation rather than being relaxed to accommodate it.
