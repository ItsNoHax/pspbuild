# The encrypted PRX format, and why dynamic sizing is possible

This document records the analysis that the implementation is based on. It maps
every byte of the legacy PSPSDK templates to a purpose and states whether that
byte must be static for PSP compatibility or can be generated from the payload.

The reference material was:

- `PrxEncrypter/main.c`, `kirk_engine.c`, `crypto.c`, `psp_headers.h` — the
  legacy encrypter,
- PPSSPP's `Core/ELF/PrxDecrypter.cpp` and `ext/libkirk/` — a working
  *decrypter*, i.e. the consumer whose checks actually have to be satisfied.

The decrypter is the authoritative source. Field meanings were taken from what
the decrypter *does with them*, not from variable names.

---

## 1. File layout

An encrypted PRX is a 0x150-byte header followed by the encrypted payload:

```text
0x000  ~PSP header               0x150 bytes
0x150  encrypted payload         align16(payload_size) bytes
```

There is nothing else — no trailer, no padding beyond the AES block alignment.

## 2. The `~PSP` header (0x150 bytes)

```text
offset  len    field                 static?    notes
------  -----  --------------------  ---------  --------------------------------
0x000   0x004  "~PSP" magic          static     format identifier
0x004   0x002  mod_attribute         derived    from the input module info
0x006   0x002  comp_attribute        derived    bit 0 = payload is gzipped
0x008   0x002  module version        derived    from the input module info
0x00A   0x01C  module name           derived    from the input module info
0x026   0x001  mod_version           static     1
0x027   0x001  nsegments             derived    count of PT_LOAD segments
0x028   0x004  elf_size              derived    size of the decrypted module
0x02C   0x004  psp_size              derived    0x150 + align16(comp_size)
0x030   0x004  boot_entry            derived    ELF e_entry
0x034   0x004  modinfo_offset        derived    first PT_LOAD p_paddr & 0x7FFFFFFF
0x038   0x004  bss_size              derived    sum of p_memsz - p_filesz
0x03C   0x008  seg_align[4]          derived    per segment
0x044   0x010  seg_address[4]        derived    per segment p_vaddr
0x054   0x010  seg_size[4]           derived    per segment p_filesz
0x064   0x014  reserved[5]           static     zero
0x078   0x004  devkit_version        free       see note below
0x07C   0x001  decrypt_mode          static     0x0D for this scheme
0x07D   0x001  padding               static     zero
0x07E   0x002  overlap_size          static     zero
------  -----  end of the metadata region; also copied as KIRK predata --------
0x080   0x030  KIRK key block 0x00..0x30    generated
0x0B0   0x010  KIRK size metadata           derived   data_size, data_offset
0x0C0   0x010  KIRK key block 0x30..0x40    generated
0x0D0   0x004  tag                          static    selects keys, 0xADF305F0
0x0D4   0x058  signature region             static    must be all zero
0x12C   0x014  SHA-1 of the header          generated
0x140   0x010  id                           generated
```

**The 0x00..0x80 region does double duty.** KIRK stores a verbatim copy of it
as the container's "predata", so it is covered by the data CMAC. Changing the
module name changes the CMAC.

### `devkit_version`

The input ELF carries no equivalent. The three legacy templates use 0x00000000,
0x03070010 and 0x05000010 with the *same* tag, so the loader does not constrain
it. This crate writes 0x03070110.

## 3. The KIRK CMD1 container

Reconstructed by the decrypter from the header; never written to disk as such.

```text
0x000  0x090  CMD1 header
0x090  0x080  predata = ~PSP metadata region (0x00..0x80), in the clear
0x110  ...    payload, AES-128-CBC encrypted, zero IV, aligned to 16
```

The CMD1 header:

```text
0x00  0x10  aes_key      per-module, wrapped with KIRK1_KEY
0x10  0x10  cmac_key     per-module, wrapped with KIRK1_KEY
0x20  0x10  cmac_header_hash   CMAC over container[0x60..0x90]
0x30  0x10  cmac_data_hash     CMAC over container[0x60..end of payload]
0x40  0x20  unused       zero
0x60  0x04  mode         1
0x64  0x0C  unknown      zero
0x70  0x04  data_size    payload size before alignment
0x74  0x04  data_offset  0x80
0x78  0x18  unknown      zero
```

Note the file's payload begins at 0x150, which is exactly container offset
0x110. That is not a coincidence: the decrypter builds the container *around*
the file so the payload never has to be moved.

## 4. What the PSP actually validates

This is the crux. For tag `0xADF305F0` (PPSSPP's "type 2" path) the checks are:

1. The signature region at 0xD4..0x12C **must be all zero**. If it is not, this
   code path is rejected outright.
2. A **SHA-1** stored at 0x12C must match a digest over
   `tag || keystream[0..0x10] || zeros(0x58) || id || key_block || size_metadata || metadata`.
3. KIRK CMD1 then checks the two **CMAC** tags using the per-module CMAC key.

**There is no signature anywhere in this chain.** The only integrity primitives
are SHA-1 (unkeyed) and CMAC under a key that is wrapped with `KIRK1_KEY` — a
value published in every open-source KIRK implementation.

Therefore every input to every check is either data we choose or key material we
hold. All of it can be recomputed for an arbitrary payload size.

## 5. Why the legacy tool needed fixed-size templates

The legacy encrypter never recomputes anything. It:

1. picks the smallest prebuilt template whose `data_size` ≥ the input size,
2. copies the template's KIRK header and `~PSP` header verbatim,
3. encrypts the payload,
4. **restores the template's original CMAC tags**, discarding the ones it just
   computed,
5. rewrites the last 16 bytes of the payload so the stale data CMAC becomes
   correct again (the "forge" step).

Because `data_size` lives inside the copied header and the SHA-1 is copied too,
the output size is whatever the chosen template's capacity happens to be. A
4 KiB input becomes 368,544 bytes; a 700 KiB input becomes 5,583,952 bytes.

The forge step is what makes step 4 survivable, and it is the reason the
approach works at all — but it is only *necessary* because the tool declines to
recompute the tags it is perfectly capable of computing.

## 6. Consequences for this implementation

- No templates. The `~PSP` header is generated from the input module and the
  actual payload size.
- No forging on the encryption path. The CMAC tags are computed correctly the
  first time. (`kirk::forge` is still implemented and tested, because it is
  needed to understand and validate legacy files.)
- Output size is exactly `0x150 + align16(payload_size)`.
- Output is deterministic: the per-module keys are derived from the payload
  rather than drawn from an RNG, so the same input always produces the same
  bytes.

## 7. What remains static

Only these, and each for a stated reason:

| Data | Why it must stay fixed |
| --- | --- |
| `KIRK1_KEY` | hardware key that wraps the per-module keys |
| KIRK 4/7 key slot 0x60 | hardware key the tag's key stream derives from |
| tag `0xADF305F0` and its 16-byte seed | selects the above; identifies the scheme |
| `decrypt_mode` = 0x0D | selects this decryption path in the loader |
| `data_offset` = 0x80 | the predata is the metadata region, whose size is fixed |
| signature region = zeros | required by this scheme |

Everything else is computed.

## 8. Validation

The claims above are tested rather than asserted:

- `tests/compatibility.rs` parses, verifies and fully decrypts a file produced
  by the **reference PSPSDK tool**. The SHA-1 and both CMAC tags are recomputed
  during that check, so passing it means the key stream, the field layout and
  the container reconstruction all match the real format.
- `scripts/cross-validate.sh` builds PPSSPP's own `PrxDecrypter` and runs it
  against this crate's output, confirming an independent implementation accepts
  the files and recovers the original module byte for byte.
