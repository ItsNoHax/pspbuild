# Encrypted PRX format

Layout of a `~PSP` encrypted module under tag `0xADF305F0`, and which fields the firmware checks.

References: PSPSDK `PrxEncrypter` (legacy encrypter) and PPSSPP `Core/ELF/PrxDecrypter.cpp` with `ext/libkirk` (decrypter). Field semantics follow the decrypter.

## 1. File layout

```text
0x000  ~PSP header         0x150 bytes
0x150  encrypted payload   align16(payload_size) bytes
```

No trailer.

## 2. `~PSP` header

```text
offset  len    field               source     notes
0x000   0x004  "~PSP"              static
0x004   0x002  mod_attribute       derived    | 0x0200 required (§7)
0x006   0x002  comp_attribute      derived    bit 0 = gzip payload
0x008   0x002  module version      derived    from module info
0x00A   0x01C  module name         derived    from module info
0x026   0x001  mod_version         static     1
0x027   0x001  nsegments           derived    PT_LOAD count
0x028   0x004  elf_size            derived    decompressed module size
0x02C   0x004  psp_size            derived    0x150 + align16(comp_size)
0x030   0x004  boot_entry          derived    e_entry
0x034   0x004  modinfo_offset      derived    first PT_LOAD p_paddr & 0x7FFFFFFF
0x038   0x004  bss_size            derived    Σ(p_memsz - p_filesz), unchecked (§8)
0x03C   0x008  seg_align[4]        derived
0x044   0x010  seg_address[4]      derived    p_vaddr
0x054   0x010  seg_size[4]         derived    p_filesz (§8)
0x064   0x014  reserved            static     0
0x078   0x004  devkit_version      derived    unchecked
0x07C   0x001  decrypt_mode        static     0x0D
0x07D   0x001  padding             static     0
0x07E   0x002  overlap_size        static     0
------  end of metadata; also the KIRK predata -----------------------
0x080   0x030  KIRK key block[0x00..0x30]    generated
0x0B0   0x010  KIRK size metadata             data_size, data_offset
0x0C0   0x010  KIRK key block[0x30..0x40]    generated
0x0D0   0x004  tag                  static    0xADF305F0
0x0D4   0x058  signature region     static    all zero
0x12C   0x014  SHA-1 of header      generated
0x140   0x010  id                   generated
```

`0x00..0x80` is copied verbatim into the KIRK container as predata, so it is covered by the data CMAC.

## 3. KIRK CMD1 container

Reconstructed by the decrypter; never stored as such.

```text
0x000  0x090  CMD1 header
0x090  0x080  predata (~PSP 0x00..0x80), plaintext
0x110  ...    payload, AES-128-CBC, zero IV, 16-byte aligned
```

CMD1 header:

```text
0x00  0x10  aes_key           per-module, wrapped with KIRK1_KEY
0x10  0x10  cmac_key          per-module, wrapped with KIRK1_KEY
0x20  0x10  cmac_header_hash  CMAC over container[0x60..0x90]
0x30  0x10  cmac_data_hash    CMAC over container[0x60..end]
0x40  0x20  unused            0
0x60  0x04  mode              1
0x64  0x0C  unknown           0
0x70  0x04  data_size         payload size before alignment
0x74  0x04  data_offset       0x80
0x78  0x18  unknown           0
```

File offset 0x150 equals container offset 0x110, so the payload is used in place.

## 4. Firmware checks

For tag `0xADF305F0`:

1. Signature region `0xD4..0x12C` is all zero.
2. SHA-1 at `0x12C` matches `tag || keystream[0..0x10] || zeros(0x58) || id || key_block || size_metadata || metadata`.
3. KIRK CMD1 verifies both CMACs with the per-module CMAC key.

No step involves a signature. The CMAC key is wrapped with the published `KIRK1_KEY`, so every check can be recomputed for any payload.

## 5. Differences from the legacy encrypter

| | `PrxEncrypter` | `pspbuild` |
| --- | --- | --- |
| Header | Copied from one of three templates | Computed |
| Output size | Template capacity (4 KiB input → 368,544 bytes) | `0x150 + align16(payload)` |
| CMAC | Template's tags restored; last 16 payload bytes forged to match | Computed |
| Keys | Template's | Derived from payload (deterministic) |

`kirk::forge` is implemented for reading legacy files; it is not used when encrypting.

## 6. Static values

| Value | Reason |
| --- | --- |
| `KIRK1_KEY` | Wraps per-module keys |
| KIRK 4/7 slot `0x60` | Key stream for this tag |
| Tag `0xADF305F0` and seed | Selects the scheme |
| `decrypt_mode` = 0x0D | Loader path |
| `data_offset` = 0x80 | Predata size |
| Signature region = 0 | Required by the scheme |
| `mod_attribute` \| 0x0200 | Required by firmware (§7) |

## 7. `mod_attribute` bit 0x0200

Required. Isolated on hardware, one field changed per build:

| Change from working build | Result |
| --- | --- |
| — | boots |
| `mod_attribute` 0x0200 → 0 | `80020148` |
| Module version 1.1 → 1.0 | boots |
| `devkit_version` 0 → 0x06060010 | boots |

The bit is OR-ed into the module's own attributes. Its meaning is unknown. PPSSPP only checks `0x1000` and accepts builds without it.

Most header errors surface as `80020148 UNSUPPORTED_PRX_TYPE`.

## 8. Size fields

| Field | Rule | Checked |
| --- | --- | --- |
| `seg_size[0]` | `p_filesz` | yes |
| `seg_size[n>0]` | `p_filesz` (Sony writes `p_memsz`) | no |
| `bss_size` | Σ(`p_memsz - p_filesz`) over `PT_LOAD` | no |
| `elf_size` | Decompressed module size | |
| `psp_size` | Whole encrypted file | |

Evidence:

| Module | `seg_size[0]` | `seg_size[1]` | `bss_size` | Result |
| --- | --- | --- | --- | --- |
| AngleZero, 1 segment | `p_memsz` | — | summed | fails; crashes when compressed |
| AngleZero, 1 segment | `p_filesz` | — | summed | boots |
| `APE ACADEMY 2`, Sony | `p_filesz`\* | `p_memsz` | `0xFFFA3130` | boots |
| `APE ACADEMY 2`, `pspbuild` | `p_filesz` | `p_filesz` | summed | boots |

\* Sony's segment 0 has `p_filesz == p_memsz` in both known fixtures; bss lives in a later segment.

Sony's `bss_size` is the negated `p_filesz` of the `PT_PRXRELOC` segment:

| Module | `PT_PRXRELOC` `p_filesz` | Sony `bss_size` |
| --- | ---: | ---: |
| `APE ACADEMY 2` | 380,624 | `0xFFFA3130` (−380,624) |
| `MotoGP` | 501,544 | `0xFFF858D8` (−501,544) |

`tests/genuine.rs` pins these divergences.

## 9. Validation

| Check | Coverage |
| --- | --- |
| `tests/compatibility.rs` | Verifies and decrypts a `PrxEncrypter` fixture, recomputing SHA-1 and both CMACs |
| `tests/genuine.rs` | Verifies and decrypts Sony builds; checks re-encrypted header fields (fixtures in `plans/`) |
| `scripts/cross-validate.sh` | PPSSPP's `PrxDecrypter` recovers the original module |
| Hardware | Compressed, dynamically sized EBOOTs boot on a PSP Slim, OFW |
