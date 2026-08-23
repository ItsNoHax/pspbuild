//! Construction of the encrypted PRX.
//!
//! # Layout
//!
//! The output is exactly:
//!
//! ```text
//! 0x000  ~PSP header            0x150 bytes
//! 0x150  encrypted payload      align16(payload_size) bytes
//! ```
//!
//! Internally the KIRK container is laid out as
//! `CMD1 header (0x90) || predata (0x80) || payload`, where the predata is a
//! verbatim copy of the `~PSP` metadata region. The container's first 0x110
//! bytes are folded into the `~PSP` header rather than written out, which is
//! why the file body starts at the payload.
//!
//! # Sizing
//!
//! Every size field is derived from the actual payload:
//!
//! ```text
//! comp_size = payload.len()                     (post-compression)
//! psp_size  = 0x150 + align16(comp_size)        (= total file size)
//! elf_size  = original uncompressed input size
//! ```
//!
//! No fixed-capacity template is consulted, so a 700 KiB module produces a
//! ~700 KiB file.

use crate::crypto::sha1::sha1_chunks;
use crate::error::{Error, Result};
use crate::format::align_to_block;
use crate::kirk::commands::cmd0_encrypt;
use crate::kirk::header::{HEADER_SIZE as KIRK_HEADER_SIZE, KirkCmd1Header};
use crate::prx::parser::ModuleInfo;
use crate::psp::header::{METADATA_SIZE, PSP_HEADER_SIZE, PspModuleHeader};
use crate::psp::tag::{HeaderFields, TagInfo, build_header};

/// Bytes of predata between the KIRK header and the payload. This region holds
/// the `~PSP` metadata copy, so it is fixed by the format.
pub const DATA_OFFSET: u32 = METADATA_SIZE as u32;

/// Offset in the KIRK container where the on-disk payload begins.
const CONTAINER_PAYLOAD_OFFSET: usize = KIRK_HEADER_SIZE + DATA_OFFSET as usize;

/// Largest payload we will build a container for (64 MiB), a sanity bound well
/// above any real PSP module.
pub const MAX_PAYLOAD: u64 = 64 * 1024 * 1024;

/// Default devkit version written into the header.
///
/// Zero, which is what the legacy tool's largest template carries and what
/// booted on retail OFW. Non-zero values (`0x03070110`, `0x06060010`) were
/// both rejected on hardware, so do not "improve" this without testing.
pub const DEFAULT_DEVKIT_VERSION: u32 = 0;

/// The decryption mode the loader uses to select this scheme. Constant across
/// every genuine module examined that uses this tag.
pub const DECRYPT_MODE: u8 = 0x0D;

/// `mod_attribute` used by every genuine Sony module examined with this tag.
///
/// The input module's own attribute is normally the right thing to copy, but
/// all three legacy templates carry `0x0200` regardless of the game, which
/// suggests the loader expects it on an encrypted module.
pub const COMPAT_MOD_ATTRIBUTE: u16 = 0x0200;

/// Module version carried by every genuine module examined with this tag.
pub const COMPAT_MODULE_VERSION: (u8, u8) = (1, 1);

/// Inputs to a build.
pub struct BuildRequest<'a> {
    /// Parsed metadata from the input module.
    pub module: &'a ModuleInfo,
    /// The payload to encrypt, already compressed if compression is enabled.
    pub payload: &'a [u8],
    /// Whether `payload` is gzip-compressed.
    pub compressed: bool,
    /// Size of the original, uncompressed input.
    pub uncompressed_size: u32,
    /// Encryption tag to emit.
    pub tag: &'a TagInfo,
    /// Use the metadata values observed in genuine Sony modules instead of the
    /// ones derived from the input, for the few fields where the correct
    /// choice is ambiguous. Retail OFW rejects the derived values, so this
    /// defaults to on.
    pub compat_metadata: bool,
}

/// A built encrypted PRX plus the numbers describing it.
pub struct BuildOutput {
    pub data: Vec<u8>,
    pub payload_size: u32,
    pub aligned_payload_size: u32,
}

/// Derive the per-module AES and CMAC keys deterministically.
///
/// These keys are wrapped with the publicly known KIRK1 key, so they provide no
/// real secrecy and there is nothing to gain from randomness. Deriving them
/// from the payload instead makes the whole output reproducible: the same input
/// always yields byte-identical output.
fn derive_keys(payload: &[u8], uncompressed_size: u32) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let derive = |domain: &[u8]| -> [u8; 16] {
        let digest = sha1_chunks(&[
            b"prx-encrypter/v1",
            domain,
            &uncompressed_size.to_le_bytes(),
            payload,
        ]);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    };
    (derive(b"aes"), derive(b"cmac"), derive(b"id"))
}

/// Build the `~PSP` metadata region for this module and payload.
fn build_metadata(request: &BuildRequest<'_>, payload_size: u32) -> Result<PspModuleHeader> {
    let module = request.module;

    let aligned = align_to_block(u64::from(payload_size));
    let psp_size = PSP_HEADER_SIZE as u64 + aligned;
    let psp_size = u32::try_from(psp_size).map_err(|_| Error::PayloadTooLarge {
        size: psp_size,
        max: u32::MAX as u64,
    })?;

    let (mod_attribute, version) = if request.compat_metadata {
        (COMPAT_MOD_ATTRIBUTE, COMPAT_MODULE_VERSION)
    } else {
        (module.attributes, (module.version_lo, module.version_hi))
    };

    let mut header = PspModuleHeader {
        mod_attribute,
        comp_attribute: 0,
        module_ver_lo: version.0,
        module_ver_hi: version.1,
        modname: module.name.clone(),
        mod_version: 1,
        nsegments: module.segments.len() as u8,
        elf_size: request.uncompressed_size,
        psp_size,
        boot_entry: module.entry,
        modinfo_offset: module.modinfo_offset,
        bss_size: module.bss_size(),
        devkit_version: DEFAULT_DEVKIT_VERSION,
        decrypt_mode: DECRYPT_MODE,
        ..Default::default()
    };
    header.set_compressed(request.compressed);

    // `seg_size` is the segment's size *in the file*, not its memory size.
    // The header tracks uninitialised memory separately in `bss_size`, so
    // using p_memsz here would count the bss twice. Hardware confirmed this:
    // a build using p_memsz (7.9 MB against a 498 KB module) failed to load,
    // and crashed outright once compression was added on top.
    for (i, seg) in module.segments.iter().enumerate() {
        header.seg_align[i] = u16::try_from(seg.align).unwrap_or(0x10);
        header.seg_address[i] = seg.address;
        header.seg_size[i] = seg.file_size;
    }

    Ok(header)
}

/// Build the complete encrypted PRX.
pub fn build(request: &BuildRequest<'_>) -> Result<BuildOutput> {
    if request.payload.is_empty() {
        return Err(Error::InvalidPrxHeader("payload is empty".into()));
    }
    if request.payload.len() as u64 > MAX_PAYLOAD {
        return Err(Error::PayloadTooLarge {
            size: request.payload.len() as u64,
            max: MAX_PAYLOAD,
        });
    }
    let payload_size =
        u32::try_from(request.payload.len()).map_err(|_| Error::PayloadTooLarge {
            size: request.payload.len() as u64,
            max: MAX_PAYLOAD,
        })?;

    let metadata = build_metadata(request, payload_size)?.to_bytes();
    let (aes_key, cmac_key, id) = derive_keys(request.payload, request.uncompressed_size);

    // --- Assemble the plaintext KIRK container ---
    let kirk_header = KirkCmd1Header::new(aes_key, cmac_key, payload_size, DATA_OFFSET);
    let container_size = kirk_header.container_size() as usize;
    let mut container = vec![0u8; container_size];
    container[..KIRK_HEADER_SIZE].copy_from_slice(&kirk_header.to_bytes());
    container[KIRK_HEADER_SIZE..CONTAINER_PAYLOAD_OFFSET].copy_from_slice(&metadata);
    container[CONTAINER_PAYLOAD_OFFSET..CONTAINER_PAYLOAD_OFFSET + request.payload.len()]
        .copy_from_slice(request.payload);
    // Any bytes between the payload and the 16-byte boundary stay zero.

    // --- Encrypt and authenticate ---
    cmd0_encrypt(&mut container)?;

    // --- Fold the container head into the ~PSP header ---
    let mut key_block = [0u8; 0x40];
    key_block.copy_from_slice(&container[..0x40]);
    let mut size_metadata = [0u8; 0x10];
    size_metadata.copy_from_slice(&container[0x70..0x80]);

    let psp_header = build_header(
        request.tag,
        &HeaderFields {
            metadata,
            key_block,
            size_metadata,
            id,
        },
    )?;

    // --- Emit ---
    let aligned_payload_size = align_to_block(u64::from(payload_size)) as u32;
    let mut data = Vec::with_capacity(PSP_HEADER_SIZE + aligned_payload_size as usize);
    data.extend_from_slice(&psp_header);
    data.extend_from_slice(&container[CONTAINER_PAYLOAD_OFFSET..]);

    // Invariants that must hold before this file is written anywhere.
    assert_eq!(
        data.len(),
        PSP_HEADER_SIZE + aligned_payload_size as usize,
        "file size must be header + aligned payload"
    );

    Ok(BuildOutput {
        data,
        payload_size,
        aligned_payload_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prx::parser::{parse_module, tests::synthetic_prx};
    use crate::psp::tag::TAG_DEMO_280;

    fn request<'a>(module: &'a ModuleInfo, payload: &'a [u8]) -> BuildRequest<'a> {
        BuildRequest {
            module,
            payload,
            compressed: false,
            uncompressed_size: module.elf_size,
            tag: &TAG_DEMO_280,
            compat_metadata: true,
        }
    }

    #[test]
    fn output_size_is_header_plus_aligned_payload() {
        let elf = synthetic_prx("sizing", 4096);
        let module = parse_module(&elf).unwrap();
        for extra in [0usize, 1, 15, 16, 17] {
            let payload = vec![0xABu8; 1000 + extra];
            let out = build(&request(&module, &payload)).unwrap();
            let expected = PSP_HEADER_SIZE + align_to_block(payload.len() as u64) as usize;
            assert_eq!(out.data.len(), expected, "payload {}", payload.len());
        }
    }

    #[test]
    fn a_700_kib_payload_stays_700_kib() {
        // The headline requirement: no fixed-capacity expansion.
        let elf = synthetic_prx("big_module", 16);
        let module = parse_module(&elf).unwrap();
        let payload = vec![0x77u8; 716_800];
        let out = build(&request(&module, &payload)).unwrap();
        assert_eq!(out.data.len(), PSP_HEADER_SIZE + 716_800);
        // Overhead is a fixed 336-byte header, not a template's capacity. The
        // legacy tool emits 5,583,952 bytes for this input.
        assert_eq!(out.data.len() - 716_800, PSP_HEADER_SIZE);
        assert!(out.data.len() < 1_000_000);
    }

    #[test]
    fn sizes_are_recorded_in_the_header() {
        let elf = synthetic_prx("m", 2048);
        let module = parse_module(&elf).unwrap();
        let payload = vec![0u8; 1001];
        let out = build(&request(&module, &payload)).unwrap();

        let meta = PspModuleHeader::parse(&out.data).unwrap();
        assert_eq!(meta.elf_size, module.elf_size);
        assert_eq!(meta.psp_size as usize, out.data.len());
        assert_eq!(meta.boot_entry, module.entry);
        assert_eq!(meta.modname, "m");
        assert_eq!(meta.nsegments, 1);
        assert_eq!(meta.decrypt_mode, DECRYPT_MODE);
    }

    #[test]
    fn output_is_deterministic() {
        let elf = synthetic_prx("determinism", 512);
        let module = parse_module(&elf).unwrap();
        let payload = vec![0x42u8; 5000];
        let a = build(&request(&module, &payload)).unwrap();
        let b = build(&request(&module, &payload)).unwrap();
        assert_eq!(a.data, b.data);
    }

    #[test]
    fn different_payloads_produce_different_output() {
        let elf = synthetic_prx("m", 512);
        let module = parse_module(&elf).unwrap();
        let a = build(&request(&module, &vec![1u8; 4096])).unwrap();
        let b = build(&request(&module, &vec![2u8; 4096])).unwrap();
        assert_ne!(a.data, b.data);
    }

    #[test]
    fn payload_is_actually_encrypted() {
        let elf = synthetic_prx("m", 512);
        let module = parse_module(&elf).unwrap();
        let payload = vec![0x5Au8; 4096];
        let out = build(&request(&module, &payload)).unwrap();
        assert!(
            !out.data[PSP_HEADER_SIZE..]
                .windows(16)
                .any(|w| w == [0x5Au8; 16])
        );
    }

    #[test]
    fn compression_flag_is_recorded() {
        let elf = synthetic_prx("m", 512);
        let module = parse_module(&elf).unwrap();
        let payload = vec![0u8; 256];
        let mut req = request(&module, &payload);
        req.compressed = true;
        let out = build(&req).unwrap();
        assert!(PspModuleHeader::parse(&out.data).unwrap().is_compressed());
    }

    /// Regression: a build using `p_memsz` here failed on hardware. The
    /// header carries `bss_size` separately, so segment sizes are file sizes
    /// and memory sizes would double-count the bss.
    #[test]
    fn segment_sizes_are_file_sizes_with_bss_tracked_separately() {
        let elf = synthetic_prx("segments", 4096);
        let module = parse_module(&elf).unwrap();
        assert!(module.segments[0].mem_size > module.segments[0].file_size);

        let out = build(&request(&module, &[0u8; 900])).unwrap();
        let meta = PspModuleHeader::parse(&out.data).unwrap();

        assert_eq!(meta.seg_size[0], module.segments[0].file_size);
        assert_ne!(meta.seg_size[0], module.segments[0].mem_size);
        assert_eq!(meta.bss_size, module.bss_size());
        // Together they account for the segment's memory footprint exactly once.
        assert_eq!(
            u64::from(meta.seg_size[0]) + u64::from(meta.bss_size),
            u64::from(module.segments[0].mem_size)
        );
    }

    /// Hardware rejected `0x03070110` (invented) and `0x06060010`; the value
    /// that booted was zero, which is also what a genuine template carries.
    #[test]
    fn devkit_version_matches_what_booted_on_hardware() {
        let elf = synthetic_prx("devkit", 512);
        let module = parse_module(&elf).unwrap();
        let out = build(&request(&module, &[0u8; 256])).unwrap();
        let meta = PspModuleHeader::parse(&out.data).unwrap();
        assert_eq!(meta.devkit_version, 0);
    }

    #[test]
    fn empty_payloads_are_rejected() {
        let elf = synthetic_prx("m", 512);
        let module = parse_module(&elf).unwrap();
        assert!(build(&request(&module, &[])).is_err());
    }
}
