//! A Rust implementation of PSP PRX encryption.
//!
//! Encrypts a PSP module into a `~PSP` encrypted PRX, sizing the output from
//! the actual payload rather than from a fixed-capacity template.
//!
//! ```no_run
//! use pspbuild::{EncryptOptions, encrypt_prx};
//!
//! let input = std::fs::read("game.prx")?;
//! let encrypted = encrypt_prx(&input, &EncryptOptions::default())?;
//! std::fs::write("game.enc.prx", encrypted.data)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Pipeline
//!
//! ```text
//! parse PRX -> extract payload -> optional compression
//!           -> size the container -> KIRK CMD0 -> ~PSP header -> file
//! ```

pub mod audio;
pub mod crypto;
pub mod eg;
pub mod error;
pub mod format;
pub mod inspect;
pub mod iso;
pub mod kirk;
pub mod mg;
pub mod npdrm;
pub mod pbp;
pub mod prx;
pub mod psp;
pub mod sfo;

pub use error::{Error, Result};
pub use sfo::{Category, Sfo};

use crate::format::align_to_block;
use crate::kirk::commands::cmd1_decrypt;
use crate::kirk::header::{HEADER_SIZE as KIRK_HEADER_SIZE, KirkCmd1Header};
use crate::pbp::Pbp;
use crate::prx::builder::{self, BuildRequest, DATA_OFFSET};
use crate::prx::parser::{ModuleInfo, parse_module};
use crate::psp::header::{METADATA_SIZE, PSP_HEADER_SIZE, PspModuleHeader};
use crate::psp::tag::{self, TAG_DEMO_280};

/// Options controlling encryption.
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// Compress the payload with gzip before encrypting.
    pub compress: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        EncryptOptions {
            // The reference implementation compresses for all but its largest
            // template, and compression only shrinks the result.
            compress: true,
        }
    }
}

/// What kind of file the encrypter produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Container {
    /// A bare encrypted PRX.
    #[default]
    Prx,
    /// A PBP container whose DATA.PSP section was encrypted.
    Pbp,
}

/// The result of an encryption.
#[derive(Debug, Clone)]
pub struct Encrypted {
    /// The encrypted PRX.
    pub data: Vec<u8>,
    /// Size of the input module.
    pub input_size: u32,
    /// Size of the payload actually encrypted, after any compression.
    pub payload_size: u32,
    /// That size rounded up to the AES block size.
    pub aligned_payload_size: u32,
    /// Whether the payload was compressed.
    pub compressed: bool,
    /// The container that was written.
    pub container: Container,
}

/// Encrypt a PSP module.
pub fn encrypt_prx(input: &[u8], options: &EncryptOptions) -> Result<Encrypted> {
    // An EBOOT.PBP carries the module in its DATA.PSP section. Encrypt that
    // section and hand back a rebuilt container, so homebrew can be encrypted
    // in the form it actually ships in.
    if Pbp::is_pbp(input) {
        let mut container = Pbp::parse(input)?;
        if container.data_psp().is_empty() {
            return Err(Error::InvalidPrxHeader(
                "PBP has an empty DATA.PSP section; nothing to encrypt".into(),
            ));
        }
        let encrypted = encrypt_prx(container.data_psp(), options)?;
        container.set_data_psp(encrypted.data);
        return Ok(Encrypted {
            data: container.to_bytes(),
            container: Container::Pbp,
            ..encrypted
        });
    }

    let module = parse_module(input)?;

    // Compression runs before any size is committed to, so the container is
    // always sized from the post-compression payload.
    let (payload, compressed) = if options.compress {
        let compressed = prx::compression::gzip_compress(input)?;
        if compressed.len() < input.len() {
            (compressed, true)
        } else {
            // Compression made it bigger (tiny or incompressible input).
            (input.to_vec(), false)
        }
    } else {
        (input.to_vec(), false)
    };

    let built = builder::build(&BuildRequest {
        module: &module,
        payload: &payload,
        compressed,
        uncompressed_size: module.elf_size,
        tag: &TAG_DEMO_280,
    })?;

    Ok(Encrypted {
        data: built.data,
        input_size: module.elf_size,
        payload_size: built.payload_size,
        aligned_payload_size: built.aligned_payload_size,
        compressed,
        container: Container::Prx,
    })
}

/// Look through a PBP container to the module it carries.
///
/// Inspection, verification and decryption all accept either a bare PRX or an
/// EBOOT.PBP, since that is how homebrew ships.
fn module_bytes(data: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    if Pbp::is_pbp(data) {
        let container = Pbp::parse(data)?;
        Ok(std::borrow::Cow::Owned(container.data_psp().to_vec()))
    } else {
        Ok(std::borrow::Cow::Borrowed(data))
    }
}

/// A description of an encrypted or plain PRX.
#[derive(Debug, Clone)]
pub struct PrxInfo {
    /// Human-readable format name.
    pub format: &'static str,
    pub encrypted: bool,
    pub compressed: bool,
    /// Size of the decrypted module, when known.
    pub payload_size: Option<u32>,
    /// Size of the encrypted KIRK payload, when known.
    pub kirk_payload_size: Option<u32>,
    pub total_size: u64,
    pub module_name: String,
    pub segments: Vec<(u32, u32)>,
    pub entry_point: u32,
    /// Encryption tag, when encrypted.
    pub tag: Option<u32>,
}

/// Inspect a PRX, encrypted or not.
pub fn inspect_prx(data: &[u8]) -> Result<PrxInfo> {
    let data = &*module_bytes(data)?;
    // An encrypted PRX starts with the ~PSP magic.
    if data.len() >= METADATA_SIZE && data[..4] == psp::header::PSP_MAGIC {
        let meta = PspModuleHeader::parse(data)?;
        let tag_value = if data.len() >= PSP_HEADER_SIZE {
            Some(u32::from_le_bytes(
                data[0xD0..0xD4].try_into().expect("4 bytes"),
            ))
        } else {
            None
        };
        let kirk_payload_size = u32::try_from(data.len().saturating_sub(PSP_HEADER_SIZE)).ok();

        return Ok(PrxInfo {
            format: "PSP PRX (encrypted)",
            encrypted: true,
            compressed: meta.is_compressed(),
            payload_size: Some(meta.elf_size),
            kirk_payload_size,
            total_size: data.len() as u64,
            module_name: meta.modname,
            segments: (0..meta.nsegments.min(4) as usize)
                .map(|i| (meta.seg_address[i], meta.seg_size[i]))
                .collect(),
            entry_point: meta.boot_entry,
            tag: tag_value,
        });
    }

    // Otherwise treat it as a plain ELF module.
    let module = parse_module(data)?;
    Ok(PrxInfo {
        format: if module.is_prx {
            "PSP PRX (plain)"
        } else {
            "PSP executable (plain)"
        },
        encrypted: false,
        compressed: false,
        payload_size: Some(module.elf_size),
        kirk_payload_size: None,
        total_size: data.len() as u64,
        module_name: module.name.clone(),
        segments: module
            .segments
            .iter()
            .map(|s| (s.address, s.file_size))
            .collect(),
        entry_point: module.entry,
        tag: None,
    })
}

/// The outcome of verifying an encrypted PRX.
#[derive(Debug, Clone)]
pub struct Verification {
    /// Checks that passed, in the order they ran.
    pub checks: Vec<String>,
    /// Size of the recovered module.
    pub recovered_size: u32,
    /// Whether the recovered payload is a parseable PSP module.
    pub module: Option<ModuleInfo>,
    /// The validator's view of the container's `SND0.AT3`, when it has one.
    pub snd0: Option<audio::At3Report>,
}

/// Verify an encrypted PRX as thoroughly as the format allows.
///
/// This reconstructs the KIRK container, checks the header SHA-1 and both CMAC
/// tags, decrypts the payload, decompresses it if needed, and re-parses the
/// result as a PSP module.
pub fn verify_prx(data: &[u8]) -> Result<Verification> {
    let mut checks = Vec::new();
    let mut snd0 = None;
    if Pbp::is_pbp(data) {
        let container = Pbp::parse(data)?;
        checks.push("PBP container structure".into());
        let music = container.section(pbp::PbpSection::Snd0At3);
        if !music.is_empty() {
            let report = audio::inspect_at3(music);
            if let Some(problems) = report.failure_summary(false) {
                return Err(Error::IntegrityCheck(format!("SND0.AT3: {problems}")));
            }
            checks.push(format!(
                "SND0.AT3 is ATRAC3 the XMB can play ({} frames)",
                report.frames
            ));
            snd0 = Some(report);
        }
    }
    let data = &*module_bytes(data)?;

    if data.len() < PSP_HEADER_SIZE {
        return Err(Error::TooShort {
            expected: PSP_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // 1. Header structure and integrity hash.
    let (_info, fields) = tag::parse_header(data)?;
    checks.push("~PSP header SHA-1".into());

    let meta = PspModuleHeader::parse(&fields.metadata)?;
    checks.push("~PSP metadata structure".into());

    // 2. Declared sizes must agree with the file.
    let kirk_header = KirkCmd1Header::parse(&rebuild_kirk_header(&fields)?)?;
    kirk_header.validate()?;

    let expected_len = PSP_HEADER_SIZE as u64 + kirk_header.aligned_data_size();
    if expected_len != data.len() as u64 {
        return Err(Error::IntegrityCheck(format!(
            "file is {} bytes but the header describes {expected_len}",
            data.len()
        )));
    }
    if u64::from(meta.psp_size) != data.len() as u64 {
        return Err(Error::IntegrityCheck(format!(
            "psp_size is {} but the file is {} bytes",
            meta.psp_size,
            data.len()
        )));
    }
    checks.push("declared sizes match the file".into());

    // 3. Rebuild the KIRK container and check both CMAC tags.
    let mut container = Vec::with_capacity(kirk_header.container_size() as usize);
    container.extend_from_slice(&rebuild_kirk_header(&fields)?);
    container.extend_from_slice(&fields.metadata);
    container.extend_from_slice(&data[PSP_HEADER_SIZE..]);

    let payload = cmd1_decrypt(&container, true)?;
    checks.push("KIRK header and data CMAC".into());

    // 4. Decompress and re-parse.
    let recovered = if meta.is_compressed() {
        let out = prx::compression::gzip_decompress(&payload)?;
        checks.push("gzip payload decompresses".into());
        out
    } else {
        payload
    };

    if recovered.len() as u32 != meta.elf_size {
        return Err(Error::IntegrityCheck(format!(
            "recovered {} bytes but elf_size is {}",
            recovered.len(),
            meta.elf_size
        )));
    }
    checks.push("recovered size matches elf_size".into());

    let module = match parse_module(&recovered) {
        Ok(m) => {
            checks.push("recovered payload is a valid PSP module".into());
            Some(m)
        }
        Err(_) => None,
    };

    Ok(Verification {
        checks,
        recovered_size: recovered.len() as u32,
        module,
        snd0,
    })
}

/// Decrypt an encrypted PRX back to the original module.
pub fn decrypt_prx(data: &[u8]) -> Result<Vec<u8>> {
    let data = &*module_bytes(data)?;
    if data.len() < PSP_HEADER_SIZE {
        return Err(Error::TooShort {
            expected: PSP_HEADER_SIZE,
            actual: data.len(),
        });
    }
    let (_info, fields) = tag::parse_header(data)?;
    let meta = PspModuleHeader::parse(&fields.metadata)?;

    let mut container = Vec::new();
    container.extend_from_slice(&rebuild_kirk_header(&fields)?);
    container.extend_from_slice(&fields.metadata);
    container.extend_from_slice(&data[PSP_HEADER_SIZE..]);

    let payload = cmd1_decrypt(&container, true)?;
    if meta.is_compressed() {
        prx::compression::gzip_decompress(&payload)
    } else {
        Ok(payload)
    }
}

/// Reassemble the 0x90-byte KIRK CMD1 header from the scattered `~PSP` fields.
fn rebuild_kirk_header(fields: &tag::HeaderFields) -> Result<[u8; KIRK_HEADER_SIZE]> {
    let mut header = [0u8; KIRK_HEADER_SIZE];
    header[..0x40].copy_from_slice(&fields.key_block);
    header[0x70..0x80].copy_from_slice(&fields.size_metadata);
    // `mode` is implied by the scheme rather than stored on disk.
    header[0x60..0x64].copy_from_slice(&kirk::header::MODE_CMD1.to_le_bytes());

    // Guard against a header that claims an implausible layout.
    let data_offset = u32::from_le_bytes(header[0x74..0x78].try_into().expect("4 bytes"));
    if data_offset != DATA_OFFSET {
        return Err(Error::InvalidKirkHeader(format!(
            "data_offset is {data_offset:#X}, expected {DATA_OFFSET:#X}"
        )));
    }
    Ok(header)
}

/// Total output size for a payload of `payload_size` bytes.
pub fn output_size_for(payload_size: u64) -> u64 {
    PSP_HEADER_SIZE as u64 + align_to_block(payload_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prx::parser::tests::synthetic_prx;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        for size in [16usize, 1000, 4096, 100_000] {
            let elf = synthetic_prx("round_trip", size);
            let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();
            assert_eq!(decrypt_prx(&enc.data).unwrap(), elf, "size {size}");
        }
    }

    #[test]
    fn round_trips_without_compression() {
        let elf = synthetic_prx("no_compress", 4096);
        let options = EncryptOptions { compress: false };
        let enc = encrypt_prx(&elf, &options).unwrap();
        assert!(!enc.compressed);
        assert_eq!(enc.payload_size as usize, elf.len());
        assert_eq!(decrypt_prx(&enc.data).unwrap(), elf);
    }

    #[test]
    fn verify_accepts_our_own_output() {
        let elf = synthetic_prx("verify_me", 8192);
        let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();
        let v = verify_prx(&enc.data).unwrap();
        assert_eq!(v.recovered_size as usize, elf.len());
        assert!(v.module.is_some());
        assert!(v.checks.iter().any(|c| c.contains("CMAC")));
    }

    #[test]
    fn verify_rejects_tampering_anywhere() {
        let elf = synthetic_prx("tamper", 4096);
        let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();
        let last = enc.data.len() - 1;
        for offset in [0usize, 0x28, 0x80, 0xB0, 0xC0, 0x140, PSP_HEADER_SIZE, last] {
            let mut bad = enc.data.clone();
            bad[offset] ^= 0x01;
            assert!(
                verify_prx(&bad).is_err(),
                "tampering at {offset:#X} accepted"
            );
        }
    }

    #[test]
    fn verify_rejects_truncation_and_extension() {
        let elf = synthetic_prx("trunc", 4096);
        let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();

        let mut short = enc.data.clone();
        short.truncate(short.len() - 16);
        assert!(verify_prx(&short).is_err());

        let mut long = enc.data.clone();
        long.extend_from_slice(&[0u8; 16]);
        assert!(verify_prx(&long).is_err());
    }

    #[test]
    fn compression_shrinks_a_compressible_module() {
        // A module full of zeros compresses hard; the output must track the
        // compressed size, not the input size.
        let elf = synthetic_prx("compressible", 200_000);
        let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();
        assert!(enc.compressed);
        assert!(enc.data.len() < 20_000, "got {}", enc.data.len());
        assert_eq!(decrypt_prx(&enc.data).unwrap(), elf);
    }

    #[test]
    fn inspect_reports_both_plain_and_encrypted() {
        let elf = synthetic_prx("inspect_me", 2048);

        let plain = inspect_prx(&elf).unwrap();
        assert!(!plain.encrypted);
        assert_eq!(plain.module_name, "inspect_me");

        let enc = encrypt_prx(&elf, &EncryptOptions::default()).unwrap();
        let info = inspect_prx(&enc.data).unwrap();
        assert!(info.encrypted);
        assert_eq!(info.module_name, "inspect_me");
        assert_eq!(info.tag, Some(TAG_DEMO_280.tag));
        assert_eq!(info.total_size, enc.data.len() as u64);
    }

    #[test]
    fn malformed_input_never_panics() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 4],
            vec![0xFFu8; 1000],
            b"~PSP".to_vec(),
            {
                let mut v = b"~PSP".to_vec();
                v.extend_from_slice(&[0u8; 0x200]);
                v
            },
        ];
        for case in cases {
            let _ = encrypt_prx(&case, &EncryptOptions::default());
            let _ = inspect_prx(&case);
            let _ = verify_prx(&case);
            let _ = decrypt_prx(&case);
        }
    }

    #[test]
    fn pbp_containers_are_encrypted_in_place() {
        use crate::pbp::Pbp;

        let module = synthetic_prx("pbp_module", 20_000);
        let mut pbp = Pbp {
            version: 0x0001_0000,
            sections: [
                b"PARAM.SFO contents".to_vec(),
                b"icon bytes".to_vec(),
                Vec::new(),
                Vec::new(),
                b"pic1 bytes".to_vec(),
                Vec::new(),
                module.clone(),
                Vec::new(),
            ],
        };
        let original = pbp.to_bytes();

        let enc = encrypt_prx(&original, &EncryptOptions::default()).unwrap();
        assert_eq!(enc.container, Container::Pbp);

        // Still a PBP, and smaller than it was.
        let rebuilt = Pbp::parse(&enc.data).unwrap();
        assert!(enc.data.len() < original.len());

        // Every other section survives byte for byte.
        for i in [0usize, 1, 2, 3, 4, 5, 7] {
            assert_eq!(rebuilt.sections[i], pbp.sections[i], "section {i} changed");
        }
        assert_eq!(rebuilt.version, pbp.version);

        // The executable is now an encrypted PRX that round-trips.
        assert_eq!(&rebuilt.data_psp()[..4], b"~PSP");
        assert_eq!(decrypt_prx(&enc.data).unwrap(), module);

        // And the whole EBOOT verifies and inspects through the container.
        let v = verify_prx(&enc.data).unwrap();
        assert!(v.checks.iter().any(|c| c.contains("PBP")));
        let info = inspect_prx(&enc.data).unwrap();
        assert!(info.encrypted);
        assert_eq!(info.module_name, "pbp_module");

        pbp.set_data_psp(Vec::new());
        assert!(encrypt_prx(&pbp.to_bytes(), &EncryptOptions::default()).is_err());
    }

    #[test]
    fn output_size_helper_agrees_with_reality() {
        let elf = synthetic_prx("sizes", 1024);
        let options = EncryptOptions { compress: false };
        let enc = encrypt_prx(&elf, &options).unwrap();
        assert_eq!(output_size_for(elf.len() as u64), enc.data.len() as u64);
    }
}
