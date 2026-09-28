//! Format detection and structural inspection.
//!
//! Inspection answers "what is this file, and what is inside it" without
//! needing the caller to know in advance. That matters most for telling the two
//! security paths apart: an MG EBOOT and an EG EBOOT are both PBP containers,
//! and the difference is in `PARAM.SFO` and in what `DATA.PSP` and `DATA.PSAR`
//! actually hold.

use crate::error::{Error, Result};
use crate::pbp::{Pbp, PbpSection};
use crate::psp::header::PspModuleHeader;
use crate::sfo::{Category, Sfo};
use crate::{PrxInfo, inspect_prx};

/// A recognised file or section format.
///
/// Detection is by magic only. It says what a blob claims to be, not that it is
/// well formed — parsing decides that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// `EBOOT.PBP` container.
    Pbp,
    /// An encrypted `~PSP` module.
    EncryptedPrx,
    /// A plain ELF or PRX.
    PlainElf,
    /// `PARAM.SFO` parameter table.
    ParamSfo,
    /// NPDRM encrypted UMD image, the EG game archive.
    NpUmdImg,
    /// Decrypted PSP ISO image.
    PsIsoImg,
    /// Multi-disc title image.
    PsTitleImg,
    /// A PGD-encrypted blob.
    Pgd,
    /// PNG image.
    Png,
    /// RIFF/AT3 audio.
    Riff,
    /// PSMF/PMF video.
    Pmf,
    /// An ISO9660 image, i.e. a UMD.
    Iso9660,
    /// Nothing at all.
    Empty,
    /// Not recognised.
    Unknown,
}

/// Offset of the `CD001` standard identifier: sector 16, one byte in.
pub const ISO_MAGIC_OFFSET: usize = 16 * 2048 + 1;

impl FileFormat {
    /// Identify a blob by its magic.
    ///
    /// `data` may be a prefix of the file. Detecting an ISO needs the first
    /// 32 KiB, so callers that only pass a short prefix will not see one —
    /// which is why [`detect_prefix`](Self::detect_prefix) exists to make that
    /// requirement explicit.
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return FileFormat::Empty;
        }
        let starts = |magic: &[u8]| data.len() >= magic.len() && &data[..magic.len()] == magic;

        // Checked before the byte-zero magics: an ISO is identified deep in the
        // file, and its first sectors are conventionally zero.
        if data.len() >= ISO_MAGIC_OFFSET + 5
            && &data[ISO_MAGIC_OFFSET..ISO_MAGIC_OFFSET + 5] == b"CD001"
        {
            return FileFormat::Iso9660;
        }

        if starts(&crate::pbp::PBP_MAGIC) {
            FileFormat::Pbp
        } else if starts(&crate::psp::header::PSP_MAGIC) {
            FileFormat::EncryptedPrx
        } else if starts(b"\x7fELF") {
            FileFormat::PlainElf
        } else if starts(&crate::sfo::SFO_MAGIC) {
            FileFormat::ParamSfo
        } else if starts(b"NPUMDIMG") {
            FileFormat::NpUmdImg
        } else if starts(b"PSISOIMG") {
            FileFormat::PsIsoImg
        } else if starts(b"PSTITLEIMG") {
            FileFormat::PsTitleImg
        } else if starts(b"\x00PGD") {
            FileFormat::Pgd
        } else if starts(b"\x89PNG") {
            FileFormat::Png
        } else if starts(b"RIFF") {
            FileFormat::Riff
        } else if starts(b"PSMF") {
            FileFormat::Pmf
        } else {
            FileFormat::Unknown
        }
    }

    /// A human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            FileFormat::Pbp => "PBP container",
            FileFormat::EncryptedPrx => "PSP PRX (encrypted)",
            FileFormat::PlainElf => "ELF/PRX (plain)",
            FileFormat::ParamSfo => "PARAM.SFO",
            FileFormat::NpUmdImg => "NPUMDIMG (NPDRM UMD image)",
            FileFormat::PsIsoImg => "PSISOIMG (decrypted ISO image)",
            FileFormat::PsTitleImg => "PSTITLEIMG (multi-disc image)",
            FileFormat::Pgd => "PGD (encrypted)",
            FileFormat::Png => "PNG image",
            FileFormat::Riff => "RIFF/AT3 audio",
            FileFormat::Pmf => "PSMF video",
            FileFormat::Iso9660 => "ISO9660 image (UMD)",
            FileFormat::Empty => "empty",
            FileFormat::Unknown => "unrecognised",
        }
    }

    /// How many bytes [`detect`](Self::detect) needs to identify every format.
    ///
    /// Reading this much of a file is enough to classify it, which matters when
    /// the file is a 1.8 GB UMD that must not be loaded into memory.
    pub const fn detect_prefix() -> usize {
        ISO_MAGIC_OFFSET + 5
    }

    /// Whether a file of this format could contain a PSP executable.
    ///
    /// A `PARAM.SFO` or a PNG is not a broken module, it is simply not a
    /// module, and reporting a PRX parse failure for one is misleading.
    pub fn may_hold_executable(self) -> bool {
        matches!(
            self,
            FileFormat::EncryptedPrx | FileFormat::PlainElf | FileFormat::Unknown
        )
    }
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One section of an inspected container.
#[derive(Debug, Clone)]
pub struct SectionReport {
    pub section: PbpSection,
    pub offset: u32,
    pub size: u32,
    pub format: FileFormat,
}

/// The container-level view of a PBP.
#[derive(Debug, Clone)]
pub struct ContainerReport {
    pub version: u32,
    /// `CATEGORY`, i.e. which security path the firmware would run.
    pub category: Option<Category>,
    pub title: Option<String>,
    pub system_version: Option<String>,
    /// Why `PARAM.SFO` could not be read, when it could not.
    pub param_sfo_error: Option<String>,
    pub sections: Vec<SectionReport>,
    /// The validator's view of `SND0.AT3`, when there is one.
    pub snd0: Option<crate::audio::At3Report>,
}

/// One asset the EG pipeline looks for in an image.
#[derive(Debug, Clone)]
pub struct IsoAsset {
    pub path: String,
    /// `None` when the image does not carry it, which is normal.
    pub size: Option<u64>,
}

/// The contents of a UMD image.
#[derive(Debug, Clone)]
pub struct IsoReport {
    pub volume: crate::iso::VolumeInfo,
    pub entry_count: usize,
    /// The `PSP_GAME` assets that would become PBP sections.
    pub assets: Vec<IsoAsset>,
    pub eboot_size: Option<u64>,
    /// The `UMD_DATA.BIN` line, e.g. `ULUS-10380|...|0001|G`.
    pub disc_id: Option<String>,
    /// The image's own `PARAM.SFO`.
    pub param_sfo: Option<Sfo>,
}

/// What a file turned out to be.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub format: FileFormat,
    pub total_size: u64,
    /// Present when the file is a PBP.
    pub container: Option<ContainerReport>,
    /// Present when the file is an ISO.
    pub iso: Option<IsoReport>,
    /// A parameter table, when the file is one or carries one.
    pub param_sfo: Option<Sfo>,
    /// The executable, whether it was bare or inside a container.
    pub module: Option<PrxInfo>,
    /// Why the executable could not be read, when it could not.
    ///
    /// Only set for files that could plausibly hold one. A PNG does not get an
    /// error here; it simply has no executable.
    pub module_error: Option<String>,
}

impl Inspection {
    /// The declared category, when there is a container.
    pub fn category(&self) -> Option<&Category> {
        self.container.as_ref().and_then(|c| c.category.as_ref())
    }
}

/// Largest section this will read in full while streaming a container.
///
/// Enough for any `PARAM.SFO` or a `~PSP` module header, and far below the
/// gigabyte-scale `DATA.PSAR` that makes streaming necessary in the first
/// place.
const STREAM_SECTION_LIMIT: u32 = 1 << 20;

/// Inspect a PBP without loading it into memory.
///
/// An EG container is routinely over a gigabyte, nearly all of it `DATA.PSAR`,
/// so reading the whole file to report its structure is the wrong shape. Only
/// the header, the small sections and a magic-length prefix of each large one
/// are read.
pub fn inspect_pbp<R: std::io::Read + std::io::Seek>(
    mut source: R,
    total_size: u64,
) -> Result<Inspection> {
    use std::io::SeekFrom;

    let mut header = [0u8; crate::pbp::HEADER_SIZE];
    source.read_exact(&mut header).map_err(Error::BareIo)?;
    let layout = crate::pbp::parse_layout(&header, total_size)?;

    // Read a section, capped: small ones whole, large ones just far enough to
    // identify.
    let mut read_section = |offset: u32, size: u32| -> Result<Vec<u8>> {
        let want = size.min(STREAM_SECTION_LIMIT) as usize;
        if want == 0 {
            return Ok(Vec::new());
        }
        source
            .seek(SeekFrom::Start(u64::from(offset)))
            .map_err(Error::BareIo)?;
        let mut buf = vec![0u8; want];
        source.read_exact(&mut buf).map_err(Error::BareIo)?;
        Ok(buf)
    };

    let mut sections = Vec::with_capacity(crate::pbp::SECTION_COUNT);
    let mut param_sfo_raw = Vec::new();
    let mut data_psp_prefix = Vec::new();
    let mut snd0 = None;

    for section in PbpSection::ALL {
        let (offset, size) = layout.section(section);
        let prefix = read_section(offset, size)?;
        sections.push(SectionReport {
            section,
            offset,
            size,
            format: FileFormat::detect(&prefix),
        });
        match section {
            PbpSection::ParamSfo => param_sfo_raw = prefix,
            PbpSection::DataPsp => data_psp_prefix = prefix,
            PbpSection::Snd0At3 if size > 0 => {
                snd0 = Some(if size > STREAM_SECTION_LIMIT {
                    crate::audio::validate::oversized(size as usize)
                } else {
                    crate::audio::inspect_at3(&prefix)
                });
            }
            _ => {}
        }
    }

    let mut report = ContainerReport {
        version: layout.version,
        category: None,
        title: None,
        system_version: None,
        param_sfo_error: None,
        sections,
        snd0,
    };

    let mut param_sfo = None;
    if param_sfo_raw.is_empty() {
        report.param_sfo_error = Some("PBP has no PARAM.SFO section".into());
    } else {
        match Sfo::parse(&param_sfo_raw) {
            Ok(sfo) => {
                report.category = sfo.category();
                report.title = sfo.get_text("TITLE");
                report.system_version = sfo.get_text("PSP_SYSTEM_VER");
                param_sfo = Some(sfo);
            }
            Err(e) => report.param_sfo_error = Some(e.to_string()),
        }
    }

    let (module, module_error) = if data_psp_prefix.is_empty() {
        (None, Some("DATA.PSP is empty".to_string()))
    } else if report.category.as_ref().is_some_and(Category::is_npdrm) {
        let category = report.category.as_ref().expect("checked above");
        (
            None,
            Some(format!(
                "{category} is an NPDRM Store download; not supported yet"
            )),
        )
    } else {
        match inspect_prx(&data_psp_prefix) {
            Ok(info) => (Some(info), None),
            Err(e) => (None, Some(e.to_string())),
        }
    };

    Ok(Inspection {
        format: FileFormat::Pbp,
        total_size,
        container: Some(report),
        iso: None,
        param_sfo,
        module,
        module_error,
    })
}

/// Inspect a UMD image without loading it into memory.
pub fn inspect_iso<R: std::io::Read + std::io::Seek>(source: R) -> Result<IsoReport> {
    let mut iso = crate::iso::Iso::new(source)?;

    let assets = crate::iso::PSP_GAME_ASSETS
        .iter()
        .map(|(path, _)| IsoAsset {
            path: (*path).to_owned(),
            size: iso.file_size(path),
        })
        .collect();

    let disc_id = iso
        .read_optional(crate::iso::UMD_DATA_BIN)?
        .map(|raw| String::from_utf8_lossy(&raw).replace('\0', "").to_string());

    // A UMD whose PARAM.SFO does not parse is still worth reporting on, so a
    // failure here is dropped rather than failing the whole inspection.
    let param_sfo = iso
        .read_optional("/PSP_GAME/PARAM.SFO")?
        .and_then(|raw| Sfo::parse(&raw).ok());

    Ok(IsoReport {
        volume: iso.volume().clone(),
        entry_count: iso.entries().count(),
        assets,
        eboot_size: iso.file_size(crate::iso::EBOOT_BIN),
        disc_id,
        param_sfo,
    })
}

/// Inspect any supported file.
///
/// This never fails on a file it cannot understand: an unrecognised blob is
/// reported as unrecognised, and a container whose parts are unreadable reports
/// the parts it could read plus the reason for the rest. Only unreadable input
/// is an error.
pub fn inspect(data: &[u8]) -> Result<Inspection> {
    let format = FileFormat::detect(data);
    let total_size = data.len() as u64;

    if format == FileFormat::Iso9660 {
        // Only reachable when a caller handed over a whole image; the CLI
        // streams instead. Reuse the streaming path rather than duplicating it.
        let report = inspect_iso(std::io::Cursor::new(data))?;
        return Ok(Inspection {
            format,
            total_size,
            container: None,
            param_sfo: report.param_sfo.clone(),
            iso: Some(report),
            module: None,
            module_error: None,
        });
    }

    if format != FileFormat::Pbp {
        // A bare file. Only attempt to read a module out of it if it could
        // plausibly be one — a PARAM.SFO is not a broken PRX.
        let (module, module_error) = if format.may_hold_executable() {
            match inspect_prx(data) {
                Ok(info) => (Some(info), None),
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };
        let param_sfo = if format == FileFormat::ParamSfo {
            Sfo::parse(data).ok()
        } else {
            None
        };
        return Ok(Inspection {
            format,
            total_size,
            container: None,
            iso: None,
            param_sfo,
            module,
            module_error,
        });
    }

    let pbp = Pbp::parse(data)?;
    let mut report = ContainerReport {
        version: pbp.version,
        category: None,
        title: None,
        system_version: None,
        param_sfo_error: None,
        sections: pbp
            .layout()
            .into_iter()
            .map(|(section, offset, size)| SectionReport {
                section,
                offset,
                size,
                format: FileFormat::detect(pbp.section(section)),
            })
            .collect(),
        snd0: {
            let snd0 = pbp.section(PbpSection::Snd0At3);
            (!snd0.is_empty()).then(|| crate::audio::inspect_at3(snd0))
        },
    };

    let mut param_sfo = None;
    match pbp.param_sfo() {
        Ok(sfo) => {
            report.category = sfo.category();
            report.title = sfo.get_text("TITLE");
            report.system_version = sfo.get_text("PSP_SYSTEM_VER");
            param_sfo = Some(sfo);
        }
        Err(e) => report.param_sfo_error = Some(e.to_string()),
    }

    // The executable is only fully readable on the MG path. A Store download's
    // DATA.PSP is NPDRM-protected, which this crate cannot open yet, so say so
    // rather than letting a PRX parser fail confusingly against it.
    let data_psp = pbp.data_psp();
    let (module, module_error) = if data_psp.is_empty() {
        (None, Some("DATA.PSP is empty".to_string()))
    } else if report.category.as_ref().is_some_and(Category::is_npdrm) {
        let category = report.category.as_ref().expect("checked above");
        (
            None,
            Some(format!(
                "{category} is an NPDRM Store download; not supported yet"
            )),
        )
    } else {
        match inspect_prx(data_psp) {
            Ok(info) => (Some(info), None),
            Err(e) => (None, Some(e.to_string())),
        }
    };

    Ok(Inspection {
        format,
        total_size,
        container: Some(report),
        iso: None,
        param_sfo,
        module,
        module_error,
    })
}

/// Read the `~PSP` metadata of an encrypted module without decrypting it.
pub fn psp_header(data: &[u8]) -> Result<PspModuleHeader> {
    PspModuleHeader::parse(data)
}

/// Parse a standalone `PARAM.SFO`.
pub fn param_sfo(data: &[u8]) -> Result<Sfo> {
    Sfo::parse(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mg::{MgEbootRequest, build_mg_eboot};
    use crate::prx::parser::tests::synthetic_prx;
    use crate::sfo::{SfoEntry, mg_param_sfo};
    use crate::{EncryptOptions, encrypt_prx};

    fn mg_eboot() -> Vec<u8> {
        let module = synthetic_prx("inspectme", 20_000);
        build_mg_eboot(&MgEbootRequest {
            module: &module,
            compress: true,
            icon0: Some(b"\x89PNG\r\n\x1a\n and pixels".to_vec()),
            ..Default::default()
        })
        .unwrap()
        .data
    }

    #[test]
    fn detects_the_formats_it_claims_to() {
        assert_eq!(FileFormat::detect(b""), FileFormat::Empty);
        assert_eq!(FileFormat::detect(b"\0PBP...."), FileFormat::Pbp);
        assert_eq!(FileFormat::detect(b"~PSP...."), FileFormat::EncryptedPrx);
        assert_eq!(FileFormat::detect(b"\x7fELF...."), FileFormat::PlainElf);
        assert_eq!(FileFormat::detect(b"\0PSF...."), FileFormat::ParamSfo);
        assert_eq!(FileFormat::detect(b"NPUMDIMG"), FileFormat::NpUmdImg);
        assert_eq!(FileFormat::detect(b"PSISOIMG"), FileFormat::PsIsoImg);
        assert_eq!(FileFormat::detect(b"PSTITLEIMG"), FileFormat::PsTitleImg);
        assert_eq!(FileFormat::detect(b"\0PGD...."), FileFormat::Pgd);
        assert_eq!(FileFormat::detect(b"\x89PNG\r\n"), FileFormat::Png);
        assert_eq!(FileFormat::detect(b"nonsense"), FileFormat::Unknown);
        // A magic-length prefix must not be read past the end of the buffer.
        assert_eq!(FileFormat::detect(b"NP"), FileFormat::Unknown);
    }

    #[test]
    fn inspects_an_mg_eboot_end_to_end() {
        let data = mg_eboot();
        let report = inspect(&data).unwrap();

        assert_eq!(report.format, FileFormat::Pbp);
        assert_eq!(report.total_size, data.len() as u64);
        assert_eq!(report.category(), Some(&Category::Mg));

        let container = report.container.as_ref().unwrap();
        assert_eq!(container.title.as_deref(), Some("inspectme"));
        assert_eq!(container.system_version.as_deref(), Some("1.00"));
        assert!(container.param_sfo_error.is_none());

        // Sections are identified by their own magic.
        let by = |s: PbpSection| container.sections.iter().find(|r| r.section == s).unwrap();
        assert_eq!(by(PbpSection::ParamSfo).format, FileFormat::ParamSfo);
        assert_eq!(by(PbpSection::DataPsp).format, FileFormat::EncryptedPrx);
        assert_eq!(by(PbpSection::Icon0Png).format, FileFormat::Png);
        assert_eq!(by(PbpSection::DataPsar).format, FileFormat::Empty);

        // Offsets and sizes describe the actual bytes.
        for section in &container.sections {
            let start = section.offset as usize;
            let end = start + section.size as usize;
            assert!(end <= data.len(), "{} runs past the file", section.section);
        }

        let module = report.module.as_ref().unwrap();
        assert!(module.encrypted);
        assert_eq!(module.module_name, "inspectme");
    }

    #[test]
    fn inspects_a_bare_module_both_ways() {
        let module = synthetic_prx("bare", 4096);

        let plain = inspect(&module).unwrap();
        assert_eq!(plain.format, FileFormat::PlainElf);
        assert!(plain.container.is_none());
        assert!(!plain.module.as_ref().unwrap().encrypted);

        let enc = encrypt_prx(&module, &EncryptOptions::default()).unwrap();
        let report = inspect(&enc.data).unwrap();
        assert_eq!(report.format, FileFormat::EncryptedPrx);
        assert!(report.module.as_ref().unwrap().encrypted);
    }

    #[test]
    fn an_eg_container_is_reported_not_misparsed() {
        // An EG DATA.PSP is NPDRM, not a PRX. Inspection must say so rather
        // than reporting a parse failure that looks like corruption.
        let mut sfo = mg_param_sfo("Some Game").unwrap();
        sfo.set(SfoEntry::text_padded("CATEGORY", "EG", 4).unwrap());
        let pbp = crate::pbp::PbpBuilder::new()
            .section(PbpSection::ParamSfo, sfo.to_bytes())
            .section(PbpSection::DataPsp, vec![0x01; 4096])
            .section(PbpSection::DataPsar, b"NPUMDIMG and then data".to_vec())
            .build();

        let report = inspect(&pbp.to_bytes()).unwrap();
        assert_eq!(report.category(), Some(&Category::Eg));
        assert!(report.module.is_none());
        assert!(
            report.module_error.as_ref().unwrap().contains("NPDRM"),
            "got {:?}",
            report.module_error
        );

        let container = report.container.unwrap();
        let psar = container
            .sections
            .iter()
            .find(|s| s.section == PbpSection::DataPsar)
            .unwrap();
        assert_eq!(psar.format, FileFormat::NpUmdImg);
    }

    #[test]
    fn unreadable_parts_are_reported_rather_than_failing_the_whole_file() {
        // A container with a corrupt PARAM.SFO and a corrupt executable still
        // inspects; the structure is readable even when the contents are not.
        let pbp = crate::pbp::PbpBuilder::new()
            .section(PbpSection::ParamSfo, b"\0PSFgarbage".to_vec())
            .section(PbpSection::DataPsp, vec![0xFF; 64])
            .build();

        let report = inspect(&pbp.to_bytes()).unwrap();
        let container = report.container.as_ref().unwrap();
        assert!(container.param_sfo_error.is_some());
        assert!(container.category.is_none());
        assert!(report.module_error.is_some());
        assert_eq!(container.sections.len(), crate::pbp::SECTION_COUNT);
    }

    #[test]
    fn a_param_sfo_is_not_reported_as_a_broken_executable() {
        // It is a parameter table, not a corrupt module. Reporting a PRX parse
        // failure for one sends the reader looking for damage that is not there.
        let sfo = mg_param_sfo("Standalone").unwrap();
        let report = inspect(&sfo.to_bytes()).unwrap();

        assert_eq!(report.format, FileFormat::ParamSfo);
        assert!(report.module.is_none());
        assert!(
            report.module_error.is_none(),
            "got {:?}",
            report.module_error
        );
        // The table itself is what the file contains, so it is reported.
        let parsed = report.param_sfo.expect("PARAM.SFO contents");
        assert_eq!(parsed.get_text("TITLE").as_deref(), Some("Standalone"));
    }

    #[test]
    fn other_non_executable_formats_report_no_executable_at_all() {
        for data in [
            b"\x89PNG\r\n\x1a\n and pixels".to_vec(),
            b"RIFF....WAVEfmt ".to_vec(),
            b"NPUMDIMG and then encrypted data".to_vec(),
        ] {
            let report = inspect(&data).unwrap();
            assert!(!report.format.may_hold_executable(), "{}", report.format);
            assert!(report.module.is_none());
            assert!(report.module_error.is_none(), "{}", report.format);
        }

        // A blob that could be a module still reports why it is not one.
        let report = inspect(&vec![0xFFu8; 500]).unwrap();
        assert_eq!(report.format, FileFormat::Unknown);
        assert!(report.module_error.is_some());
    }

    #[test]
    fn detects_an_iso_by_its_descriptor_not_its_first_bytes() {
        // An ISO identifies itself at sector 16; its first sectors are zero,
        // which must not be mistaken for an empty or unrecognised file.
        let iso =
            crate::iso::reader::tests::synthetic_iso(&[crate::iso::reader::tests::TestFile {
                path: "/PARAM.SFO",
                data: crate::sfo::mg_param_sfo("On A Disc").unwrap().to_bytes(),
            }]);
        assert_eq!(FileFormat::detect(&iso), FileFormat::Iso9660);

        let report = inspect(&iso).unwrap();
        assert_eq!(report.format, FileFormat::Iso9660);
        let iso_report = report.iso.expect("ISO report");
        assert_eq!(iso_report.volume.system_id, "PSP GAME");
        assert!(iso_report.entry_count > 0);

        // Truncating before sector 16 must not still look like an ISO.
        assert_ne!(FileFormat::detect(&iso[..1000]), FileFormat::Iso9660);
    }

    #[test]
    fn streaming_a_container_agrees_with_reading_it_whole() {
        let data = mg_eboot();
        let whole = inspect(&data).unwrap();
        let streamed = inspect_pbp(std::io::Cursor::new(&data), data.len() as u64).unwrap();

        assert_eq!(streamed.format, whole.format);
        assert_eq!(streamed.total_size, whole.total_size);
        assert_eq!(streamed.category(), whole.category());

        let (a, b) = (
            streamed.container.as_ref().unwrap(),
            whole.container.as_ref().unwrap(),
        );
        assert_eq!(a.version, b.version);
        assert_eq!(a.title, b.title);
        assert_eq!(a.system_version, b.system_version);
        assert_eq!(a.sections.len(), b.sections.len());
        for (s, w) in a.sections.iter().zip(&b.sections) {
            assert_eq!(
                (s.section, s.offset, s.size, s.format),
                (w.section, w.offset, w.size, w.format)
            );
        }
        assert_eq!(
            streamed.module.map(|m| m.module_name),
            whole.module.map(|m| m.module_name)
        );
    }

    #[test]
    fn streaming_reads_only_a_bounded_amount_of_a_huge_section() {
        // The point of streaming: a gigabyte-scale DATA.PSAR must be identified
        // from its magic without being read. Build a container whose archive is
        // far larger than the read limit and check it is still reported.
        let big = STREAM_SECTION_LIMIT as usize * 4;
        let mut psar = b"NPUMDIMG".to_vec();
        psar.resize(big, 0);
        let pbp = crate::pbp::PbpBuilder::new()
            .section(
                PbpSection::ParamSfo,
                crate::sfo::mg_param_sfo("Big").unwrap().to_bytes(),
            )
            .section(PbpSection::DataPsar, psar)
            .build();
        let bytes = pbp.to_bytes();

        let report = inspect_pbp(std::io::Cursor::new(&bytes), bytes.len() as u64).unwrap();
        let container = report.container.unwrap();
        let archive = container
            .sections
            .iter()
            .find(|s| s.section == PbpSection::DataPsar)
            .unwrap();
        assert_eq!(archive.format, FileFormat::NpUmdImg);
        assert_eq!(archive.size as usize, big);
    }

    #[test]
    fn streaming_rejects_a_malformed_container() {
        let data = mg_eboot();
        // A truncated file: the offset table describes more than exists.
        assert!(inspect_pbp(std::io::Cursor::new(&data), 64).is_err());
        assert!(inspect_pbp(std::io::Cursor::new(b"nope".to_vec()), 4).is_err());
    }

    #[test]
    fn unrecognised_and_malformed_input_never_panics() {
        for case in [
            vec![],
            vec![0u8; 3],
            vec![0xFFu8; 5000],
            b"\0PBP".to_vec(),
            b"~PSP".to_vec(),
        ] {
            let _ = inspect(&case);
        }
        // Truncating a real EBOOT at every length must not panic either.
        let full = mg_eboot();
        for cut in (0..full.len()).step_by(97) {
            let _ = inspect(&full[..cut]);
        }
    }
}
