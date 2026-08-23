//! Format detection and structural inspection.
//!
//! Inspection answers "what is this file, and what is inside it" without
//! needing the caller to know in advance. That matters most for telling the two
//! security paths apart: an MG EBOOT and an EG EBOOT are both PBP containers,
//! and the difference is in `PARAM.SFO` and in what `DATA.PSP` and `DATA.PSAR`
//! actually hold.

use crate::error::Result;
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
    /// Nothing at all.
    Empty,
    /// Not recognised.
    Unknown,
}

impl FileFormat {
    /// Identify a blob by its magic.
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return FileFormat::Empty;
        }
        let starts = |magic: &[u8]| data.len() >= magic.len() && &data[..magic.len()] == magic;

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
            FileFormat::Empty => "empty",
            FileFormat::Unknown => "unrecognised",
        }
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
}

/// What a file turned out to be.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub format: FileFormat,
    pub total_size: u64,
    /// Present when the file is a PBP.
    pub container: Option<ContainerReport>,
    /// The executable, whether it was bare or inside a container.
    pub module: Option<PrxInfo>,
    /// Why the executable could not be read, when it could not.
    pub module_error: Option<String>,
}

impl Inspection {
    /// The declared category, when there is a container.
    pub fn category(&self) -> Option<&Category> {
        self.container.as_ref().and_then(|c| c.category.as_ref())
    }
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

    if format != FileFormat::Pbp {
        // A bare file: the only thing that can be inside it is a module.
        let (module, module_error) = match inspect_prx(data) {
            Ok(info) => (Some(info), None),
            Err(e) => (None, Some(e.to_string())),
        };
        return Ok(Inspection {
            format,
            total_size,
            container: None,
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
    };

    match pbp.param_sfo() {
        Ok(sfo) => {
            report.category = sfo.category();
            report.title = sfo.get_text("TITLE");
            report.system_version = sfo.get_text("PSP_SYSTEM_VER");
        }
        Err(e) => report.param_sfo_error = Some(e.to_string()),
    }

    // The executable is only readable on the MG path. An EG DATA.PSP is an
    // NPDRM container, which this crate cannot open yet, so report that rather
    // than letting a PRX parser fail confusingly against it.
    let data_psp = pbp.data_psp();
    let (module, module_error) = if data_psp.is_empty() {
        (None, Some("DATA.PSP is empty".to_string()))
    } else if report.category.as_ref() == Some(&Category::Eg) {
        (
            None,
            Some("EG DATA.PSP is an NPDRM container; not supported yet".to_string()),
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
