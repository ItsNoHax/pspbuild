//! Building an EG `EBOOT.PBP` from a UMD image.
//!
//! An EG container is a whole disc in a PBP: the `PARAM.SFO` and media assets
//! lifted from the image, a signed `DATA.PSP` licence stub, and the encrypted
//! image itself in `DATA.PSAR`.
//!
//! ```text
//! PARAM.SFO   the disc's own, with CATEGORY changed from UG to EG
//! ICON0.PNG   \
//! ICON1.PMF    |  copied from /PSP_GAME, when present
//! PIC0.PNG     |
//! PIC1.PNG     |
//! SND0.AT3    /
//! DATA.PSP    signed licence stub binding the SFO to the content ID
//! DATA.PSAR   NPUMDIMG archive of the entire image
//! ```
//!
//! # This is a separate pipeline from MG, on purpose
//!
//! They share the PBP container and the KIRK primitives and nothing else. An
//! MG EBOOT carries an encrypted PRX and no archive; an EG one carries a
//! licence stub and the whole disc. The two are not modes of one another, and
//! [`crate::pbp::Pbp::require_category`] exists so neither can be run against
//! the other's container by accident.
//!
//! # Order matters twice over
//!
//! The `PARAM.SFO` has to be rewritten to `CATEGORY=EG` *before* `DATA.PSP` is
//! signed, because the signature covers it. And the archive has to be written
//! before the container, because it is the largest part and is streamed rather
//! than held. Both are enforced by the shape of [`build_eg_eboot`] rather than
//! left to the caller.

use std::io::{Read, Seek, Write};

use crate::error::{Error, Result};
use crate::iso::{Iso, PSP_GAME_ASSETS};
use crate::npdrm::archive::{ArchiveOptions, ArchiveSummary, write_archive};
use crate::npdrm::data_psp;
use crate::npdrm::random::Entropy;
use crate::pbp::{PbpBuilder, PbpSection};
use crate::sfo::{Category, Sfo, SfoEntry};

/// The container version an EG EBOOT declares.
const PBP_VERSION: u32 = 0x0001_0001;

/// `DATA.PSAR` starts on this boundary in every container examined.
const PSAR_ALIGNMENT: usize = 0x100;

/// What was built.
#[derive(Debug, Clone)]
pub struct EgEboot {
    /// The content ID the container was signed for.
    pub content_id: String,
    /// The title from the disc's `PARAM.SFO`, if it had one.
    pub title: Option<String>,
    /// Bytes of PBP header, SFO and media, before `DATA.PSAR`.
    pub container_size: u64,
    /// Detail from the archive step.
    pub archive: ArchiveSummary,
}

/// Build an EG `EBOOT.PBP` from a UMD image, writing it to `out`.
///
/// `image` is the raw disc; `out` receives the finished container. Both are
/// streamed, so a gigabyte disc does not become a gigabyte of memory.
pub fn build_eg_eboot<R, W, E>(
    image: R,
    image_size: u64,
    out: &mut W,
    options: &ArchiveOptions,
    entropy: &mut E,
) -> Result<EgEboot>
where
    R: Read + Seek,
    W: Write + Seek,
    E: Entropy,
{
    let mut iso = Iso::new(image)?;

    // 1. The disc's PARAM.SFO, relabelled. A UMD's own table says CATEGORY=UG;
    //    an EG container must say EG, and the DATA.PSP signature covers it.
    let disc_sfo = iso.read_file("/PSP_GAME/PARAM.SFO").map_err(|e| {
        Error::InvalidIso(format!(
            "the image has no PSP_GAME/PARAM.SFO, so it is not a PSP UMD: {e}"
        ))
    })?;
    let mut sfo = Sfo::parse(&disc_sfo)?;
    let title = sfo.get_text("TITLE");
    sfo.set(SfoEntry::text_padded("CATEGORY", Category::Eg.as_str(), 4)?);
    let param_sfo = sfo.to_bytes();

    // 2. The licence stub, over the *relabelled* table.
    let container_data_psp = data_psp::build(&param_sfo, &options.content_id, options.np_flags)?;

    // 3. Media, copied from the disc. Absent assets stay absent: a UMD is not
    //    required to carry all of them, and SND0.AT3 frequently is not there.
    let mut builder = PbpBuilder::new()
        .version(PBP_VERSION)
        .section(PbpSection::ParamSfo, param_sfo)
        .section(PbpSection::DataPsp, container_data_psp.clone());
    for (path, section) in PSP_GAME_ASSETS {
        if section == PbpSection::ParamSfo {
            continue;
        }
        if let Some(bytes) = iso.read_optional(path)? {
            builder = builder.section(section, bytes);
        }
    }

    // 4. Everything but the archive. A PBP records section offsets and no
    //    lengths, so writing the container with an empty DATA.PSAR puts that
    //    section's offset exactly at the end — which is where the archive
    //    then goes, and its length is implied by the file's.
    //
    //    DATA.PSAR must start on a 0x100 boundary. All four Sony containers
    //    examined do, and the reference implementation pads for it explicitly.
    //    The padding goes after DATA.PSP; since a PBP stores no lengths, a
    //    reader simply sees a slightly longer DATA.PSP.
    let unpadded = builder
        .clone()
        .section(PbpSection::DataPsar, Vec::new())
        .build()
        .to_bytes()
        .len();
    let padding = unpadded.next_multiple_of(PSAR_ALIGNMENT) - unpadded;
    if padding > 0 {
        let mut padded = container_data_psp.clone();
        padded.extend(std::iter::repeat_n(0u8, padding));
        builder = builder.section(PbpSection::DataPsp, padded);
    }

    let prefix = builder
        .section(PbpSection::DataPsar, Vec::new())
        .build()
        .to_bytes();
    let psar_offset = prefix.len() as u64;
    debug_assert!(psar_offset.is_multiple_of(PSAR_ALIGNMENT as u64));
    out.write_all(&prefix)?;

    // 5. The archive itself, streamed straight through.
    let mut image = iso.into_inner();
    let archive = write_archive(&mut image, image_size, out, options, entropy)?;

    Ok(EgEboot {
        content_id: options.content_id.clone(),
        title,
        container_size: psar_offset,
        archive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::random::PredictableEntropy;
    use crate::pbp::Pbp;
    use std::io::Cursor;

    const CONTENT_ID: &str = "UL0000-ABCD12345_00-0000000000000000";

    /// A minimal but genuine ISO9660 image with the PSP layout, built here so
    /// the test does not need a retail disc.
    fn synthetic_umd() -> Vec<u8> {
        crate::iso::reader::tests::synthetic_psp_iso()
    }

    #[test]
    fn a_built_container_has_the_right_shape() {
        let image = synthetic_umd();
        let mut out = Cursor::new(Vec::new());
        let built = build_eg_eboot(
            Cursor::new(image.clone()),
            image.len() as u64,
            &mut out,
            &ArchiveOptions::fixed_key(CONTENT_ID),
            &mut PredictableEntropy::new(0x5A),
        )
        .unwrap();

        let bytes = out.into_inner();
        let pbp = Pbp::parse(&bytes).unwrap();

        // The category is what routes the whole security path.
        assert_eq!(pbp.category(), Some(Category::Eg));

        // DATA.PSP must verify against the container's own PARAM.SFO.
        let sfo = pbp.section(PbpSection::ParamSfo);
        let psp = pbp.section(PbpSection::DataPsp);
        assert!(data_psp::verify(psp, sfo).unwrap());
        assert_eq!(data_psp::content_id(psp).unwrap(), CONTENT_ID);

        // DATA.PSAR must start on a 0x100 boundary, as Sony's containers do.
        let psar_offset = pbp
            .layout()
            .iter()
            .find(|(s, _, _)| *s == PbpSection::DataPsar)
            .map(|(_, offset, _)| *offset)
            .expect("the container has a DATA.PSAR");
        assert_eq!(psar_offset % 0x100, 0, "DATA.PSAR is not 0x100 aligned");
        assert_eq!(u64::from(psar_offset), built.container_size);

        // And DATA.PSAR is the archive we streamed.
        let psar = pbp.section(PbpSection::DataPsar);
        assert_eq!(&psar[..8], b"NPUMDIMG");
        assert_eq!(psar.len() as u64, built.archive.size);
        assert!(crate::npdrm::verify_header(&psar[..0x100]).unwrap());
    }

    /// The container's PARAM.SFO must say EG even though the disc's says UG,
    /// and the signature must be over the changed one.
    #[test]
    fn the_category_is_rewritten_before_it_is_signed() {
        let image = synthetic_umd();
        let mut out = Cursor::new(Vec::new());
        build_eg_eboot(
            Cursor::new(image.clone()),
            image.len() as u64,
            &mut out,
            &ArchiveOptions::fixed_key(CONTENT_ID),
            &mut PredictableEntropy::new(1),
        )
        .unwrap();

        let bytes = out.into_inner();
        let pbp = Pbp::parse(&bytes).unwrap();
        let sfo = Sfo::parse(pbp.section(PbpSection::ParamSfo)).unwrap();
        assert_eq!(sfo.get_text("CATEGORY").as_deref(), Some("EG"));

        // The disc's own table said UG; signing the disc's copy would verify
        // against the wrong category, so check the one that shipped.
        let mut disc = Iso::new(Cursor::new(image)).unwrap();
        let disc_sfo = Sfo::parse(&disc.read_file("/PSP_GAME/PARAM.SFO").unwrap()).unwrap();
        assert_eq!(disc_sfo.get_text("CATEGORY").as_deref(), Some("UG"));
    }

    #[test]
    fn an_image_without_a_param_sfo_is_refused() {
        let image = vec![0u8; 40 * 2048];
        let mut out = Cursor::new(Vec::new());
        assert!(
            build_eg_eboot(
                Cursor::new(image),
                40 * 2048,
                &mut out,
                &ArchiveOptions::fixed_key(CONTENT_ID),
                &mut PredictableEntropy::new(1),
            )
            .is_err()
        );
    }
}
