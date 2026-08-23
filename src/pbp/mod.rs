//! The PBP container.
//!
//! `EBOOT.PBP` is how PSP software actually ships: a 0x28-byte header followed
//! by eight concatenated sections. The executable lives in `DATA.PSP`, so
//! encrypting a homebrew build means rewriting that one section and fixing up
//! the offsets.
//!
//! ```text
//! 0x00  magic "\0PBP"
//! 0x04  version
//! 0x08  offset[8]   start of each section; each runs to the next offset
//! 0x28  section data
//! ```
//!
//! There are no section *lengths* on disk. A section runs from its own offset
//! to the next one, and the last runs to the end of the file, so an empty
//! section shows up as two equal offsets. That is also why nothing may be
//! appended after `DATA.PSAR`: trailing bytes are indistinguishable from that
//! section's contents.
//!
//! See `docs/PBP.md` for the byte-level specification.

pub mod builder;
pub mod parser;

use crate::error::{Error, Result};
use crate::sfo::{Category, Sfo};

pub use builder::{PbpBuilder, build_pbp};
pub use parser::parse_pbp;

/// PBP magic, `"\0PBP"`.
pub const PBP_MAGIC: [u8; 4] = [0x00, b'P', b'B', b'P'];

/// Size of the PBP header.
pub const HEADER_SIZE: usize = 0x28;

/// Number of sections in a PBP.
pub const SECTION_COUNT: usize = 8;

/// Section names, in container order.
pub const SECTION_NAMES: [&str; SECTION_COUNT] = [
    "PARAM.SFO",
    "ICON0.PNG",
    "ICON1.PMF",
    "PIC0.PNG",
    "PIC1.PNG",
    "SND0.AT3",
    "DATA.PSP",
    "DATA.PSAR",
];

/// Index of the executable section.
pub const DATA_PSP: usize = 6;

/// A section of a PBP container, named rather than numbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PbpSection {
    /// Parameter table: title, category, firmware requirement.
    ParamSfo,
    /// XMB icon.
    Icon0Png,
    /// Animated XMB icon.
    Icon1Pmf,
    /// Background image, upper layer.
    Pic0Png,
    /// Background image.
    Pic1Png,
    /// XMB background audio.
    Snd0At3,
    /// The executable.
    DataPsp,
    /// Bulk data: the game archive for EG, usually empty for MG.
    DataPsar,
}

impl PbpSection {
    /// Every section, in container order.
    pub const ALL: [PbpSection; SECTION_COUNT] = [
        PbpSection::ParamSfo,
        PbpSection::Icon0Png,
        PbpSection::Icon1Pmf,
        PbpSection::Pic0Png,
        PbpSection::Pic1Png,
        PbpSection::Snd0At3,
        PbpSection::DataPsp,
        PbpSection::DataPsar,
    ];

    /// Position in the container.
    pub fn index(self) -> usize {
        self as usize
    }

    /// The conventional filename.
    pub fn name(self) -> &'static str {
        SECTION_NAMES[self.index()]
    }

    /// The section at `index`, if it is in range.
    pub fn from_index(index: usize) -> Option<Self> {
        PbpSection::ALL.get(index).copied()
    }
}

impl std::fmt::Display for PbpSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A parsed PBP container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbp {
    /// Container version, preserved verbatim.
    pub version: u32,
    /// The eight sections, in container order. Any may be empty.
    pub sections: [Vec<u8>; SECTION_COUNT],
}

impl Pbp {
    /// Whether `data` looks like a PBP container.
    pub fn is_pbp(data: &[u8]) -> bool {
        data.len() >= HEADER_SIZE && data[..4] == PBP_MAGIC
    }

    /// Parse a PBP container.
    pub fn parse(data: &[u8]) -> Result<Self> {
        parser::parse_pbp(data)
    }

    /// Serialise the container, recomputing every offset.
    pub fn to_bytes(&self) -> Vec<u8> {
        builder::build_pbp(self)
    }

    /// Borrow a section.
    pub fn section(&self, section: PbpSection) -> &[u8] {
        &self.sections[section.index()]
    }

    /// Replace a section, leaving every other one untouched.
    pub fn set_section(&mut self, section: PbpSection, data: Vec<u8>) {
        self.sections[section.index()] = data;
    }

    /// The executable section.
    pub fn data_psp(&self) -> &[u8] {
        self.section(PbpSection::DataPsp)
    }

    /// Replace the executable section.
    pub fn set_data_psp(&mut self, data: Vec<u8>) {
        self.set_section(PbpSection::DataPsp, data);
    }

    /// The bulk-data section. Empty for a normal MG homebrew EBOOT.
    pub fn data_psar(&self) -> &[u8] {
        self.section(PbpSection::DataPsar)
    }

    /// Every section with the offset and length it would be written at.
    ///
    /// Offsets are computed from the current contents, so this describes what
    /// [`Pbp::to_bytes`] would produce rather than what was parsed.
    pub fn layout(&self) -> Vec<(PbpSection, u32, u32)> {
        let mut offset = HEADER_SIZE as u32;
        let mut out = Vec::with_capacity(SECTION_COUNT);
        for section in PbpSection::ALL {
            let len = self.sections[section.index()].len() as u32;
            out.push((section, offset, len));
            offset += len;
        }
        out
    }

    /// Parse the `PARAM.SFO` section.
    pub fn param_sfo(&self) -> Result<Sfo> {
        let raw = self.section(PbpSection::ParamSfo);
        if raw.is_empty() {
            return Err(Error::InvalidPbp("PBP has no PARAM.SFO section".into()));
        }
        Sfo::parse(raw)
    }

    /// The `CATEGORY` this container declares, if it has a readable one.
    pub fn category(&self) -> Option<Category> {
        self.param_sfo().ok().and_then(|sfo| sfo.category())
    }

    /// Fail unless the container declares `expected`.
    ///
    /// MG and EG are different security paths, so a build must never run one
    /// against a container asking for the other. A container with no readable
    /// `PARAM.SFO` is an error too, rather than an assumption.
    pub fn require_category(&self, expected: &Category) -> Result<()> {
        let actual = self
            .param_sfo()?
            .category()
            .ok_or_else(|| Error::InvalidSfo("PARAM.SFO has no CATEGORY entry".into()))?;
        if &actual != expected {
            return Err(Error::CategoryMismatch {
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(())
    }
}

/// Borrow one section of a container.
pub fn extract_section(pbp: &Pbp, section: PbpSection) -> &[u8] {
    pbp.section(section)
}

/// Replace one section, preserving all the others.
pub fn replace_section(pbp: &mut Pbp, section: PbpSection, data: Vec<u8>) {
    pbp.set_section(section, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::write_u32;

    fn sample() -> Pbp {
        Pbp {
            version: 0x0001_0000,
            sections: [
                b"PARAM".to_vec(),
                b"ICON0".to_vec(),
                Vec::new(),
                Vec::new(),
                b"PIC1".to_vec(),
                Vec::new(),
                b"\x7fELF and the rest of a module".to_vec(),
                Vec::new(),
            ],
        }
    }

    #[test]
    fn round_trips_through_bytes() {
        let pbp = sample();
        assert_eq!(Pbp::parse(&pbp.to_bytes()).unwrap(), pbp);
    }

    #[test]
    fn recomputes_offsets_after_a_section_changes() {
        let mut pbp = sample();
        pbp.set_data_psp(vec![0xAB; 5000]);
        let bytes = pbp.to_bytes();

        let parsed = Pbp::parse(&bytes).unwrap();
        assert_eq!(parsed.data_psp().len(), 5000);
        // Sections either side must survive untouched.
        assert_eq!(parsed.sections[0], b"PARAM");
        assert_eq!(parsed.sections[4], b"PIC1");
        assert_eq!(bytes.len(), HEADER_SIZE + 5 + 5 + 4 + 5000);
    }

    #[test]
    fn shrinking_the_executable_shrinks_the_container() {
        let mut pbp = sample();
        pbp.set_data_psp(vec![0u8; 100_000]);
        let big = pbp.to_bytes().len();
        pbp.set_data_psp(vec![0u8; 1_000]);
        assert_eq!(pbp.to_bytes().len(), big - 99_000);
    }

    #[test]
    fn empty_sections_round_trip() {
        let parsed = Pbp::parse(&sample().to_bytes()).unwrap();
        assert!(parsed.sections[2].is_empty());
        assert!(parsed.sections[7].is_empty());
    }

    #[test]
    fn detects_pbp_containers() {
        assert!(Pbp::is_pbp(&sample().to_bytes()));
        assert!(!Pbp::is_pbp(b"\x7fELF"));
        assert!(!Pbp::is_pbp(b""));
        assert!(!Pbp::is_pbp(&[0u8; HEADER_SIZE]));
    }

    #[test]
    fn rejects_malformed_containers() {
        assert!(Pbp::parse(b"").is_err());
        assert!(Pbp::parse(b"\x7fELF").is_err());
        assert!(Pbp::parse(&[0u8; HEADER_SIZE]).is_err());

        // Offset past the end of the file.
        let mut bytes = sample().to_bytes();
        write_u32(&mut bytes, 8, 0xFFFF_FFFF);
        assert!(Pbp::parse(&bytes).is_err());

        // Offsets running backwards would underflow a length.
        let mut bytes = sample().to_bytes();
        write_u32(&mut bytes, 8 + 4, HEADER_SIZE as u32);
        write_u32(&mut bytes, 8, (HEADER_SIZE + 10) as u32);
        assert!(Pbp::parse(&bytes).is_err());

        // Offset inside the header.
        let mut bytes = sample().to_bytes();
        write_u32(&mut bytes, 8, 4);
        assert!(Pbp::parse(&bytes).is_err());
    }

    #[test]
    fn truncated_containers_never_panic() {
        let full = sample().to_bytes();
        for cut in 0..full.len() {
            let _ = Pbp::parse(&full[..cut]);
        }
    }

    #[test]
    fn sections_are_addressable_by_name() {
        let pbp = sample();
        assert_eq!(pbp.section(PbpSection::ParamSfo), b"PARAM");
        assert_eq!(pbp.section(PbpSection::Pic1Png), b"PIC1");
        assert!(pbp.section(PbpSection::DataPsar).is_empty());

        assert_eq!(PbpSection::DataPsp.index(), DATA_PSP);
        assert_eq!(PbpSection::from_index(0), Some(PbpSection::ParamSfo));
        assert_eq!(PbpSection::from_index(SECTION_COUNT), None);
        // The enum order must match the on-disk order.
        for (i, section) in PbpSection::ALL.iter().enumerate() {
            assert_eq!(section.index(), i);
            assert_eq!(section.name(), SECTION_NAMES[i]);
        }
    }

    #[test]
    fn replace_section_preserves_the_others() {
        let mut pbp = sample();
        let before = pbp.clone();
        replace_section(&mut pbp, PbpSection::Icon0Png, vec![0x89; 40]);

        assert_eq!(extract_section(&pbp, PbpSection::Icon0Png).len(), 40);
        for section in PbpSection::ALL {
            if section != PbpSection::Icon0Png {
                assert_eq!(
                    pbp.section(section),
                    before.section(section),
                    "{section} changed"
                );
            }
        }
        // And it survives a serialise/parse cycle.
        assert_eq!(parse_pbp(&build_pbp(&pbp)).unwrap(), pbp);
    }

    #[test]
    fn layout_describes_what_would_be_written() {
        let pbp = sample();
        let bytes = pbp.to_bytes();
        for (section, offset, len) in pbp.layout() {
            let slice = &bytes[offset as usize..(offset + len) as usize];
            assert_eq!(slice, pbp.section(section), "{section} misplaced");
        }
        // The first section starts immediately after the header.
        assert_eq!(pbp.layout()[0].1, HEADER_SIZE as u32);
    }

    #[test]
    fn category_is_read_through_param_sfo() {
        let mut pbp = sample();
        pbp.set_section(
            PbpSection::ParamSfo,
            crate::sfo::mg_param_sfo("Homebrew").unwrap().to_bytes(),
        );

        assert_eq!(pbp.category(), Some(Category::Mg));
        assert!(pbp.require_category(&Category::Mg).is_ok());

        // Asking for the other pipeline must fail loudly, naming both sides.
        let err = pbp.require_category(&Category::Eg).unwrap_err();
        assert!(
            matches!(&err, Error::CategoryMismatch { expected, actual }
                if expected == "EG" && actual == "MG"),
            "got {err}"
        );
    }

    #[test]
    fn a_container_without_a_readable_category_is_an_error() {
        // Garbage PARAM.SFO: unreadable, so no category may be assumed.
        let pbp = sample();
        assert!(pbp.category().is_none());
        assert!(pbp.require_category(&Category::Mg).is_err());

        // Missing entirely.
        let mut empty = sample();
        empty.set_section(PbpSection::ParamSfo, Vec::new());
        assert!(matches!(
            empty.require_category(&Category::Mg).unwrap_err(),
            Error::InvalidPbp(_)
        ));

        // A valid table that simply has no CATEGORY entry.
        let mut sfo = crate::sfo::Sfo::default();
        sfo.set(crate::sfo::SfoEntry::int("BOOTABLE", 1));
        let mut no_category = sample();
        no_category.set_section(PbpSection::ParamSfo, sfo.to_bytes());
        assert!(matches!(
            no_category.require_category(&Category::Mg).unwrap_err(),
            Error::InvalidSfo(_)
        ));
    }
}
