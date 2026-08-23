//! Assembling a PBP container.

use super::{HEADER_SIZE, PBP_MAGIC, Pbp, PbpSection, SECTION_COUNT};
use crate::format::write_u32;

/// The version every PSP PBP carries.
pub const PBP_VERSION: u32 = 0x0001_0000;

/// Serialise a PBP container, recomputing every offset from the section
/// contents.
///
/// The output is exactly the header plus the sections: no padding, no
/// alignment, no reserved space. A section's size is whatever it holds.
pub fn build_pbp(pbp: &Pbp) -> Vec<u8> {
    let total: usize = HEADER_SIZE + pbp.sections.iter().map(Vec::len).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&PBP_MAGIC);
    out.extend_from_slice(&pbp.version.to_le_bytes());

    let mut offset = HEADER_SIZE as u32;
    let mut table = [0u8; SECTION_COUNT * 4];
    for (i, section) in pbp.sections.iter().enumerate() {
        write_u32(&mut table, i * 4, offset);
        offset += section.len() as u32;
    }
    out.extend_from_slice(&table);
    for section in &pbp.sections {
        out.extend_from_slice(section);
    }

    debug_assert_eq!(out.len(), total);
    out
}

/// Assemble a PBP container section by section.
///
/// Sections left unset are emitted empty, which is how the PSP represents an
/// absent icon or soundtrack. Building on top of an existing container with
/// [`PbpBuilder::from_pbp`] keeps everything that is not explicitly replaced.
#[derive(Debug, Clone)]
pub struct PbpBuilder {
    version: u32,
    sections: [Vec<u8>; SECTION_COUNT],
}

impl PbpBuilder {
    /// An empty container.
    pub fn new() -> Self {
        PbpBuilder {
            version: PBP_VERSION,
            sections: std::array::from_fn(|_| Vec::new()),
        }
    }

    /// Start from an existing container, preserving all of its sections.
    pub fn from_pbp(pbp: &Pbp) -> Self {
        PbpBuilder {
            version: pbp.version,
            sections: pbp.sections.clone(),
        }
    }

    /// Override the container version.
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set a section.
    pub fn section(mut self, section: PbpSection, data: impl Into<Vec<u8>>) -> Self {
        self.sections[section.index()] = data.into();
        self
    }

    /// Set a section only if `data` is `Some`, leaving it untouched otherwise.
    pub fn optional_section(self, section: PbpSection, data: Option<Vec<u8>>) -> Self {
        match data {
            Some(data) => self.section(section, data),
            None => self,
        }
    }

    /// Finish, producing the container.
    pub fn build(self) -> Pbp {
        Pbp {
            version: self.version,
            sections: self.sections,
        }
    }

    /// Finish and serialise in one step.
    pub fn build_bytes(self) -> Vec<u8> {
        build_pbp(&self.build())
    }
}

impl Default for PbpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pbp::parse_pbp;

    #[test]
    fn an_empty_builder_produces_a_header_only_container() {
        let bytes = PbpBuilder::new().build_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = parse_pbp(&bytes).unwrap();
        assert_eq!(parsed.version, PBP_VERSION);
        assert!(parsed.sections.iter().all(Vec::is_empty));
        // Every offset points at the end of the header, i.e. every section is
        // empty rather than absent.
        for (_, offset, len) in parsed.layout() {
            assert_eq!((offset, len), (HEADER_SIZE as u32, 0));
        }
    }

    #[test]
    fn sections_land_where_the_offsets_say() {
        let pbp = PbpBuilder::new()
            .section(PbpSection::ParamSfo, b"sfo".to_vec())
            .section(PbpSection::DataPsp, vec![0xEE; 100])
            .build();

        let bytes = build_pbp(&pbp);
        assert_eq!(bytes.len(), HEADER_SIZE + 3 + 100);
        assert_eq!(parse_pbp(&bytes).unwrap(), pbp);
        assert_eq!(pbp.section(PbpSection::DataPsp).len(), 100);
        assert!(pbp.section(PbpSection::Snd0At3).is_empty());
    }

    #[test]
    fn from_pbp_preserves_everything_not_replaced() {
        let original = PbpBuilder::new()
            .version(0x0002_0000)
            .section(PbpSection::ParamSfo, b"sfo".to_vec())
            .section(PbpSection::Icon0Png, b"icon".to_vec())
            .section(PbpSection::DataPsp, b"old executable".to_vec())
            .build();

        let updated = PbpBuilder::from_pbp(&original)
            .section(PbpSection::DataPsp, b"new".to_vec())
            .build();

        assert_eq!(updated.version, 0x0002_0000);
        assert_eq!(updated.section(PbpSection::DataPsp), b"new");
        assert_eq!(updated.section(PbpSection::ParamSfo), b"sfo");
        assert_eq!(updated.section(PbpSection::Icon0Png), b"icon");
    }

    #[test]
    fn optional_sections_are_skipped_when_absent() {
        let base = PbpBuilder::new()
            .section(PbpSection::Icon0Png, b"kept".to_vec())
            .build();

        let untouched = PbpBuilder::from_pbp(&base)
            .optional_section(PbpSection::Icon0Png, None)
            .build();
        assert_eq!(untouched.section(PbpSection::Icon0Png), b"kept");

        let replaced = PbpBuilder::from_pbp(&base)
            .optional_section(PbpSection::Icon0Png, Some(b"new".to_vec()))
            .build();
        assert_eq!(replaced.section(PbpSection::Icon0Png), b"new");
    }
}
