//! The PBP container.
//!
//! `EBOOT.PBP` is how PSP homebrew actually ships: a 0x28-byte header followed
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
//! Sections may be empty, which shows up as two equal offsets.

use crate::error::{Error, Result};
use crate::format::{read_array, read_u32, write_u32};

/// PBP magic.
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

/// A parsed PBP container.
#[derive(Debug, Clone)]
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
        if data.len() < HEADER_SIZE {
            return Err(Error::TooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }
        let magic: [u8; 4] = read_array(data, 0)?;
        if magic != PBP_MAGIC {
            return Err(Error::InvalidPrxHeader(
                "not a PBP container (bad magic)".into(),
            ));
        }
        let version = read_u32(data, 4)?;

        // Read the offset table, then treat the file end as the final bound.
        let mut bounds = [0usize; SECTION_COUNT + 1];
        for (i, bound) in bounds.iter_mut().take(SECTION_COUNT).enumerate() {
            *bound = read_u32(data, 8 + i * 4)? as usize;
        }
        bounds[SECTION_COUNT] = data.len();

        // Offsets must be inside the file and never go backwards, or a section
        // length would underflow.
        for i in 0..SECTION_COUNT {
            if bounds[i] < HEADER_SIZE || bounds[i] > data.len() {
                return Err(Error::InvalidPrxHeader(format!(
                    "PBP section {} offset {:#X} is outside the file",
                    SECTION_NAMES[i], bounds[i]
                )));
            }
            if bounds[i] > bounds[i + 1] {
                return Err(Error::InvalidPrxHeader(format!(
                    "PBP section {} offsets run backwards ({:#X} > {:#X})",
                    SECTION_NAMES[i],
                    bounds[i],
                    bounds[i + 1]
                )));
            }
        }

        let sections = std::array::from_fn(|i| data[bounds[i]..bounds[i + 1]].to_vec());
        Ok(Pbp { version, sections })
    }

    /// The executable section.
    pub fn data_psp(&self) -> &[u8] {
        &self.sections[DATA_PSP]
    }

    /// Replace the executable section.
    pub fn set_data_psp(&mut self, data: Vec<u8>) {
        self.sections[DATA_PSP] = data;
    }

    /// Serialise the container, recomputing every offset.
    pub fn to_bytes(&self) -> Vec<u8> {
        let total: usize = HEADER_SIZE + self.sections.iter().map(Vec::len).sum::<usize>();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&PBP_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());

        let mut offset = HEADER_SIZE as u32;
        let mut table = [0u8; SECTION_COUNT * 4];
        for (i, section) in self.sections.iter().enumerate() {
            write_u32(&mut table, i * 4, offset);
            offset += section.len() as u32;
        }
        out.extend_from_slice(&table);
        for section in &self.sections {
            out.extend_from_slice(section);
        }

        debug_assert_eq!(out.len(), total);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let parsed = Pbp::parse(&pbp.to_bytes()).unwrap();
        assert_eq!(parsed.version, pbp.version);
        assert_eq!(parsed.sections, pbp.sections);
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
}
