//! Reading a PBP container.

use super::{HEADER_SIZE, PBP_MAGIC, Pbp, PbpSection, SECTION_COUNT, SECTION_NAMES};
use crate::error::{Error, Result};
use crate::format::{read_array, read_u32};

/// Where each section sits, without any of its contents.
///
/// An EG `EBOOT.PBP` is routinely over a gigabyte, essentially all of it
/// `DATA.PSAR`. Reading the whole file to answer "what is in this container"
/// is the wrong shape, so the layout is separable from the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PbpLayout {
    pub version: u32,
    /// `(offset, size)` per section, in container order.
    pub sections: [(u32, u32); SECTION_COUNT],
}

impl PbpLayout {
    /// Offset and size of one section.
    pub fn section(&self, section: PbpSection) -> (u32, u32) {
        self.sections[section.index()]
    }
}

/// Parse just the offset table, given the file's total length.
///
/// `total_size` is needed because the last section's length is implied by the
/// end of the file rather than stored.
pub fn parse_layout(header: &[u8], total_size: u64) -> Result<PbpLayout> {
    if header.len() < HEADER_SIZE {
        return Err(Error::TooShort {
            expected: HEADER_SIZE,
            actual: header.len(),
        });
    }
    let magic: [u8; 4] = read_array(header, 0)?;
    if magic != PBP_MAGIC {
        return Err(Error::InvalidPbp("not a PBP container (bad magic)".into()));
    }
    let version = read_u32(header, 4)?;

    let mut bounds = [0u64; SECTION_COUNT + 1];
    for (i, bound) in bounds.iter_mut().take(SECTION_COUNT).enumerate() {
        *bound = u64::from(read_u32(header, 8 + i * 4)?);
    }
    bounds[SECTION_COUNT] = total_size;

    for i in 0..SECTION_COUNT {
        if bounds[i] < HEADER_SIZE as u64 || bounds[i] > total_size {
            return Err(Error::InvalidPbp(format!(
                "PBP section {} offset {:#X} is outside the {total_size}-byte file",
                SECTION_NAMES[i], bounds[i]
            )));
        }
        if bounds[i] > bounds[i + 1] {
            return Err(Error::InvalidPbp(format!(
                "PBP section {} offsets run backwards ({:#X} > {:#X})",
                SECTION_NAMES[i],
                bounds[i],
                bounds[i + 1]
            )));
        }
    }

    let sections = std::array::from_fn(|i| {
        (
            bounds[i] as u32,
            u32::try_from(bounds[i + 1] - bounds[i]).unwrap_or(u32::MAX),
        )
    });
    Ok(PbpLayout { version, sections })
}

/// Parse a PBP container.
///
/// Section bounds come from the offset table, with the end of the file acting
/// as the bound for the last section. Every offset is checked before it is
/// used to slice, since a hostile table could otherwise point outside the file
/// or run backwards and underflow a length.
pub fn parse_pbp(data: &[u8]) -> Result<Pbp> {
    if data.len() < HEADER_SIZE {
        return Err(Error::TooShort {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }
    let magic: [u8; 4] = read_array(data, 0)?;
    if magic != PBP_MAGIC {
        return Err(Error::InvalidPbp("not a PBP container (bad magic)".into()));
    }
    let version = read_u32(data, 4)?;

    let mut bounds = [0usize; SECTION_COUNT + 1];
    for (i, bound) in bounds.iter_mut().take(SECTION_COUNT).enumerate() {
        *bound = read_u32(data, 8 + i * 4)? as usize;
    }
    bounds[SECTION_COUNT] = data.len();

    for i in 0..SECTION_COUNT {
        if bounds[i] < HEADER_SIZE || bounds[i] > data.len() {
            return Err(Error::InvalidPbp(format!(
                "PBP section {} offset {:#X} is outside the file",
                SECTION_NAMES[i], bounds[i]
            )));
        }
        if bounds[i] > bounds[i + 1] {
            return Err(Error::InvalidPbp(format!(
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
