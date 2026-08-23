//! Reading a PBP container.

use super::{HEADER_SIZE, PBP_MAGIC, Pbp, SECTION_COUNT, SECTION_NAMES};
use crate::error::{Error, Result};
use crate::format::{read_array, read_u32};

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
