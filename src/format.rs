//! Alignment helpers and little-endian field access.
//!
//! All PSP on-disk structures are little-endian. Rather than scattering
//! `from_le_bytes` calls (and their slice-length panics) across the codebase,
//! every read goes through the checked helpers here.

use crate::error::{Error, Result};

/// Round `value` up to the next multiple of `alignment`.
///
/// `alignment` must be a non-zero power of two. Returns `None` on overflow.
pub fn try_align_up(value: u64, alignment: u64) -> Option<u64> {
    debug_assert!(
        alignment.is_power_of_two(),
        "alignment must be a power of two"
    );
    let mask = alignment - 1;
    value.checked_add(mask).map(|v| v & !mask)
}

/// Round `value` up to the next multiple of `alignment`.
///
/// Panics only on programmer error (non-power-of-two alignment or overflow),
/// never on user input; use [`try_align_up`] when the value is attacker
/// controlled.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    try_align_up(value, alignment).expect("align_up overflowed")
}

/// The AES block size, which is also the KIRK payload alignment.
pub const AES_BLOCK: u64 = 16;

/// Round up to the next AES block boundary.
pub fn align_to_block(value: u64) -> u64 {
    align_up(value, AES_BLOCK)
}

/// Read a little-endian `u32` at `offset`.
pub fn read_u32(buf: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::InvalidPrxHeader("offset overflow".into()))?;
    let bytes = buf.get(offset..end).ok_or(Error::TooShort {
        expected: end,
        actual: buf.len(),
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
}

/// Read a little-endian `u16` at `offset`.
pub fn read_u16(buf: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| Error::InvalidPrxHeader("offset overflow".into()))?;
    let bytes = buf.get(offset..end).ok_or(Error::TooShort {
        expected: end,
        actual: buf.len(),
    })?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("2 bytes")))
}

/// Read a `u8` at `offset`.
pub fn read_u8(buf: &[u8], offset: usize) -> Result<u8> {
    buf.get(offset).copied().ok_or(Error::TooShort {
        expected: offset + 1,
        actual: buf.len(),
    })
}

/// Copy a fixed-size array out of `buf` at `offset`.
pub fn read_array<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| Error::InvalidPrxHeader("offset overflow".into()))?;
    let bytes = buf.get(offset..end).ok_or(Error::TooShort {
        expected: end,
        actual: buf.len(),
    })?;
    Ok(bytes.try_into().expect("N bytes"))
}

/// Write a little-endian `u32` at `offset`. The caller owns the buffer, so a
/// short buffer here is a programmer error.
pub fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a little-endian `u16` at `offset`.
pub fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Interpret a fixed-width, NUL-padded field as a display string.
pub fn cstr_from_field(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_matches_reference_cases() {
        // The values called out in the implementation plan.
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
        assert_eq!(align_up(31, 16), 32);
        assert_eq!(align_up(32, 16), 32);
    }

    #[test]
    fn align_up_handles_realistic_prx_sizes() {
        assert_eq!(align_up(716_800, 16), 716_800);
        assert_eq!(align_up(716_801, 16), 716_816);
        assert_eq!(align_up(1_048_576, 16), 1_048_576);
    }

    #[test]
    fn try_align_up_detects_overflow() {
        // Only the last 15 values overflow when 15 is added.
        assert_eq!(try_align_up(u64::MAX, 16), None);
        assert_eq!(try_align_up(u64::MAX - 14, 16), None);
        // One below that rounds up exactly to the top block.
        assert_eq!(try_align_up(u64::MAX - 15, 16), Some(u64::MAX - 15));
    }

    #[test]
    fn reads_are_bounds_checked() {
        let buf = [1u8, 2, 3];
        assert!(read_u32(&buf, 0).is_err());
        assert!(read_u16(&buf, 2).is_err());
        assert_eq!(read_u16(&buf, 0).unwrap(), 0x0201);
        assert!(read_array::<8>(&buf, 0).is_err());
        // An offset near usize::MAX must not wrap.
        assert!(read_u32(&buf, usize::MAX).is_err());
    }

    #[test]
    fn cstr_field_stops_at_nul() {
        assert_eq!(cstr_from_field(b"main\0\0\0\0"), "main");
        assert_eq!(cstr_from_field(b"nonul"), "nonul");
        assert_eq!(cstr_from_field(b""), "");
    }
}
