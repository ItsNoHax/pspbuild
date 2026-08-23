//! Shared inputs for the AMCTRL known-answer tests.
//!
//! The keys and message contents here are arbitrary — they are not real
//! NPDRM material. What matters is that the reference implementation was
//! driven with exactly these values to capture the expected outputs recorded
//! in each module's tests, so the two sides are comparable.

use crate::crypto::aes::Key;

/// The version key every vector was captured with.
pub const VERSION_KEY: Key = [
    0x5D, 0x64, 0x6B, 0x72, 0x79, 0x80, 0x87, 0x8E, 0x95, 0x9C, 0xA3, 0xAA, 0xB1, 0xB8, 0xBF, 0xC6,
];

/// The header key every BB-Cipher vector was captured with.
pub const HEADER_KEY: Key = [
    0x17, 0x1E, 0x25, 0x2C, 0x33, 0x3A, 0x41, 0x48, 0x4F, 0x56, 0x5D, 0x64, 0x6B, 0x72, 0x79, 0x80,
];

/// Reproduce the reference harness's message filler.
///
/// Deterministic and dependent on the position, so a vector can be
/// regenerated from its length and salt alone, and so a MAC over it is
/// sensitive to reordering.
pub fn filler(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(7) + salt.wrapping_mul(31) + (i >> 5)) as u8)
        .collect()
}

/// Decode a hex string from a test vector.
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}
