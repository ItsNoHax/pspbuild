//! KIRK key vault.
//!
//! These are the well-known PSP KIRK keys, published in the open-source KIRK
//! engine used by every PSP tool and emulator. They are not secrets in any
//! meaningful sense, but they are still key material: never log them.

use crate::crypto::aes::Key;
use crate::error::{Error, Result};

/// The KIRK command-1 master key. Wraps the per-module AES and CMAC keys that
/// sit at the front of every KIRK CMD1 header.
pub const KIRK1_KEY: Key = [
    0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8, 0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA,
];

/// KIRK command 4/7 key slots, indexed by the `keyseed` used by a PRX tag.
///
/// Only the slots this tool actually needs are present; unknown slots are a
/// clean error rather than a silent wrong-key decryption.
const KIRK7_KEYS: &[(u8, Key)] = &[
    (
        0x4B,
        [
            0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42,
            0x28, 0x8B,
        ],
    ),
    (
        0x5D,
        [
            0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F,
            0x18, 0x6F,
        ],
    ),
    (
        0x60,
        [
            0xF4, 0x28, 0x30, 0xA5, 0xFB, 0x0D, 0x8D, 0x76, 0x0E, 0xA6, 0x71, 0xC2, 0x2B, 0xDE,
            0x66, 0x9D,
        ],
    ),
    (
        0x61,
        [
            0xFB, 0x5F, 0xEB, 0x7F, 0xC7, 0xDC, 0xDD, 0x69, 0x37, 0x01, 0x97, 0x9B, 0x29, 0x03,
            0x5C, 0x47,
        ],
    ),
];

/// Look up a KIRK 4/7 key slot.
pub fn kirk7_key(seed: u8) -> Result<&'static Key> {
    KIRK7_KEYS
        .iter()
        .find(|(id, _)| *id == seed)
        .map(|(_, key)| key)
        .ok_or_else(|| Error::Crypto(format!("unsupported KIRK 4/7 key slot {seed:#04X}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_slots_resolve() {
        assert_eq!(kirk7_key(0x60).unwrap()[0], 0xF4);
        assert_eq!(kirk7_key(0x5D).unwrap()[0], 0x11);
    }

    #[test]
    fn unknown_slot_is_an_error_not_a_panic() {
        assert!(kirk7_key(0x00).is_err());
        assert!(kirk7_key(0xFF).is_err());
    }

    #[test]
    fn key_table_has_no_duplicate_slots() {
        let mut ids: Vec<u8> = KIRK7_KEYS.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before);
    }
}
