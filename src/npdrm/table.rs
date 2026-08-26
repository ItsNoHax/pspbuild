//! The NPUMDIMG block table.
//!
//! One 0x20-byte entry per block, immediately after the header. Each entry
//! says where its block is, how long it is, and carries a BB-MAC over the
//! block's ciphertext.
//!
//! ```text
//! 0x00  u8[16]  mac       BB-MAC type 3 of the encrypted block
//! 0x10  u32     offset    absolute offset of the block within DATA.PSAR
//! 0x14  u32     size      encrypted size in bytes
//! 0x18  u32     0
//! 0x1C  u32     0
//! ```
//!
//! # The obfuscation is not encryption
//!
//! Once filled in, the four words after the MAC are XORed with values derived
//! from the MAC's own four words:
//!
//! ```text
//! k0 = m0^m1   k1 = m1^m2   k2 = m0^m3   k3 = m2^m3
//!
//! offset ^= k3   size ^= k1   pad0 ^= k2   pad1 ^= k0
//! ```
//!
//! Every input is already in the entry, so anyone holding the entry can undo
//! it. There is no key and no secret. It is self-inverse — applying it twice
//! returns the original — so one routine serves both directions, which is why
//! the reference implementation only has an `encrypt_table` and never needed a
//! matching decrypt.
//!
//! What it does buy is that the table does not *look* like a table: without
//! it, a run of plausible ascending offsets and a repeated block size would
//! make the structure obvious at a glance in a hex editor. It raises the cost
//! of recognising the format, nothing more, and it should not be described as
//! protecting anything.

use crate::crypto::aes::Key;
use crate::error::{Error, Result};

/// Size of one block table entry.
pub const ENTRY_SIZE: usize = 0x20;

/// One block's entry in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEntry {
    /// BB-MAC type 3 over the block's ciphertext, keyed by the version key.
    pub mac: Key,
    /// Absolute offset of the block within `DATA.PSAR`.
    pub offset: u32,
    /// Encrypted size in bytes, before padding out to 16.
    pub size: u32,
}

impl BlockEntry {
    /// Encode the entry, obfuscation applied, ready to write to the table.
    pub fn to_bytes(self) -> [u8; ENTRY_SIZE] {
        let mut raw = [0u8; ENTRY_SIZE];
        raw[..16].copy_from_slice(&self.mac);
        raw[0x10..0x14].copy_from_slice(&self.offset.to_le_bytes());
        raw[0x14..0x18].copy_from_slice(&self.size.to_le_bytes());
        obfuscate(&mut raw);
        raw
    }

    /// Decode an entry as stored in the table.
    ///
    /// The two trailing words are expected to be zero once deobfuscated; a
    /// non-zero value there means either a misread entry or a variant of the
    /// format this code does not know, and both are worth surfacing rather
    /// than ignoring.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let mut buf: [u8; ENTRY_SIZE] = raw
            .get(..ENTRY_SIZE)
            .ok_or(Error::TooShort {
                expected: ENTRY_SIZE,
                actual: raw.len(),
            })?
            .try_into()
            .expect("checked length");

        obfuscate(&mut buf);

        let word = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().expect("4 bytes"));
        let (pad0, pad1) = (word(0x18), word(0x1C));
        if pad0 != 0 || pad1 != 0 {
            return Err(Error::Crypto(format!(
                "block table entry has {pad0:#X}/{pad1:#X} where two zero words are expected"
            )));
        }

        Ok(BlockEntry {
            mac: buf[..16].try_into().expect("16 bytes"),
            offset: word(0x10),
            size: word(0x14),
        })
    }
}

/// Apply the table obfuscation in place. Its own inverse.
fn obfuscate(entry: &mut [u8; ENTRY_SIZE]) {
    fn word(entry: &[u8; ENTRY_SIZE], o: usize) -> u32 {
        u32::from_le_bytes(entry[o..o + 4].try_into().expect("4 bytes"))
    }
    let (m0, m1, m2, m3) = (
        word(entry, 0),
        word(entry, 4),
        word(entry, 8),
        word(entry, 12),
    );

    // Each mask mixes two of the MAC's words; the pairings are not symmetric,
    // and the order they are applied in is not the order they are derived in.
    for (offset, mask) in [
        (0x10, m2 ^ m3),
        (0x14, m1 ^ m2),
        (0x18, m0 ^ m3),
        (0x1C, m0 ^ m1),
    ] {
        let value = word(entry, offset) ^ mask;
        entry[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BlockEntry {
        BlockEntry {
            mac: [
                0x2A, 0xEE, 0x4B, 0xC0, 0x93, 0x35, 0x49, 0x84, 0x41, 0x22, 0x7A, 0x7E, 0xFE, 0x4D,
                0x53, 0x8D,
            ],
            offset: 0x0010_F5E0,
            size: 32768,
        }
    }

    #[test]
    fn an_entry_round_trips() {
        let entry = sample();
        assert_eq!(BlockEntry::from_bytes(&entry.to_bytes()).unwrap(), entry);
    }

    #[test]
    fn the_obfuscation_is_its_own_inverse() {
        let mut raw = [0u8; ENTRY_SIZE];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let original = raw;
        obfuscate(&mut raw);
        assert_ne!(raw, original, "obfuscation left the entry unchanged");
        obfuscate(&mut raw);
        assert_eq!(raw, original);
    }

    /// The MAC is what the masks are derived from, so it must survive
    /// untouched — otherwise deobfuscation could not reproduce them.
    #[test]
    fn the_mac_is_not_obfuscated() {
        let entry = sample();
        assert_eq!(entry.to_bytes()[..16], entry.mac[..]);
    }

    /// The point of the obfuscation is that the plaintext fields do not appear
    /// verbatim. A table of ascending offsets and a constant size would
    /// otherwise be obvious on sight.
    #[test]
    fn the_offset_and_size_do_not_appear_in_the_clear() {
        let entry = sample();
        let raw = entry.to_bytes();
        assert_ne!(raw[0x10..0x14], entry.offset.to_le_bytes());
        assert_ne!(raw[0x14..0x18], entry.size.to_le_bytes());
        assert_ne!(raw[0x18..0x20], [0u8; 8]);
    }

    /// Deriving the masks from the MAC means a different MAC has to move the
    /// other fields, even when they hold identical values.
    #[test]
    fn the_mac_keys_the_obfuscation() {
        let a = sample();
        let mut b = sample();
        b.mac[0] ^= 0x01;
        assert_ne!(a.to_bytes()[0x10..], b.to_bytes()[0x10..]);
    }

    #[test]
    fn a_truncated_entry_is_an_error_not_a_panic() {
        assert!(BlockEntry::from_bytes(&[0u8; 0x1F]).is_err());
        assert!(BlockEntry::from_bytes(&[]).is_err());
    }

    /// Garbage that deobfuscates to non-zero trailing words is rejected rather
    /// than yielding a plausible-looking offset and size.
    #[test]
    fn a_corrupt_entry_is_rejected() {
        let mut raw = sample().to_bytes();
        raw[0x18] ^= 0xFF;
        assert!(BlockEntry::from_bytes(&raw).is_err());
    }
}
