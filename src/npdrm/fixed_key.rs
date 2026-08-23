//! `sceNpDrmGetFixedKey` — the derived version key.
//!
//! NPDRM content normally carries a per-purchase version key, delivered
//! alongside it in a `KEYS.BIN`. The *fixed* key is the alternative: a key
//! derived from the content ID alone, so anything that knows the ID can
//! decrypt it. It is what `np_flags` bit 0x01000000 selects, and what makes a
//! fixed-key archive playable without an account.
//!
//! ```text
//! key = BB-MAC type 1 over the content ID, NUL-padded to 0x30 bytes,
//!       finalised with NPDRM_FIXED_KEY as the version key
//! key = AES-ECB(NPDRM_ENC_KEYS[variant - 1], key)     when variant is 1..=3
//! ```
//!
//! The low byte of `np_flags` picks the variant. `NPUMDIMG` uses
//! `0x01000003`, so the third key applies.

use crate::crypto::aes::{Aes128Ctx, Key};
use crate::error::{Error, Result};
use crate::npdrm::bbmac::{BbMacType, bbmac};
use crate::npdrm::keys::{NPDRM_ENC_KEYS, NPDRM_FIXED_KEY};

/// The `np_flags` bit that selects fixed-key derivation.
pub const FIXED_KEY_FLAG: u32 = 0x0100_0000;

/// Content IDs are MAC'd over a fixed-width field, not over their length.
const CONTENT_ID_LEN: usize = 0x30;

/// Derive the version key for a fixed-key title.
///
/// `np_flags` is the header field verbatim; the bit that requests fixed-key
/// derivation and the variant in the low byte are both read from it, so a
/// caller cannot pass a `np_flags` that disagrees with the key it gets back.
pub fn fixed_key(content_id: &str, np_flags: u32) -> Result<Key> {
    if np_flags & FIXED_KEY_FLAG == 0 {
        return Err(Error::Crypto(format!(
            "np_flags {np_flags:#010X} does not request a fixed key; \
             a version key must be supplied instead"
        )));
    }

    let variant = np_flags & 0xFF;
    if variant as usize > NPDRM_ENC_KEYS.len() {
        return Err(Error::Crypto(format!(
            "np_flags {np_flags:#010X} selects key variant {variant}, but only 0..=3 exist"
        )));
    }

    // The firmware copies the ID into a fixed 0x30-byte buffer, so a longer ID
    // is truncated rather than rejected. Reject it here: a silently truncated
    // content ID would derive a key for a different title.
    let id = content_id.as_bytes();
    if id.len() > CONTENT_ID_LEN {
        return Err(Error::Crypto(format!(
            "content ID is {} bytes, more than the {CONTENT_ID_LEN} the field holds",
            id.len()
        )));
    }
    let mut padded = [0u8; CONTENT_ID_LEN];
    padded[..id.len()].copy_from_slice(id);

    let key = bbmac(BbMacType::Type1, &padded, Some(&NPDRM_FIXED_KEY))?;

    // Variant 0 stops at the MAC; the others encrypt it once more.
    if variant == 0 {
        return Ok(key);
    }
    Ok(Aes128Ctx::new(&NPDRM_ENC_KEYS[variant as usize - 1]).encrypt_block(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::test_vectors::unhex;

    /// Known answers from the reference implementation, covering both a real
    /// content ID (the one behind the archive this format was derived from)
    /// and every variant the low byte selects.
    #[rustfmt::skip]
    const FIXED_KEY_VECTORS: &[(&str, u32, &str)] = &[
        ("UL0000-ULUS10380_00-0000000000000000", 0x0100_0003, "251c095d75576db6464474b0eeac7c01"),
        ("UL0000-ULUS10380_00-0000000000000000", 0x0100_0002, "59da2d524658d0bf989c7f29321192ea"),
        ("UL0000-ULUS10380_00-0000000000000000", 0x0100_0001, "c8e919e63c10d4cabac4fb68f41c371b"),
        ("UL0000-ULUS10380_00-0000000000000000", 0x0100_0000, "8ca3def3431370736968fe779b10609e"),
        ("EP9000-NPEG00001_00-0000000000000001", 0x0100_0003, "dfdafd8049bc459cc180335905dfafe0"),
        ("EP9000-NPEG00001_00-0000000000000001", 0x0100_0002, "815b2472b766fed6e961f7fafbacddeb"),
        ("EP9000-NPEG00001_00-0000000000000001", 0x0100_0001, "1d4295bb667cf6f493a18e789195354c"),
        ("EP9000-NPEG00001_00-0000000000000001", 0x0100_0000, "de362b5923180fdabbb2d1597018357a"),
    ];

    #[test]
    fn derivation_matches_the_reference() {
        for &(id, flags, want) in FIXED_KEY_VECTORS {
            assert_eq!(
                fixed_key(id, flags).unwrap().to_vec(),
                unhex(want),
                "{id} with np_flags {flags:#010X}"
            );
        }
    }

    #[test]
    fn the_content_id_selects_the_key() {
        let a = fixed_key("UL0000-ULUS10380_00-0000000000000000", 0x0100_0003).unwrap();
        let b = fixed_key("UL0000-ULUS10381_00-0000000000000000", 0x0100_0003).unwrap();
        assert_ne!(a, b);
    }

    /// Padding is part of the message, so a shorter ID must not collide with
    /// the same ID written out to full width.
    #[test]
    fn padding_is_not_ambiguous() {
        let short = fixed_key("UL0000-ULUS10380", 0x0100_0003).unwrap();
        let long = fixed_key("UL0000-ULUS10380_00-0000000000000000", 0x0100_0003).unwrap();
        assert_ne!(short, long);
    }

    #[test]
    fn flags_without_the_fixed_key_bit_are_refused() {
        // 0x2 is the supplied-version-key form: there is no key to derive.
        assert!(fixed_key("UL0000-ULUS10380_00-0", 0x0000_0002).is_err());
    }

    #[test]
    fn an_unknown_variant_is_an_error_not_a_wrong_key() {
        assert!(fixed_key("UL0000-ULUS10380_00-0", 0x0100_0004).is_err());
        assert!(fixed_key("UL0000-ULUS10380_00-0", 0x0100_00FF).is_err());
    }

    #[test]
    fn an_oversized_content_id_is_refused_rather_than_truncated() {
        assert!(fixed_key(&"A".repeat(0x31), 0x0100_0003).is_err());
        assert!(fixed_key(&"A".repeat(0x30), 0x0100_0003).is_ok());
    }
}
