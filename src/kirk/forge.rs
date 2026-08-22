//! The KIRK data-CMAC forge.
//!
//! # Why this exists
//!
//! A KIRK CMD1 header holds two CMAC tags. The header tag covers `0x60..0x90`;
//! the data tag covers that same region plus the predata and the whole aligned
//! payload. Both are computed with the module's CMAC key.
//!
//! The legacy PSPSDK flow copies an entire KIRK header out of a genuine Sony
//! module, replaces the payload, and then restores the original header bytes —
//! discarding the freshly computed tags. The header tag survives that, because
//! the bytes it covers are unchanged. The data tag does not: the payload is
//! new. Rather than write a new tag, the legacy tool rewrites the final 16
//! bytes of the payload so the *old* tag becomes correct again.
//!
//! # Which bytes it modifies
//!
//! Exactly the last 16-byte block of the CMAC'd region, i.e. the final block of
//! the aligned payload. Nothing else. Because the payload is padded up to a
//! 16-byte boundary and the module's real content ends before it, in practice
//! this overwrites padding.
//!
//! # Which relationship must hold
//!
//! Afterwards `CMAC(cmac_key, container[0x60..end]) == header.cmac_data_hash`,
//! while the header tag is left untouched and must already be valid.
//!
//! # Why the PSP accepts the result
//!
//! KIRK CMD1 authenticates with CMAC only — there is no signature over the
//! payload. Any payload whose data CMAC matches the stored tag is accepted, and
//! the tag is a value we can hit exactly (see [`crate::crypto::cmac::aes_cmac_forge`]).
//!
//! # Assumptions
//!
//! This depends on the CMD1 layout specifically: that the authenticated region
//! ends exactly at the end of the aligned payload, and that its length is a
//! non-zero multiple of 16 so the complete-block (K1) branch of CMAC applies.
//!
//! # When it is *not* needed
//!
//! This crate's normal encryption path generates its own header, so it can
//! simply compute the correct tag. Forging is only required when a pre-existing
//! tag must be preserved. It is kept here because it is the operation that
//! makes template-based output work, and because [`crate::verify`] needs to
//! understand files produced that way.

use crate::crypto::cmac::{aes_cmac, aes_cmac_forge};
use crate::error::{Error, Result};
use crate::kirk::commands::{calculate_data_cmac, calculate_header_cmac, unwrap_keys};
use crate::kirk::header::KirkCmd1Header;

/// Outcome of a forge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeOutcome {
    /// The data tag already matched; nothing was changed.
    AlreadyValid,
    /// The final payload block was rewritten to match the stored tag.
    Forged,
}

/// Make `container`'s data CMAC match the tag already stored in its header.
///
/// The header CMAC must already be valid — if it is not, the container is
/// inconsistent in a way forging cannot repair.
pub fn forge_data_cmac(container: &mut [u8]) -> Result<ForgeOutcome> {
    let header = KirkCmd1Header::parse(container)?;
    header.validate()?;

    let total = header.container_size() as usize;
    if container.len() < total {
        return Err(Error::TooShort {
            expected: total,
            actual: container.len(),
        });
    }

    let (_aes_key, cmac_key) = unwrap_keys(container)?;

    // The header tag must hold, or we are forging onto a broken container.
    if calculate_header_cmac(&cmac_key, container)? != header.cmac_header_hash {
        return Err(Error::IntegrityCheck(
            "KIRK header CMAC is invalid; refusing to forge the data CMAC".into(),
        ));
    }

    if calculate_data_cmac(&cmac_key, container, &header)? == header.cmac_data_hash {
        return Ok(ForgeOutcome::AlreadyValid);
    }

    let range = header.data_cmac_range();
    aes_cmac_forge(
        &cmac_key,
        &mut container[range.clone()],
        &header.cmac_data_hash,
    )?;

    debug_assert_eq!(
        aes_cmac(&cmac_key, &container[range]),
        header.cmac_data_hash
    );
    Ok(ForgeOutcome::Forged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kirk::commands::{cmd0_encrypt, cmd1_decrypt};
    use crate::kirk::header::HEADER_SIZE;

    fn build(payload: &[u8]) -> Vec<u8> {
        let header = KirkCmd1Header::new([0x11; 16], [0x22; 16], payload.len() as u32, 0x80);
        let mut buf = vec![0u8; header.container_size() as usize];
        buf[..HEADER_SIZE].copy_from_slice(&header.to_bytes());
        let start = HEADER_SIZE + 0x80;
        buf[start..start + payload.len()].copy_from_slice(payload);
        buf
    }

    #[test]
    fn a_freshly_encrypted_container_needs_no_forging() {
        let mut c = build(&[0xAAu8; 256]);
        cmd0_encrypt(&mut c).unwrap();
        assert_eq!(forge_data_cmac(&mut c).unwrap(), ForgeOutcome::AlreadyValid);
    }

    #[test]
    fn forging_restores_a_stale_data_tag() {
        // Encrypt, then swap in a different payload while keeping the old tags,
        // exactly as the legacy template flow does.
        let mut c = build(&[0xAAu8; 256]);
        cmd0_encrypt(&mut c).unwrap();
        let original_tags = c[0x20..0x40].to_vec();

        let mut c2 = build(&[0x55u8; 256]);
        cmd0_encrypt(&mut c2).unwrap();
        c2[0x20..0x40].copy_from_slice(&original_tags);

        // The header tag is shared (same 0x60..0x90 bytes), the data tag is not.
        assert!(cmd1_decrypt(&c2, true).is_err());
        assert_eq!(forge_data_cmac(&mut c2).unwrap(), ForgeOutcome::Forged);
        assert!(cmd1_decrypt(&c2, true).is_ok());
    }

    #[test]
    fn forging_only_rewrites_the_final_block() {
        let mut c = build(&[0xAAu8; 256]);
        cmd0_encrypt(&mut c).unwrap();
        let mut c2 = build(&[0x55u8; 256]);
        cmd0_encrypt(&mut c2).unwrap();
        c2[0x20..0x40].copy_from_slice(&c[0x20..0x40]);

        let before = c2.clone();
        forge_data_cmac(&mut c2).unwrap();

        let split = c2.len() - 16;
        assert_eq!(c2[..split], before[..split]);
        assert_ne!(c2[split..], before[split..]);
    }

    #[test]
    fn refuses_to_forge_when_the_header_tag_is_broken() {
        let mut c = build(&[0xAAu8; 256]);
        cmd0_encrypt(&mut c).unwrap();
        c[0x20] ^= 0xFF; // corrupt the header tag
        assert!(matches!(
            forge_data_cmac(&mut c).unwrap_err(),
            Error::IntegrityCheck(_)
        ));
    }

    #[test]
    fn malformed_input_errors_cleanly() {
        assert!(forge_data_cmac(&mut [0u8; 8]).is_err());
        assert!(forge_data_cmac(&mut [0u8; 0x90]).is_err());
    }
}
