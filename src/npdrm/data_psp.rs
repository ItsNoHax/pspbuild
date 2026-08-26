//! `DATA.PSP`, the EG container's licence stub.
//!
//! Where an MG `EBOOT.PBP` puts an encrypted PRX, an EG one puts this: a
//! mostly-empty 0x594-byte structure whose job is to bind the container's
//! `PARAM.SFO` to a content ID under Sony's signature.
//!
//! ```text
//! 0x000  u8[0x28]  signature    ECDSA over the digest below
//! 0x028  ...       zero
//! 0x560  u8[0x30]  content_id   ASCII, NUL-padded
//! 0x590  u32be     np_flags     big-endian, unlike everywhere else
//! 0x594  ...       STARTDAT and PGD, both optional
//! ```
//!
//! # What is signed
//!
//! ```text
//! digest = SHA-1( PARAM.SFO || content_id field )
//! ```
//!
//! The `PARAM.SFO` is the container's own, *after* its `CATEGORY` has been set
//! to `EG` — so the signature covers the category, and an EG container cannot
//! be turned into an MG one without breaking it.
//!
//! As with the archive header, the reference implementation builds a buffer
//! with a four-byte length in front and hands it to KIRK's SHA-1 command.
//! Those four bytes are the command header, not part of the message. All four
//! Sony archives on hand verify under the reading above and none verify under
//! the length-prefixed one.
//!
//! # `np_flags` is big-endian here
//!
//! The archive header stores `np_flags` little-endian; this stores the same
//! value byte-swapped. Confirmed on Sony's containers, where a fixed-key
//! title reads `01 00 00 03` rather than `03 00 00 01`.

use crate::crypto::sha1::{Digest160, sha1_chunks};
use crate::error::{Error, Result};
use crate::npdrm::ecdsa::{self, Signature};
use crate::npdrm::keys::{NPUMDIMG_PRIVATE_KEY, NPUMDIMG_PUBLIC_KEY};
use crate::npdrm::npumdimg::CONTENT_ID_SIZE;

/// Size of the structure, before any optional payload.
pub const DATA_PSP_SIZE: usize = 0x594;

/// Where the signature sits.
const SIGNATURE: std::ops::Range<usize> = 0x000..0x028;

/// Where the content ID sits.
const CONTENT_ID: std::ops::Range<usize> = 0x560..0x590;

/// Where `np_flags` sits, big-endian.
const NP_FLAGS: std::ops::Range<usize> = 0x590..0x594;

/// The digest a `DATA.PSP` signature is made over.
///
/// `content_id_field` is the 0x30-byte field as stored, padding included —
/// the padding is part of the message.
pub fn digest(param_sfo: &[u8], content_id_field: &[u8; CONTENT_ID_SIZE]) -> Digest160 {
    sha1_chunks(&[param_sfo, content_id_field])
}

/// Build and sign a `DATA.PSP` for a container.
///
/// `param_sfo` must already carry `CATEGORY=EG`, since the signature covers
/// it. Passing the unmodified SFO from a disc produces a container that
/// verifies against the wrong category.
pub fn build(param_sfo: &[u8], content_id: &str, np_flags: u32) -> Result<Vec<u8>> {
    let id = content_id.as_bytes();
    if id.len() > CONTENT_ID_SIZE || !content_id.is_ascii() {
        return Err(Error::Crypto(format!(
            "content ID {content_id:?} must be at most {CONTENT_ID_SIZE} bytes of ASCII"
        )));
    }

    let mut out = vec![0u8; DATA_PSP_SIZE];
    out[CONTENT_ID.start..CONTENT_ID.start + id.len()].copy_from_slice(id);
    out[NP_FLAGS].copy_from_slice(&np_flags.to_be_bytes());

    let field: [u8; CONTENT_ID_SIZE] = out[CONTENT_ID].try_into().expect("0x30 bytes");
    let signature = ecdsa::sign_deterministic(&digest(param_sfo, &field), &NPUMDIMG_PRIVATE_KEY)?;
    out[SIGNATURE].copy_from_slice(&signature.to_bytes());

    // A signature that does not verify would ship and fail on hardware.
    if !verify(&out, param_sfo)? {
        return Err(Error::IntegrityCheck(
            "freshly generated DATA.PSP signature does not verify".into(),
        ));
    }
    Ok(out)
}

/// Check the signature on an existing `DATA.PSP` against a `PARAM.SFO`.
pub fn verify(data_psp: &[u8], param_sfo: &[u8]) -> Result<bool> {
    if data_psp.len() < DATA_PSP_SIZE {
        return Err(Error::TooShort {
            expected: DATA_PSP_SIZE,
            actual: data_psp.len(),
        });
    }
    let field: [u8; CONTENT_ID_SIZE] = data_psp[CONTENT_ID].try_into().expect("0x30 bytes");
    let signature = Signature::from_bytes(&data_psp[SIGNATURE])?;
    Ok(ecdsa::verify(
        &digest(param_sfo, &field),
        &NPUMDIMG_PUBLIC_KEY,
        &signature,
    ))
}

/// The content ID a `DATA.PSP` names, with its padding trimmed.
pub fn content_id(data_psp: &[u8]) -> Result<String> {
    if data_psp.len() < DATA_PSP_SIZE {
        return Err(Error::TooShort {
            expected: DATA_PSP_SIZE,
            actual: data_psp.len(),
        });
    }
    let raw = &data_psp[CONTENT_ID];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8(raw[..end].to_vec())
        .map_err(|_| Error::Crypto("DATA.PSP content ID is not valid ASCII".into()))
}

/// The `np_flags` a `DATA.PSP` declares.
pub fn np_flags(data_psp: &[u8]) -> Result<u32> {
    if data_psp.len() < DATA_PSP_SIZE {
        return Err(Error::TooShort {
            expected: DATA_PSP_SIZE,
            actual: data_psp.len(),
        });
    }
    Ok(u32::from_be_bytes(
        data_psp[NP_FLAGS].try_into().expect("4 bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "UL0000-ABCD12345_00-0000000000000000";
    const FLAGS: u32 = 0x0100_0003;

    fn sfo() -> Vec<u8> {
        eg_sfo("EG").to_bytes()
    }

    /// A PARAM.SFO with the given category, as an EG container carries it.
    fn eg_sfo(category: &str) -> crate::sfo::Sfo {
        let mut sfo = crate::sfo::mg_param_sfo("A Title").expect("a template SFO");
        sfo.set(crate::sfo::SfoEntry::text_padded("CATEGORY", category, 4).expect("fits"));
        sfo
    }

    #[test]
    fn a_built_container_verifies() {
        let sfo = sfo();
        let psp = build(&sfo, ID, FLAGS).unwrap();

        assert_eq!(psp.len(), DATA_PSP_SIZE);
        assert!(verify(&psp, &sfo).unwrap());
        assert_eq!(content_id(&psp).unwrap(), ID);
        assert_eq!(np_flags(&psp).unwrap(), FLAGS);
    }

    /// `np_flags` is stored byte-swapped relative to the archive header, and
    /// getting that wrong is invisible until hardware rejects it.
    #[test]
    fn np_flags_is_stored_big_endian() {
        let psp = build(&sfo(), ID, 0x0100_0003).unwrap();
        assert_eq!(&psp[0x590..0x594], &[0x01, 0x00, 0x00, 0x03]);
    }

    /// Everything between the signature and the content ID is zero in Sony's
    /// containers, and nothing this crate writes should change that.
    #[test]
    fn the_body_is_otherwise_empty() {
        let psp = build(&sfo(), ID, FLAGS).unwrap();
        assert!(psp[0x028..0x560].iter().all(|&b| b == 0));
    }

    /// The signature covers the SFO, so a container cannot be moved to a
    /// different one — including one that differs only in its category.
    #[test]
    fn a_different_param_sfo_does_not_verify() {
        let psp = build(&sfo(), ID, FLAGS).unwrap();

        // The category is inside the signed message, so an otherwise
        // identical MG table must not verify against an EG container.
        assert!(!verify(&psp, &eg_sfo("MG").to_bytes()).unwrap());

        let mut tampered = sfo();
        tampered[0x30] ^= 0x01;
        assert!(!verify(&psp, &tampered).unwrap());
    }

    #[test]
    fn a_different_content_id_does_not_verify() {
        let sfo = sfo();
        let mut psp = build(&sfo, ID, FLAGS).unwrap();
        psp[0x560] ^= 0x01;
        assert!(!verify(&psp, &sfo).unwrap());
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let sfo = sfo();
        let mut psp = build(&sfo, ID, FLAGS).unwrap();
        psp[0] ^= 0x01;
        assert!(!verify(&psp, &sfo).unwrap());
    }

    #[test]
    fn a_bad_content_id_is_refused() {
        assert!(build(&sfo(), &"A".repeat(0x31), FLAGS).is_err());
        assert!(build(&sfo(), "not-ascii-Ω", FLAGS).is_err());
    }

    #[test]
    fn a_truncated_container_is_an_error_not_a_panic() {
        assert!(verify(&[0u8; 0x100], &sfo()).is_err());
        assert!(content_id(&[0u8; 0x10]).is_err());
        assert!(np_flags(&[]).is_err());
    }
}
