//! The NPUMDIMG header: building it, and signing it.
//!
//! See `docs/NPUMDIMG.md` for the format. [`build_header`] runs the whole
//! chain of its §3 — assemble, encrypt the body, MAC, digest, sign — and the
//! functions below it cover the individual steps.

use crate::crypto::aes::Key;
use crate::crypto::sha1::{Digest160, sha1};
use crate::error::{Error, Result};
use crate::npdrm::bbcipher::bbcipher;
use crate::npdrm::bbmac::{BbMacType, bbmac};
use crate::npdrm::blocks::{BlockLayout, SECTOR_SIZE};
use crate::npdrm::ecdsa::{self, Signature};
use crate::npdrm::keys::{NPUMDIMG_PRIVATE_KEY, NPUMDIMG_PUBLIC_KEY};
use crate::npdrm::random::PADDING_SIZE;

/// The NPUMDIMG header, in bytes.
pub const HEADER_SIZE: usize = 0x100;

/// How much of the header the signature covers: everything before it.
pub const SIGNED_LEN: usize = 0xD8;

/// Where the signature sits.
pub const SIGNATURE_OFFSET: usize = 0xD8;

/// The archive's magic.
pub const MAGIC: &[u8; 8] = b"NPUMDIMG";

/// The content ID field's width. Shorter IDs are NUL-padded.
pub const CONTENT_ID_SIZE: usize = 0x30;

/// The body, which is stored encrypted.
const BODY: std::ops::Range<usize> = 0x40..0xA0;

/// Where the header hash covers up to.
const HASHED_LEN: usize = 0xC0;

/// `unk_2` switches above a 1 GiB image. It is not a compression flag; see
/// `docs/NPUMDIMG.md` §2.4.
const LARGE_IMAGE_THRESHOLD: u64 = 0x4000_0000;

/// Everything needed to build a header, other than the crypto.
#[derive(Debug, Clone)]
pub struct HeaderFields {
    /// The content ID, at most [`CONTENT_ID_SIZE`] bytes of ASCII.
    pub content_id: String,
    /// `np_flags` verbatim: the fixed-key bit and the key variant.
    pub np_flags: u32,
    /// Where the blocks are and how many.
    pub layout: BlockLayout,
    /// The per-archive random key the blocks were encrypted under.
    pub header_key: Key,
    /// The MAC over the finished block table. A *result*, so the table must
    /// already exist when this is called.
    pub data_key: Key,
    /// The eight random bytes at 0xD0.
    pub padding: [u8; PADDING_SIZE],
}

/// Build a complete, signed 256-byte header.
///
/// The steps run in the order `docs/NPUMDIMG.md` §3 sets out, and the order
/// matters: each one covers the output of the one before. The body is
/// encrypted before the MAC is taken, so the MAC covers ciphertext; the MAC is
/// written before the digest, so the signature covers the MAC.
pub fn build_header(fields: &HeaderFields, version_key: &Key) -> Result<[u8; HEADER_SIZE]> {
    let id = fields.content_id.as_bytes();
    if id.len() > CONTENT_ID_SIZE {
        return Err(Error::Crypto(format!(
            "content ID is {} bytes, more than the {CONTENT_ID_SIZE} the field holds",
            id.len()
        )));
    }
    if !fields.content_id.is_ascii() {
        return Err(Error::Crypto("content ID must be ASCII".into()));
    }

    let mut header = [0u8; HEADER_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[0x08..0x0C].copy_from_slice(&fields.np_flags.to_le_bytes());
    header[0x0C..0x10].copy_from_slice(&fields.layout.block_basis.to_le_bytes());
    header[0x10..0x10 + id.len()].copy_from_slice(id);

    write_body(&mut header, fields)?;

    header[0xA0..0xB0].copy_from_slice(&fields.header_key);
    header[0xB0..0xC0].copy_from_slice(&fields.data_key);
    // header_hash stays zero until the body is encrypted and MAC'd.
    header[0xD0..0xD8].copy_from_slice(&fields.padding);

    // Body first, so everything after covers its ciphertext.
    bbcipher(&fields.header_key, version_key, 0, &mut header[BODY])?;

    let hash = bbmac(BbMacType::Type3, &header[..HASHED_LEN], Some(version_key))?;
    header[0xC0..0xD0].copy_from_slice(&hash);

    sign_header(&mut header)?;
    Ok(header)
}

/// Fill in the plaintext body at 0x40..0xA0.
fn write_body(header: &mut [u8; HEADER_SIZE], fields: &HeaderFields) -> Result<()> {
    let layout = fields.layout;
    let body = &mut header[BODY];

    let put16 = |body: &mut [u8], at: usize, v: u16| {
        body[at..at + 2].copy_from_slice(&v.to_le_bytes());
    };
    let put32 = |body: &mut [u8], at: usize, v: u32| {
        body[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };

    put16(body, 0x00, SECTOR_SIZE as u16);
    put16(
        body,
        0x02,
        if layout.iso_size > LARGE_IMAGE_THRESHOLD {
            0xE001
        } else {
            0xE000
        },
    );
    put32(body, 0x08, 0x1010);
    put32(body, 0x14, 0); // lba_start
    put32(body, 0x1C, layout.nsectors());
    put32(body, 0x24, layout.lba_end());
    put32(body, 0x28, 0x0100_3FFE);
    put32(body, 0x2C, HEADER_SIZE as u32); // block_entry_offset

    // disc_id is rebuilt from the content ID rather than carried separately:
    // characters 7..11, a dash, then 11..16.
    let id = fields.content_id.as_bytes();
    if id.len() >= 16 {
        body[0x30..0x34].copy_from_slice(&id[7..11]);
        body[0x34] = b'-';
        body[0x35..0x3A].copy_from_slice(&id[11..16]);
    } else {
        return Err(Error::Crypto(format!(
            "content ID {:?} is too short to contain a disc ID",
            fields.content_id
        )));
    }

    Ok(())
}

/// The digest the header's signature is made over.
///
/// # The length word is not part of the message
///
/// The reference implementation builds a `0xDC`-byte buffer — the little-endian
/// length `0xD8`, then the header — and hands it to KIRK's SHA-1 command. It
/// is natural to read that as a length-prefixed message, and an earlier
/// revision of `docs/NPUMDIMG.md` did.
///
/// It is not. Those first four bytes are the *command header*: KIRK command 11
/// reads a `data_size` from them and hashes only what follows. The digest is
/// over `header[0x00..0xD8]` and nothing else.
///
/// The distinction is invisible until you try to verify a real signature,
/// which is exactly how it was caught — the prefixed reading fails to verify
/// the reference archive and this one succeeds.
pub fn header_digest(header: &[u8]) -> Result<Digest160> {
    if header.len() < SIGNED_LEN {
        return Err(Error::TooShort {
            expected: SIGNED_LEN,
            actual: header.len(),
        });
    }
    Ok(sha1(&header[..SIGNED_LEN]))
}

/// Sign a header in place, writing the signature at 0xD8.
///
/// The nonce is derived from the header and the key by RFC 6979 rather than
/// drawn from a generator, so signing the same header twice gives the same
/// signature and no entropy source can compromise the key. See
/// [`ecdsa::sign_deterministic`].
pub fn sign_header(header: &mut [u8]) -> Result<Signature> {
    if header.len() < HEADER_SIZE {
        return Err(Error::TooShort {
            expected: HEADER_SIZE,
            actual: header.len(),
        });
    }
    let digest = header_digest(header)?;
    let signature = ecdsa::sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY)?;
    header[SIGNATURE_OFFSET..HEADER_SIZE].copy_from_slice(&signature.to_bytes());

    // A signature that does not verify is worse than none: it would ship and
    // fail on hardware. Check before returning, always.
    if !verify_header(header)? {
        return Err(Error::IntegrityCheck(
            "freshly generated NPUMDIMG signature does not verify".into(),
        ));
    }
    Ok(signature)
}

/// Check the signature already present in a header.
pub fn verify_header(header: &[u8]) -> Result<bool> {
    if header.len() < HEADER_SIZE {
        return Err(Error::TooShort {
            expected: HEADER_SIZE,
            actual: header.len(),
        });
    }
    let digest = header_digest(header)?;
    let signature = Signature::from_bytes(&header[SIGNATURE_OFFSET..HEADER_SIZE])?;
    Ok(ecdsa::verify(&digest, &NPUMDIMG_PUBLIC_KEY, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header shaped like a real one, but with no valid signature yet.
    fn scratch_header() -> Vec<u8> {
        let mut header = vec![0u8; HEADER_SIZE];
        header[..8].copy_from_slice(b"NPUMDIMG");
        header[8..12].copy_from_slice(&0x0100_0003u32.to_le_bytes());
        header[12..16].copy_from_slice(&0x10u32.to_le_bytes());
        let content_id = b"UL0000-ULUS10380_00-0000000000000000";
        header[0x10..0x10 + content_id.len()].copy_from_slice(content_id);
        for (i, b) in header[0x40..0xD8].iter_mut().enumerate() {
            *b = (i * 31) as u8;
        }
        header
    }

    #[test]
    fn a_signed_header_verifies() {
        let mut header = scratch_header();
        assert!(!verify_header(&header).unwrap(), "unsigned header verified");

        sign_header(&mut header).unwrap();
        assert!(verify_header(&header).unwrap());
    }

    /// The signature covers 0x00..0xD8 and nothing after it, so the padding at
    /// 0xD0 is inside and the signature field itself is outside.
    #[test]
    fn every_byte_below_the_signature_is_covered() {
        let mut header = scratch_header();
        sign_header(&mut header).unwrap();

        for offset in [0x00, 0x08, 0x10, 0x40, 0xA0, 0xC0, 0xD0, 0xD7] {
            let mut tampered = header.clone();
            tampered[offset] ^= 0x01;
            assert!(
                !verify_header(&tampered).unwrap(),
                "a flipped bit at {offset:#04X} still verified"
            );
        }
    }

    #[test]
    fn the_digest_ignores_the_signature_field() {
        let mut header = scratch_header();
        let before = header_digest(&header).unwrap();
        header[SIGNATURE_OFFSET] ^= 0xFF;
        header[HEADER_SIZE - 1] ^= 0xFF;
        assert_eq!(header_digest(&header).unwrap(), before);
    }

    /// Signing is reproducible: the same header always yields the same
    /// signature, because the nonce is derived from the header rather than
    /// drawn. Two runs of a build differ only where the format requires it.
    #[test]
    fn signing_the_same_header_twice_is_reproducible() {
        let mut a = scratch_header();
        let mut b = scratch_header();
        sign_header(&mut a).unwrap();
        sign_header(&mut b).unwrap();

        assert_eq!(a, b, "identical headers signed differently");
        assert!(verify_header(&a).unwrap());
    }

    /// The other half: two different headers must not share a nonce, which
    /// would expose the private key. A shared nonce shows up as a shared `r`.
    #[test]
    fn different_headers_do_not_share_a_nonce() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..16u8 {
            let mut header = scratch_header();
            header[0x40] = i;
            let signature = sign_header(&mut header).unwrap();
            assert!(seen.insert(signature.r), "header {i} reused a nonce");
            assert!(verify_header(&header).unwrap());
        }
    }

    #[test]
    fn a_short_header_is_an_error_not_a_panic() {
        assert!(header_digest(&[0u8; 0x40]).is_err());
        assert!(verify_header(&[0u8; 0x80]).is_err());
        assert!(sign_header(&mut [0u8; 0x80]).is_err());
    }
}
