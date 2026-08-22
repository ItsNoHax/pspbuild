//! PRX tag handling: the obfuscation layer between the `~PSP` header on disk
//! and the KIRK CMD1 header the hardware consumes.
//!
//! # The type-2 layout
//!
//! A tag selects a 16-byte seed and a KIRK 4/7 key slot. The seed is expanded
//! into a 0x90-byte key stream, which masks the KIRK key block. The 0x150-byte
//! on-disk header scatters the logical fields as follows:
//!
//! ```text
//! file 0x00..0x80  module metadata     -> also the KIRK predata
//! file 0x80..0xB0  kirk key block, bytes 0x00..0x30
//! file 0xB0..0xC0  kirk size metadata  -> data_size, data_offset
//! file 0xC0..0xD0  kirk key block, bytes 0x30..0x40
//! file 0xD0..0xD4  tag
//! file 0xD4..0x12C reserved, must be all zero for this scheme
//! file 0x12C..0x140 SHA-1 of the header
//! file 0x140..0x150 id
//! ```
//!
//! # Why dynamic sizing is possible
//!
//! The header's integrity is protected by a **plain SHA-1**, not by a
//! signature: the reserved signature region is required to be zero for this
//! scheme. Every input to that hash is derived from data we control or key
//! material we hold, so the hash can be recomputed for any payload size. The
//! size fields therefore are not frozen, and there is no need to select a
//! pre-built header of fixed capacity.

use crate::crypto::sha1::sha1_chunks;
use crate::error::{Error, Result};
use crate::kirk::commands::{kirk4_encrypt, kirk7_decrypt};
use crate::psp::header::{METADATA_SIZE, PSP_HEADER_SIZE};

/// Length of the expanded key stream.
const XORBUF_LEN: usize = 0x90;
/// Length of the KIRK key block carried in the header.
const KEY_BLOCK_LEN: usize = 0x40;
/// Length of the region that the tag's cipher pass covers: id + sha1 + most of
/// the key block.
const SCRAMBLED_LEN: usize = 0x60;
/// Length of the size-metadata block.
const METADATA_BLOCK_LEN: usize = 0x10;
/// Length of the reserved signature region.
const RESERVED_LEN: usize = 0x58;

// On-disk offsets within the 0x150-byte header.
const OFF_KEY_BLOCK_LO: usize = 0x80;
const OFF_SIZE_METADATA: usize = 0xB0;
const OFF_KEY_BLOCK_HI: usize = 0xC0;
const OFF_TAG: usize = 0xD0;
const OFF_RESERVED: usize = 0xD4;
const OFF_SHA1: usize = 0x12C;
const OFF_ID: usize = 0x140;

/// A supported PRX encryption tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    /// The 4-byte value stored at offset 0xD0.
    pub tag: u32,
    /// The 16-byte seed the key stream is expanded from.
    pub seed: [u8; 16],
    /// KIRK 4/7 key slot used for both the expansion and the cipher passes.
    pub code: u8,
}

/// The tag this tool emits by default.
///
/// `0xADF305F0` is the 2.80 demo key. Its scheme requires a zero signature
/// region, which is what makes a freely sized, self-generated header valid.
pub const TAG_DEMO_280: TagInfo = TagInfo {
    tag: 0xADF3_05F0,
    seed: [
        0x12, 0x99, 0x70, 0x5E, 0x24, 0x07, 0x6C, 0xD0, 0x2D, 0x06, 0xFE, 0x7E, 0xB3, 0x0C, 0x11,
        0x26,
    ],
    code: 0x60,
};

/// Every tag this tool understands.
pub const SUPPORTED_TAGS: &[TagInfo] = &[TAG_DEMO_280];

/// Look up a tag.
pub fn lookup(tag: u32) -> Result<&'static TagInfo> {
    SUPPORTED_TAGS
        .iter()
        .find(|t| t.tag == tag)
        .ok_or(Error::UnknownTag { tag })
}

/// Expand a tag seed into the 0x90-byte key stream.
///
/// Each 16-byte slot is the seed with its first byte replaced by the slot
/// index, and the whole buffer is then put through a KIRK 7 pass.
fn expand_seed(info: &TagInfo) -> Result<[u8; XORBUF_LEN]> {
    let mut buf = [0u8; XORBUF_LEN];
    let (slots, _rest) = buf.as_chunks_mut::<16>();
    for (index, slot) in slots.iter_mut().enumerate() {
        slot.copy_from_slice(&info.seed);
        slot[0] = index as u8;
    }
    kirk7_decrypt(&mut buf, info.code)?;
    Ok(buf)
}

/// The logical contents of an encrypted-PRX header, before scattering.
#[derive(Debug, Clone)]
pub struct HeaderFields {
    /// Module metadata, file bytes 0x00..0x80.
    pub metadata: [u8; METADATA_SIZE],
    /// KIRK CMD1 header bytes 0x00..0x40: wrapped keys and both CMAC tags.
    pub key_block: [u8; KEY_BLOCK_LEN],
    /// KIRK CMD1 header bytes 0x70..0x80: data_size and data_offset.
    pub size_metadata: [u8; METADATA_BLOCK_LEN],
    /// Opaque 16-byte id field.
    pub id: [u8; METADATA_BLOCK_LEN],
}

/// Unmask a key block: the on-disk form is masked, KIRK-7'd, then masked again.
fn unmask_key_block(
    masked: &[u8; KEY_BLOCK_LEN],
    xorbuf: &[u8; XORBUF_LEN],
    code: u8,
) -> Result<[u8; KEY_BLOCK_LEN]> {
    let mut out = [0u8; KEY_BLOCK_LEN];
    for i in 0..KEY_BLOCK_LEN {
        out[i] = masked[i] ^ xorbuf[0x10 + i];
    }
    kirk7_decrypt(&mut out, code)?;
    for i in 0..KEY_BLOCK_LEN {
        out[i] ^= xorbuf[0x50 + i];
    }
    Ok(out)
}

/// The exact inverse of [`unmask_key_block`].
fn mask_key_block(
    plain: &[u8; KEY_BLOCK_LEN],
    xorbuf: &[u8; XORBUF_LEN],
    code: u8,
) -> Result<[u8; KEY_BLOCK_LEN]> {
    let mut out = *plain;
    for i in 0..KEY_BLOCK_LEN {
        out[i] ^= xorbuf[0x50 + i];
    }
    kirk4_encrypt(&mut out, code)?;
    for i in 0..KEY_BLOCK_LEN {
        out[i] ^= xorbuf[0x10 + i];
    }
    Ok(out)
}

/// Compute the header SHA-1 over the logical field order.
///
/// Note the hash covers the *unscrambled* id and key block, and includes the
/// first 16 bytes of the key stream as an implicit shared secret.
fn header_sha1(
    info: &TagInfo,
    xorbuf: &[u8; XORBUF_LEN],
    id: &[u8; METADATA_BLOCK_LEN],
    key_block: &[u8; KEY_BLOCK_LEN],
    size_metadata: &[u8; METADATA_BLOCK_LEN],
    metadata: &[u8; METADATA_SIZE],
) -> [u8; 20] {
    let reserved = [0u8; RESERVED_LEN];
    sha1_chunks(&[
        &info.tag.to_le_bytes(),
        &xorbuf[..0x10],
        &reserved,
        id,
        key_block,
        size_metadata,
        metadata,
    ])
}

/// Assemble a 0x150-byte encrypted-PRX header from its logical fields.
pub fn build_header(info: &TagInfo, fields: &HeaderFields) -> Result<[u8; PSP_HEADER_SIZE]> {
    let xorbuf = expand_seed(info)?;

    // The key block as the decryptor will see it after unmasking.
    let masked_key_block = mask_key_block(&fields.key_block, &xorbuf, info.code)?;

    let digest = header_sha1(
        info,
        &xorbuf,
        &fields.id,
        &masked_key_block,
        &fields.size_metadata,
        &fields.metadata,
    );

    // The tag's cipher pass covers id || sha1 || key_block[0..0x3C] as one
    // contiguous run in logical order.
    let mut scrambled = [0u8; SCRAMBLED_LEN];
    scrambled[..0x10].copy_from_slice(&fields.id);
    scrambled[0x10..0x24].copy_from_slice(&digest);
    scrambled[0x24..].copy_from_slice(&masked_key_block[..SCRAMBLED_LEN - 0x24]);
    kirk4_encrypt(&mut scrambled, info.code)?;

    let mut out = [0u8; PSP_HEADER_SIZE];
    out[..METADATA_SIZE].copy_from_slice(&fields.metadata);

    // Scatter the key block, taking its scrambled prefix and clear tail.
    let mut on_disk_key_block = [0u8; KEY_BLOCK_LEN];
    on_disk_key_block[..SCRAMBLED_LEN - 0x24].copy_from_slice(&scrambled[0x24..]);
    on_disk_key_block[SCRAMBLED_LEN - 0x24..]
        .copy_from_slice(&masked_key_block[SCRAMBLED_LEN - 0x24..]);

    out[OFF_KEY_BLOCK_LO..OFF_KEY_BLOCK_LO + 0x30].copy_from_slice(&on_disk_key_block[..0x30]);
    out[OFF_KEY_BLOCK_HI..OFF_KEY_BLOCK_HI + 0x10].copy_from_slice(&on_disk_key_block[0x30..]);
    out[OFF_SIZE_METADATA..OFF_SIZE_METADATA + METADATA_BLOCK_LEN]
        .copy_from_slice(&fields.size_metadata);
    out[OFF_TAG..OFF_TAG + 4].copy_from_slice(&info.tag.to_le_bytes());
    // 0xD4..0x12C stays zero: this scheme requires an empty signature region.
    out[OFF_SHA1..OFF_SHA1 + 0x14].copy_from_slice(&scrambled[0x10..0x24]);
    out[OFF_ID..OFF_ID + 0x10].copy_from_slice(&scrambled[..0x10]);
    Ok(out)
}

/// Recover the logical fields from a 0x150-byte header, verifying the SHA-1.
pub fn parse_header(header: &[u8]) -> Result<(&'static TagInfo, HeaderFields)> {
    if header.len() < PSP_HEADER_SIZE {
        return Err(Error::TooShort {
            expected: PSP_HEADER_SIZE,
            actual: header.len(),
        });
    }
    let tag = u32::from_le_bytes(header[OFF_TAG..OFF_TAG + 4].try_into().expect("4 bytes"));
    let info = lookup(tag)?;

    if header[OFF_RESERVED..OFF_RESERVED + RESERVED_LEN]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(Error::InvalidPrxHeader(
            "signature region is not zero; this PRX uses an unsupported scheme".into(),
        ));
    }

    let xorbuf = expand_seed(info)?;

    // Gather the scrambled run back into logical order and undo the pass.
    let mut on_disk_key_block = [0u8; KEY_BLOCK_LEN];
    on_disk_key_block[..0x30].copy_from_slice(&header[OFF_KEY_BLOCK_LO..OFF_KEY_BLOCK_LO + 0x30]);
    on_disk_key_block[0x30..].copy_from_slice(&header[OFF_KEY_BLOCK_HI..OFF_KEY_BLOCK_HI + 0x10]);

    let mut scrambled = [0u8; SCRAMBLED_LEN];
    scrambled[..0x10].copy_from_slice(&header[OFF_ID..OFF_ID + 0x10]);
    scrambled[0x10..0x24].copy_from_slice(&header[OFF_SHA1..OFF_SHA1 + 0x14]);
    scrambled[0x24..].copy_from_slice(&on_disk_key_block[..SCRAMBLED_LEN - 0x24]);
    kirk7_decrypt(&mut scrambled, info.code)?;

    let mut id = [0u8; METADATA_BLOCK_LEN];
    id.copy_from_slice(&scrambled[..0x10]);
    let stored_digest: [u8; 20] = scrambled[0x10..0x24].try_into().expect("20 bytes");

    let mut masked_key_block = on_disk_key_block;
    masked_key_block[..SCRAMBLED_LEN - 0x24].copy_from_slice(&scrambled[0x24..]);

    let mut metadata = [0u8; METADATA_SIZE];
    metadata.copy_from_slice(&header[..METADATA_SIZE]);
    let mut size_metadata = [0u8; METADATA_BLOCK_LEN];
    size_metadata
        .copy_from_slice(&header[OFF_SIZE_METADATA..OFF_SIZE_METADATA + METADATA_BLOCK_LEN]);

    let digest = header_sha1(
        info,
        &xorbuf,
        &id,
        &masked_key_block,
        &size_metadata,
        &metadata,
    );
    if digest != stored_digest {
        return Err(Error::IntegrityCheck("PSP header SHA-1 mismatch".into()));
    }

    let key_block = unmask_key_block(&masked_key_block, &xorbuf, info.code)?;
    Ok((
        info,
        HeaderFields {
            metadata,
            key_block,
            size_metadata,
            id,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> HeaderFields {
        let mut metadata = [0u8; METADATA_SIZE];
        metadata[..4].copy_from_slice(b"~PSP");
        metadata[0x0A..0x0E].copy_from_slice(b"test");
        HeaderFields {
            metadata,
            key_block: core::array::from_fn(|i| i as u8),
            size_metadata: [0xAA; 16],
            id: [0x5C; 16],
        }
    }

    #[test]
    fn key_block_masking_round_trips() {
        let xorbuf = expand_seed(&TAG_DEMO_280).unwrap();
        let plain: [u8; KEY_BLOCK_LEN] = core::array::from_fn(|i| (i * 3) as u8);
        let masked = mask_key_block(&plain, &xorbuf, TAG_DEMO_280.code).unwrap();
        assert_ne!(masked, plain);
        assert_eq!(
            unmask_key_block(&masked, &xorbuf, TAG_DEMO_280.code).unwrap(),
            plain
        );
    }

    #[test]
    fn header_round_trips() {
        let f = fields();
        let header = build_header(&TAG_DEMO_280, &f).unwrap();
        let (info, parsed) = parse_header(&header).unwrap();
        assert_eq!(info.tag, TAG_DEMO_280.tag);
        assert_eq!(parsed.metadata, f.metadata);
        assert_eq!(parsed.key_block, f.key_block);
        assert_eq!(parsed.size_metadata, f.size_metadata);
        assert_eq!(parsed.id, f.id);
    }

    #[test]
    fn built_header_has_the_expected_shape() {
        let header = build_header(&TAG_DEMO_280, &fields()).unwrap();
        assert_eq!(header.len(), PSP_HEADER_SIZE);
        assert_eq!(&header[..4], b"~PSP");
        assert_eq!(&header[OFF_TAG..OFF_TAG + 4], &0xADF3_05F0u32.to_le_bytes());
        // The signature region must be empty for this scheme.
        assert!(
            header[OFF_RESERVED..OFF_RESERVED + RESERVED_LEN]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn size_metadata_is_stored_in_the_clear() {
        // Size fields are not masked, so the header can be resized without
        // touching the key material.
        let mut f = fields();
        f.size_metadata = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let header = build_header(&TAG_DEMO_280, &f).unwrap();
        assert_eq!(
            &header[OFF_SIZE_METADATA..OFF_SIZE_METADATA + 16],
            &f.size_metadata
        );
    }

    #[test]
    fn tampering_is_detected() {
        let header = build_header(&TAG_DEMO_280, &fields()).unwrap();
        for offset in [
            0x00,
            0x40,
            OFF_KEY_BLOCK_LO,
            OFF_SIZE_METADATA,
            OFF_KEY_BLOCK_HI,
            OFF_ID,
        ] {
            let mut bad = header;
            bad[offset] ^= 0x01;
            assert!(
                parse_header(&bad).is_err(),
                "tampering at {offset:#X} went undetected"
            );
        }
    }

    #[test]
    fn unknown_tags_and_short_buffers_error_cleanly() {
        let mut header = build_header(&TAG_DEMO_280, &fields()).unwrap();
        header[OFF_TAG..OFF_TAG + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(
            parse_header(&header).unwrap_err(),
            Error::UnknownTag { .. }
        ));
        assert!(parse_header(&[]).is_err());
        assert!(parse_header(&[0u8; 0x14F]).is_err());
    }

    #[test]
    fn non_zero_signature_region_is_rejected() {
        let mut header = build_header(&TAG_DEMO_280, &fields()).unwrap();
        header[OFF_RESERVED] = 1;
        assert!(matches!(
            parse_header(&header).unwrap_err(),
            Error::InvalidPrxHeader(_)
        ));
    }
}
