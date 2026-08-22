//! The KIRK command-1 header.
//!
//! On-disk layout (0x90 bytes, little-endian). All offsets live here; no other
//! module may hard-code them.
//!
//! ```text
//! 0x00  aes_key[16]           per-module AES key, wrapped with KIRK1_KEY
//! 0x10  cmac_key[16]          per-module CMAC key, wrapped with KIRK1_KEY
//! 0x20  cmac_header_hash[16]  CMAC over 0x60..0x90
//! 0x30  cmac_data_hash[16]    CMAC over 0x60..0x90 + predata + aligned payload
//! 0x40  unused[32]            zero
//! 0x60  mode: u32             1 for CMD1
//! 0x64  unk3[12]              zero
//! 0x70  data_size: u32        payload size in bytes, before 16-byte alignment
//! 0x74  data_offset: u32      bytes of "predata" between header and payload
//! 0x78  unk4[8]               zero
//! 0x80  unk5[16]              zero
//! ```
//!
//! The encrypted container is laid out as
//! `header (0x90) || predata (data_offset) || payload (aligned to 16)`.

use crate::error::{Error, Result};
use crate::format::{align_to_block, read_array, read_u32, write_u32};

/// Size of the KIRK CMD1 header structure.
pub const HEADER_SIZE: usize = 0x90;

/// `mode` value identifying a CMD1 (decrypt-private) container.
pub const MODE_CMD1: u32 = 1;

// Field offsets.
const OFF_AES_KEY: usize = 0x00;
const OFF_CMAC_KEY: usize = 0x10;
const OFF_CMAC_HEADER_HASH: usize = 0x20;
const OFF_CMAC_DATA_HASH: usize = 0x30;
const OFF_MODE: usize = 0x60;
const OFF_DATA_SIZE: usize = 0x70;
const OFF_DATA_OFFSET: usize = 0x74;

/// Region covered by the *header* CMAC: `0x60..0x90`.
pub const CMAC_REGION_START: usize = 0x60;
/// Length of the header CMAC region.
pub const CMAC_HEADER_LEN: usize = 0x30;

/// A parsed KIRK command-1 header.
///
/// Holds plaintext key material, so it zeroes itself on drop.
#[derive(Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct KirkCmd1Header {
    /// Per-module AES key. Plaintext in memory, wrapped on disk.
    pub aes_key: [u8; 16],
    /// Per-module CMAC key. Plaintext in memory, wrapped on disk.
    pub cmac_key: [u8; 16],
    pub cmac_header_hash: [u8; 16],
    pub cmac_data_hash: [u8; 16],
    pub mode: u32,
    /// Payload size in bytes, before alignment.
    pub data_size: u32,
    /// Bytes of predata between the header and the payload.
    pub data_offset: u32,
    /// Bytes this parser does not interpret, preserved verbatim so that
    /// re-serialising a parsed header is lossless. Not key material.
    #[zeroize(skip)]
    reserved: Reserved,
}

/// Reserved/unknown header bytes, preserved rather than zeroed.
#[derive(Clone, PartialEq, Eq, Default)]
struct Reserved {
    unused_40: [u8; 32],
    unk3_64: [u8; 12],
    unk4_78: [u8; 8],
    unk5_80: [u8; 16],
}

// Keys must never reach a log or a panic message.
impl std::fmt::Debug for KirkCmd1Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KirkCmd1Header")
            .field("aes_key", &"<redacted>")
            .field("cmac_key", &"<redacted>")
            .field("mode", &self.mode)
            .field("data_size", &self.data_size)
            .field("data_offset", &self.data_offset)
            .finish_non_exhaustive()
    }
}

impl KirkCmd1Header {
    /// Build a CMD1 header describing a payload of `data_size` bytes.
    ///
    /// CMAC fields are left zero; they are filled in by the encryption step.
    pub fn new(aes_key: [u8; 16], cmac_key: [u8; 16], data_size: u32, data_offset: u32) -> Self {
        KirkCmd1Header {
            aes_key,
            cmac_key,
            cmac_header_hash: [0; 16],
            cmac_data_hash: [0; 16],
            mode: MODE_CMD1,
            data_size,
            data_offset,
            reserved: Reserved::default(),
        }
    }

    /// Parse a header from the first `HEADER_SIZE` bytes of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::TooShort {
                expected: HEADER_SIZE,
                actual: buf.len(),
            });
        }
        Ok(KirkCmd1Header {
            aes_key: read_array(buf, OFF_AES_KEY)?,
            cmac_key: read_array(buf, OFF_CMAC_KEY)?,
            cmac_header_hash: read_array(buf, OFF_CMAC_HEADER_HASH)?,
            cmac_data_hash: read_array(buf, OFF_CMAC_DATA_HASH)?,
            mode: read_u32(buf, OFF_MODE)?,
            data_size: read_u32(buf, OFF_DATA_SIZE)?,
            data_offset: read_u32(buf, OFF_DATA_OFFSET)?,
            reserved: Reserved {
                unused_40: read_array(buf, 0x40)?,
                unk3_64: read_array(buf, 0x64)?,
                unk4_78: read_array(buf, 0x78)?,
                unk5_80: read_array(buf, 0x80)?,
            },
        })
    }

    /// Serialise to the on-disk 0x90-byte form.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(&self.aes_key);
        buf[OFF_CMAC_KEY..OFF_CMAC_KEY + 16].copy_from_slice(&self.cmac_key);
        buf[OFF_CMAC_HEADER_HASH..OFF_CMAC_HEADER_HASH + 16]
            .copy_from_slice(&self.cmac_header_hash);
        buf[OFF_CMAC_DATA_HASH..OFF_CMAC_DATA_HASH + 16].copy_from_slice(&self.cmac_data_hash);
        buf[0x40..0x60].copy_from_slice(&self.reserved.unused_40);
        write_u32(&mut buf, OFF_MODE, self.mode);
        buf[0x64..0x70].copy_from_slice(&self.reserved.unk3_64);
        write_u32(&mut buf, OFF_DATA_SIZE, self.data_size);
        write_u32(&mut buf, OFF_DATA_OFFSET, self.data_offset);
        buf[0x78..0x80].copy_from_slice(&self.reserved.unk4_78);
        buf[0x80..0x90].copy_from_slice(&self.reserved.unk5_80);
        buf
    }

    /// Validate the fields this tool relies on.
    pub fn validate(&self) -> Result<()> {
        if self.mode != MODE_CMD1 {
            return Err(Error::InvalidKirkHeader(format!(
                "unsupported mode {} (expected {MODE_CMD1})",
                self.mode
            )));
        }
        if self.data_size == 0 {
            return Err(Error::InvalidKirkHeader("data_size is zero".into()));
        }
        if !self.data_offset.is_multiple_of(16) {
            return Err(Error::InvalidKirkHeader(format!(
                "data_offset {:#X} is not 16-byte aligned",
                self.data_offset
            )));
        }
        Ok(())
    }

    /// Payload size rounded up to the AES block size.
    pub fn aligned_data_size(&self) -> u64 {
        align_to_block(u64::from(self.data_size))
    }

    /// Total container size: header + predata + aligned payload.
    pub fn container_size(&self) -> u64 {
        HEADER_SIZE as u64 + u64::from(self.data_offset) + self.aligned_data_size()
    }

    /// Byte range covered by the *data* CMAC, relative to the container start.
    ///
    /// Starts at 0x60 and runs to the end of the aligned payload.
    pub fn data_cmac_range(&self) -> std::ops::Range<usize> {
        CMAC_REGION_START..self.container_size() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> KirkCmd1Header {
        KirkCmd1Header::new([0xAA; 16], [0xBB; 16], 0x1234, 0x80)
    }

    #[test]
    fn round_trips_through_bytes() {
        let h = sample();
        let parsed = KirkCmd1Header::parse(&h.to_bytes()).unwrap();
        assert!(h == parsed);
    }

    #[test]
    fn field_offsets_match_the_documented_layout() {
        let h = sample();
        let b = h.to_bytes();
        assert_eq!(&b[0x00..0x10], &[0xAA; 16]);
        assert_eq!(&b[0x10..0x20], &[0xBB; 16]);
        assert_eq!(u32::from_le_bytes(b[0x60..0x64].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(b[0x70..0x74].try_into().unwrap()),
            0x1234
        );
        assert_eq!(u32::from_le_bytes(b[0x74..0x78].try_into().unwrap()), 0x80);
    }

    #[test]
    fn preserves_reserved_bytes() {
        // Unknown bytes must survive a parse/serialise cycle untouched.
        let mut raw = [0u8; HEADER_SIZE];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Make it a structurally valid CMD1 header.
        write_u32(&mut raw, OFF_MODE, MODE_CMD1);
        write_u32(&mut raw, OFF_DATA_SIZE, 0x100);
        write_u32(&mut raw, OFF_DATA_OFFSET, 0x80);

        let parsed = KirkCmd1Header::parse(&raw).unwrap();
        assert_eq!(parsed.to_bytes(), raw);
    }

    #[test]
    fn sizes_account_for_alignment() {
        let h = KirkCmd1Header::new([0; 16], [0; 16], 0x1001, 0x80);
        assert_eq!(h.aligned_data_size(), 0x1010);
        assert_eq!(h.container_size(), 0x90 + 0x80 + 0x1010);
        assert_eq!(h.data_cmac_range(), 0x60..(0x90 + 0x80 + 0x1010));
    }

    #[test]
    fn validate_rejects_malformed_headers() {
        let mut h = sample();
        h.mode = 2;
        assert!(h.validate().is_err());

        let mut h = sample();
        h.data_size = 0;
        assert!(h.validate().is_err());

        let mut h = sample();
        h.data_offset = 0x81;
        assert!(h.validate().is_err());

        assert!(sample().validate().is_ok());
    }

    #[test]
    fn parse_rejects_short_input() {
        assert!(KirkCmd1Header::parse(&[0u8; 0x8F]).is_err());
        assert!(KirkCmd1Header::parse(&[]).is_err());
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let text = format!("{:?}", sample());
        assert!(text.contains("redacted"));
        assert!(!text.contains("170")); // 0xAA
        assert!(!text.contains("187")); // 0xBB
    }
}
