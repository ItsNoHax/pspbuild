//! `STARTDAT`, the boot screen a container can carry.
//!
//! An optional PNG shown while the game loads, wrapped in a 0x50-byte header
//! and appended to `DATA.PSP`.
//!
//! ```text
//! 0x00  u8[8]   magic          "STARTDAT"
//! 0x08  u32     unk1           1
//! 0x0C  u32     unk2           1
//! 0x10  u32     header_size    0x50
//! 0x14  u32     data_size      length of the PNG
//! 0x18  ...     zero to 0x50
//! 0x50  ...     the PNG itself
//! ```
//!
//! Every field above was read back out of four genuine Sony containers, which
//! agree with each other and with the reference implementation exactly — same
//! magic, same two ones, same 0x50 header, and the payload is a PNG in all
//! four.
//!
//! # Where it sits
//!
//! At `0x594 + 0xC` within `DATA.PSP` — twelve zero bytes after the licence
//! stub, not immediately after it. The gap is not explained by anything
//! observed here; it is simply what Sony writes and what the reference
//! reproduces, confirmed at offset `0x5A0` in all four containers.

use crate::error::{Error, Result};

/// Size of the header that precedes the image.
pub const HEADER_SIZE: usize = 0x50;

/// The magic at the front.
pub const MAGIC: &[u8; 8] = b"STARTDAT";

/// Gap between the end of the licence stub and the start of `STARTDAT`.
pub const GAP: usize = 0xC;

/// The PNG signature, so a caller cannot quietly supply something else.
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Wrap a PNG as a `STARTDAT` block.
pub fn build(png: &[u8]) -> Result<Vec<u8>> {
    if png.len() < PNG_MAGIC.len() || png[..8] != PNG_MAGIC {
        return Err(Error::Crypto(
            "STARTDAT payload is not a PNG; the firmware shows this image directly \
             and will not accept another format"
                .into(),
        ));
    }
    let data_size = u32::try_from(png.len())
        .map_err(|_| Error::Crypto("STARTDAT image is larger than 4 GiB".into()))?;

    let mut out = vec![0u8; HEADER_SIZE];
    out[..8].copy_from_slice(MAGIC);
    out[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
    out[0x0C..0x10].copy_from_slice(&1u32.to_le_bytes());
    out[0x10..0x14].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    out[0x14..0x18].copy_from_slice(&data_size.to_le_bytes());
    out.extend_from_slice(png);
    Ok(out)
}

/// A `STARTDAT` block's header, as read from a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartDat {
    pub header_size: u32,
    pub data_size: u32,
}

impl StartDat {
    /// Parse the header at the front of `data`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x18 || data[..8] != *MAGIC {
            return Err(Error::Crypto("not a STARTDAT block".into()));
        }
        let word = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().expect("4 bytes"));
        let parsed = StartDat {
            header_size: word(0x10),
            data_size: word(0x14),
        };

        let end = (parsed.header_size as usize)
            .checked_add(parsed.data_size as usize)
            .ok_or_else(|| Error::Crypto("STARTDAT sizes overflow".into()))?;
        if end > data.len() {
            return Err(Error::TooShort {
                expected: end,
                actual: data.len(),
            });
        }
        Ok(parsed)
    }

    /// Total bytes the block occupies.
    pub fn total_size(self) -> usize {
        self.header_size as usize + self.data_size as usize
    }

    /// The image itself.
    pub fn image(self, data: &[u8]) -> &[u8] {
        &data[self.header_size as usize..self.total_size()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(len: usize) -> Vec<u8> {
        let mut v = PNG_MAGIC.to_vec();
        v.resize(len.max(8), 0x5A);
        v
    }

    #[test]
    fn a_block_round_trips() {
        let image = png(1000);
        let block = build(&image).unwrap();

        assert_eq!(block.len(), HEADER_SIZE + image.len());
        let parsed = StartDat::parse(&block).unwrap();
        assert_eq!(parsed.header_size, HEADER_SIZE as u32);
        assert_eq!(parsed.data_size, image.len() as u32);
        assert_eq!(parsed.image(&block), &image[..]);
    }

    /// The header must match what Sony writes, byte for byte. All four
    /// containers examined carry exactly these 0x18 bytes ahead of the image.
    #[test]
    fn the_header_matches_sonys() {
        let block = build(&png(9734)).unwrap();
        assert_eq!(&block[..8], b"STARTDAT");
        assert_eq!(
            &block[0x08..0x18],
            &[
                0x01, 0x00, 0x00, 0x00, // unk1
                0x01, 0x00, 0x00, 0x00, // unk2
                0x50, 0x00, 0x00, 0x00, // header_size
                0x06, 0x26, 0x00, 0x00, // data_size = 9734, as in all four
            ]
        );
        // The rest of the header is zero.
        assert!(block[0x18..HEADER_SIZE].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_non_png_is_refused() {
        assert!(build(b"not a png at all").is_err());
        assert!(build(&[]).is_err());
    }

    #[test]
    fn malformed_blocks_are_errors_not_panics() {
        assert!(StartDat::parse(&[]).is_err());
        assert!(StartDat::parse(b"NOTSTART").is_err());

        // Sizes that run past the buffer.
        let mut block = build(&png(100)).unwrap();
        block[0x14..0x18].copy_from_slice(&999_999u32.to_le_bytes());
        assert!(StartDat::parse(&block).is_err());
    }
}
