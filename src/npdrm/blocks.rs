//! NPUMDIMG block geometry and per-block crypto.
//!
//! The archive stores a UMD image as fixed-size blocks, each encrypted with
//! BB-Cipher and authenticated with a BB-MAC recorded in the block table.
//!
//! ```text
//! block_size = block_basis * 2048
//! iso_blocks = ceil(iso_size / block_size)
//! table_size = iso_blocks * 0x20
//! data       = 0x100 + table_size
//! ```
//!
//! # Each block is keyed to its own position
//!
//! BB-Cipher is seeded with `offset >> 4` — the block's byte offset within
//! `DATA.PSAR`, in 16-byte units. Two identical blocks at different offsets
//! therefore encrypt differently. That is why [`encrypt_block`] takes an
//! offset rather than an index: the position is an input to the cipher, not
//! bookkeeping.
//!
//! Note what this does *not* do. The per-block MAC covers the ciphertext, so a
//! block moved somewhere else still passes its own MAC and simply decrypts to
//! garbage. Relocation is caught one level up, where the offset is part of the
//! block table, the table is covered by the data key, and the data key sits in
//! the signed header.
//!
//! # Compression
//!
//! Blocks may be LZRC-compressed before encryption, individually, and the
//! compressed form is kept only when it saves enough to be worth it. Sony
//! archives use this heavily and mix the two freely — one observed title
//! stores 4,216 of its 6,119 blocks compressed and the rest raw.
//!
//! Compression sits *inside* the encryption, so a block is decrypted first and
//! decompressed after. A block is compressed exactly when its table entry's
//! size is below the block size; nothing in the header records it. See
//! [`crate::npdrm::lzrc`], which implements the decoder.
//!
//! [`BlockLayout`] describes where things are, which holds either way, except
//! for [`BlockLayout::archive_size`], which assumes no compression and is
//! documented as such.

use crate::crypto::aes::Key;
use crate::error::{Error, Result};
use crate::npdrm::bbcipher::bbcipher;
use crate::npdrm::bbmac::{BbMacType, bbmac};
use crate::npdrm::npumdimg::HEADER_SIZE;
use crate::npdrm::table::{BlockEntry, ENTRY_SIZE};

/// A UMD sector. Block sizes are always a multiple of this.
pub const SECTOR_SIZE: u32 = 2048;

/// Blocks are padded out to the cipher's block size.
const ALIGNMENT: u32 = 16;

/// Where an archive's parts sit, derived from the image size and block basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLayout {
    /// Sectors per block. `0x10` in every archive seen so far.
    pub block_basis: u32,
    /// Size of the source image, in bytes.
    pub iso_size: u64,
    /// Number of blocks the image divides into.
    pub blocks: u32,
}

impl BlockLayout {
    /// Work out the layout for an image.
    pub fn new(iso_size: u64, block_basis: u32) -> Result<Self> {
        if block_basis == 0 {
            return Err(Error::Crypto("block_basis must not be zero".into()));
        }
        if iso_size == 0 {
            return Err(Error::Crypto(
                "cannot build an archive from an empty image".into(),
            ));
        }

        let block_size = u64::from(block_basis) * u64::from(SECTOR_SIZE);
        let blocks = iso_size.div_ceil(block_size);
        let blocks = u32::try_from(blocks).map_err(|_| Error::PayloadTooLarge {
            size: iso_size,
            max: u64::from(u32::MAX) * block_size,
        })?;

        Ok(BlockLayout {
            block_basis,
            iso_size,
            blocks,
        })
    }

    /// Bytes of image per block.
    pub fn block_size(self) -> u32 {
        self.block_basis * SECTOR_SIZE
    }

    /// Bytes occupied by the block table.
    pub fn table_size(self) -> u64 {
        u64::from(self.blocks) * ENTRY_SIZE as u64
    }

    /// Offset of the first block's data.
    pub fn data_offset(self) -> u64 {
        HEADER_SIZE as u64 + self.table_size()
    }

    /// Total archive size, for an uncompressed build.
    ///
    /// Only exact without compression: every block is stored at full size, and
    /// the image is a whole number of blocks once the last one is padded.
    pub fn archive_size(self) -> u64 {
        self.data_offset() + u64::from(self.blocks) * u64::from(self.block_size())
    }

    /// How much of the image the final block carries before padding.
    pub fn last_block_len(self) -> u32 {
        let remainder = (self.iso_size % u64::from(self.block_size())) as u32;
        if remainder == 0 {
            self.block_size()
        } else {
            remainder
        }
    }

    /// The last sector the image occupies, as the header's `lba_end` records
    /// it. Counts the padded final block, not the image's true length.
    pub fn lba_end(self) -> u32 {
        self.blocks * self.block_basis - 1
    }

    /// `nsectors` as the header records it: [`Self::lba_end`] saturated at a
    /// single-layer UMD's capacity.
    ///
    /// A dual-layer disc genuinely exceeds this, so on a large image the two
    /// fields disagree — that is the format's behaviour, not a rounding error.
    pub fn nsectors(self) -> u32 {
        self.lba_end().min(UMD_MAX_SECTOR)
    }
}

/// The highest sector number `nsectors` will report: a single-layer UMD.
pub const UMD_MAX_SECTOR: u32 = 0x6C0BF;

/// Encrypt one block in place and produce its table entry.
///
/// `plain` must already be padded to a multiple of 16 — for the final short
/// block, zero-padded up to the full block size. `offset` is where the block
/// will sit in `DATA.PSAR`, and is what keys the cipher to its position.
pub fn encrypt_block(
    plain: &mut [u8],
    offset: u64,
    header_key: &Key,
    version_key: &Key,
) -> Result<BlockEntry> {
    let seed = block_seed(offset, plain.len())?;
    bbcipher(header_key, version_key, seed, plain)?;

    Ok(BlockEntry {
        mac: bbmac(BbMacType::Type3, plain, Some(version_key))?,
        offset: offset as u32,
        size: plain.len() as u32,
    })
}

/// Decrypt one block in place, checking its MAC first.
///
/// The MAC is over the *ciphertext*, so it can be checked before decrypting.
/// Doing it in that order means corrupt data is refused rather than turned
/// into plausible-looking plaintext.
pub fn decrypt_block(
    cipher: &mut [u8],
    entry: &BlockEntry,
    header_key: &Key,
    version_key: &Key,
) -> Result<()> {
    if cipher.len() != entry.size as usize {
        return Err(Error::IntegrityCheck(format!(
            "block at {:#X} is {} bytes but its entry says {}",
            entry.offset,
            cipher.len(),
            entry.size
        )));
    }

    let mac = bbmac(BbMacType::Type3, cipher, Some(version_key))?;
    if mac != entry.mac {
        return Err(Error::IntegrityCheck(format!(
            "block at {:#X} fails its BB-MAC",
            entry.offset
        )));
    }

    let seed = block_seed(u64::from(entry.offset), cipher.len())?;
    bbcipher(header_key, version_key, seed, cipher)
}

/// The BB-Cipher seed for a block: its offset in 16-byte units.
fn block_seed(offset: u64, len: usize) -> Result<u32> {
    if !offset.is_multiple_of(u64::from(ALIGNMENT)) {
        return Err(Error::InvalidAlignment(format!(
            "block offset {offset:#X} is not {ALIGNMENT}-byte aligned"
        )));
    }
    if !len.is_multiple_of(ALIGNMENT as usize) {
        return Err(Error::InvalidAlignment(format!(
            "block length {len} is not a multiple of {ALIGNMENT}"
        )));
    }
    u32::try_from(offset / u64::from(ALIGNMENT))
        .map_err(|_| Error::Crypto(format!("block offset {offset:#X} exceeds the seed's range")))
}

/// Compute the `data_key`: a BB-MAC over the finished block table.
///
/// This is a *result*, not an input. Every block has to be encrypted and every
/// entry written before it can be computed, which is why the archive body is
/// built before the header that describes it.
pub fn data_key(table: &[u8], version_key: &Key) -> Result<Key> {
    bbmac(BbMacType::Type3, table, Some(version_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::test_vectors::{HEADER_KEY, VERSION_KEY, filler};

    /// The reference archive's real geometry, which reconciles to the byte
    /// against the file `sign_np` produced from a retail UMD.
    #[test]
    fn the_reference_archives_geometry_reconciles() {
        const ISO_SIZE: u64 = 1_136_689_152;
        let layout = BlockLayout::new(ISO_SIZE, 0x10).unwrap();

        assert_eq!(layout.block_size(), 32768);
        assert_eq!(layout.blocks, 34_689);
        assert_eq!(layout.table_size(), 1_110_048);
        assert_eq!(layout.data_offset(), 0x100 + 1_110_048);
        assert_eq!(layout.lba_end(), 555_023);

        // This image happens to be an exact multiple of the block size, so
        // nothing is padded and the archive size is the plain sum of its
        // parts. That is what lets it reconcile to the byte against the real
        // file; an image that did not divide evenly would run slightly longer.
        assert_eq!(ISO_SIZE % u64::from(layout.block_size()), 0);
        assert_eq!(layout.last_block_len(), layout.block_size());
        assert_eq!(layout.archive_size(), 1_137_799_456);

        // nsectors saturates here; lba_end does not.
        assert_eq!(layout.nsectors(), UMD_MAX_SECTOR);
        assert!(layout.lba_end() > layout.nsectors());
    }

    #[test]
    fn an_exact_multiple_needs_no_padding() {
        let layout = BlockLayout::new(32768 * 4, 0x10).unwrap();
        assert_eq!(layout.blocks, 4);
        assert_eq!(layout.last_block_len(), layout.block_size());
        assert_eq!(layout.archive_size(), layout.data_offset() + 32768 * 4);
    }

    #[test]
    fn a_partial_block_still_counts_as_a_block() {
        let layout = BlockLayout::new(1, 0x10).unwrap();
        assert_eq!(layout.blocks, 1);
        assert_eq!(layout.last_block_len(), 1);

        let layout = BlockLayout::new(32769, 0x10).unwrap();
        assert_eq!(layout.blocks, 2);
        assert_eq!(layout.last_block_len(), 1);
    }

    #[test]
    fn a_block_round_trips_through_encryption() {
        let original = filler(32768, 4);
        let mut block = original.clone();
        let offset = 0x100 + 0x20 * 4;

        let entry = encrypt_block(&mut block, offset, &HEADER_KEY, &VERSION_KEY).unwrap();
        assert_ne!(block, original, "block was left in the clear");
        assert_eq!(entry.offset, offset as u32);
        assert_eq!(entry.size, 32768);

        decrypt_block(&mut block, &entry, &HEADER_KEY, &VERSION_KEY).unwrap();
        assert_eq!(block, original);
    }

    /// Position is an input to the cipher, so the same plaintext at two
    /// offsets must not produce the same ciphertext.
    #[test]
    fn identical_blocks_at_different_offsets_differ() {
        let mut a = filler(4096, 4);
        let mut b = a.clone();
        encrypt_block(&mut a, 0x1000, &HEADER_KEY, &VERSION_KEY).unwrap();
        encrypt_block(&mut b, 0x2000, &HEADER_KEY, &VERSION_KEY).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_corrupt_block_is_refused_before_it_is_decrypted() {
        let mut block = filler(4096, 4);
        let entry = encrypt_block(&mut block, 0x1000, &HEADER_KEY, &VERSION_KEY).unwrap();

        let mut corrupt = block.clone();
        corrupt[100] ^= 0x01;
        let err = decrypt_block(&mut corrupt, &entry, &HEADER_KEY, &VERSION_KEY).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheck(_)));

        // And the buffer was not decrypted on the way to failing.
        assert_eq!(corrupt[..100], block[..100]);
    }

    /// A relocated block yields garbage rather than an error, and it is worth
    /// being precise about why.
    ///
    /// The MAC covers the ciphertext only, so moving a block leaves it intact
    /// and the MAC still passes. The offset feeds the *cipher*, so the
    /// plaintext comes out wrong — silently. Nothing at this layer notices.
    ///
    /// What actually catches it is a level up: the offset lives in the block
    /// table, the table is covered by the data key, and the data key is in the
    /// signed header. Relocation is detected there, not here.
    #[test]
    fn a_relocated_block_decrypts_to_garbage_rather_than_failing() {
        let original = filler(4096, 4);
        let mut block = original.clone();
        let mut entry = encrypt_block(&mut block, 0x1000, &HEADER_KEY, &VERSION_KEY).unwrap();

        entry.offset = 0x2000;
        decrypt_block(&mut block, &entry, &HEADER_KEY, &VERSION_KEY)
            .expect("the MAC is over the ciphertext, so it still passes");
        assert_ne!(
            block, original,
            "the wrong seed still recovered the plaintext"
        );
    }

    /// The data key is what makes a moved block detectable, so a changed
    /// offset in the table has to change it.
    #[test]
    fn the_data_key_notices_a_moved_block() {
        let mut block = filler(4096, 4);
        let entry = encrypt_block(&mut block, 0x1000, &HEADER_KEY, &VERSION_KEY).unwrap();

        let mut moved = entry;
        moved.offset = 0x2000;

        let before = data_key(&entry.to_bytes(), &VERSION_KEY).unwrap();
        let after = data_key(&moved.to_bytes(), &VERSION_KEY).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn misaligned_blocks_are_refused() {
        let mut block = filler(4096, 4);
        assert!(encrypt_block(&mut block, 0x1008, &HEADER_KEY, &VERSION_KEY).is_err());

        let mut odd = filler(4090, 4);
        assert!(encrypt_block(&mut odd, 0x1000, &HEADER_KEY, &VERSION_KEY).is_err());
    }

    #[test]
    fn degenerate_layouts_are_errors_not_panics() {
        assert!(BlockLayout::new(0, 0x10).is_err());
        assert!(BlockLayout::new(1000, 0).is_err());
    }

    /// The data key depends on every entry, so a single changed block MAC has
    /// to move it. That is what makes it authenticate the whole table.
    #[test]
    fn the_data_key_covers_the_whole_table() {
        let mut table = filler(ENTRY_SIZE * 8, 6);
        let before = data_key(&table, &VERSION_KEY).unwrap();
        table[ENTRY_SIZE * 5] ^= 0x01;
        assert_ne!(data_key(&table, &VERSION_KEY).unwrap(), before);
    }
}
