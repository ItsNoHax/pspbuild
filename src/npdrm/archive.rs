//! Writing a complete NPUMDIMG archive.
//!
//! # The build order is forced
//!
//! Every part of the archive commits to the part after it, so there is exactly
//! one order in which it can be assembled:
//!
//! ```text
//! header_key                      random, and needed before any block
//!   └─ encrypt each block          keyed to its own offset
//!       └─ block table             each entry's MAC and position
//!           └─ data_key            a MAC over the finished table
//!               └─ header          carries data_key, then is hashed
//!                   └─ signature   over the finished header
//! ```
//!
//! `data_key` is the reason the header cannot be written first: it is a MAC
//! over the completed table, so the body has to exist before the header that
//! describes it can be built. The writer handles this by reserving space,
//! streaming the blocks, then seeking back to fill in the header and table it
//! could only compute at the end.
//!
//! # Memory
//!
//! A UMD runs to a gigabyte or more, so nothing proportional to the image is
//! held: blocks are read, encrypted and written one at a time. Only the block
//! table is kept, at 0x20 bytes per 32 KiB of image — about a megabyte for a
//! full disc.
//!
//! # Compression
//!
//! Each block is compressed independently and kept compressed only when it
//! saves at least [`RATIO_LIMIT`]; otherwise it is stored raw. That is the
//! reference implementation's rule, and it is why a real archive mixes the two
//! freely. Nothing in the header records which a block is — a block is
//! compressed exactly when its table entry is smaller than a full block.
//!
//! Compression can be turned off with [`ArchiveOptions::compress`], which
//! makes the output directly comparable with an uncompressed reference build.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::crypto::aes::Key;
use crate::error::{Error, Result};
use crate::npdrm::blocks::{BlockLayout, data_key, encrypt_block};
use crate::npdrm::fixed_key::{FIXED_KEY_FLAG, fixed_key};
use crate::npdrm::lzrc;
use crate::npdrm::npumdimg::{CONTENT_ID_SIZE, HEADER_SIZE, HeaderFields, build_header};
use crate::npdrm::random::Entropy;
use crate::npdrm::table::ENTRY_SIZE;

/// `np_flags` for a fixed-key archive: derivable from the content ID, so
/// playable without the account that bought it.
pub const NP_FLAGS_FIXED_KEY: u32 = 0x0100_0003;

/// Sectors per block. Every archive observed uses this.
pub const DEFAULT_BLOCK_BASIS: u32 = 0x10;

/// A compressed block is kept only if it comes to less than this percentage of
/// a full one. Below the threshold the decode cost is not worth the space.
pub const RATIO_LIMIT: usize = 90;

/// How to build an archive.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// The content ID, which for a fixed-key archive also derives the key.
    pub content_id: String,
    /// `np_flags` verbatim.
    pub np_flags: u32,
    /// Sectors per block.
    pub block_basis: u32,
    /// The version key. Required unless `np_flags` requests a fixed key, in
    /// which case it is derived and this must be `None`.
    pub version_key: Option<Key>,
    /// Compress blocks that benefit from it. Sony's archives do.
    pub compress: bool,
    /// A PNG to show while the game loads.
    pub startdat: Option<Vec<u8>>,
    /// An `OPNSSMP.BIN` module to carry, encrypted as a PGD.
    pub opnssmp: Option<Vec<u8>>,
}

impl ArchiveOptions {
    /// A fixed-key archive for `content_id`.
    pub fn fixed_key(content_id: impl Into<String>) -> Self {
        ArchiveOptions {
            content_id: content_id.into(),
            np_flags: NP_FLAGS_FIXED_KEY,
            block_basis: DEFAULT_BLOCK_BASIS,
            version_key: None,
            compress: true,
            startdat: None,
            opnssmp: None,
        }
    }

    /// The version key, for callers outside this module that need it — the
    /// EG builder encrypts an `OPNSSMP` under the same key.
    pub fn version_key_for_extras(&self) -> Result<Key> {
        self.resolve_version_key()
    }

    /// Resolve the version key this archive will be built under.
    fn resolve_version_key(&self) -> Result<Key> {
        match (self.np_flags & FIXED_KEY_FLAG != 0, self.version_key) {
            (true, None) => fixed_key(&self.content_id, self.np_flags),
            (false, Some(key)) => Ok(key),
            (true, Some(_)) => Err(Error::Crypto(
                "np_flags requests a derived fixed key, but a version key was also supplied; \
                 one of the two is wrong"
                    .into(),
            )),
            (false, None) => Err(Error::Crypto(
                "np_flags does not request a fixed key, so a version key must be supplied".into(),
            )),
        }
    }
}

/// What was written.
#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    pub layout: BlockLayout,
    /// Total bytes written.
    pub size: u64,
    /// The header key drawn for this archive. Never log it.
    pub header_key: Key,
    /// The MAC over the finished block table.
    pub data_key: Key,
    /// How many blocks were stored compressed rather than raw.
    pub compressed_blocks: u32,
}

/// Write a `DATA.PSAR` for `image` into `out`.
///
/// `out` must be seekable: the header and table are written twice, once as
/// reserved space and once for real, because neither can be computed until
/// every block has been.
pub fn write_archive<R, W, E>(
    image: &mut R,
    image_size: u64,
    out: &mut W,
    options: &ArchiveOptions,
    entropy: &mut E,
) -> Result<ArchiveSummary>
where
    R: Read + Seek,
    W: Write + Seek,
    E: Entropy,
{
    if options.content_id.len() > CONTENT_ID_SIZE || !options.content_id.is_ascii() {
        return Err(Error::Crypto(format!(
            "content ID {:?} must be at most {CONTENT_ID_SIZE} bytes of ASCII",
            options.content_id
        )));
    }

    let version_key = options.resolve_version_key()?;
    let layout = BlockLayout::new(image_size, options.block_basis)?;
    let header_key = entropy.header_key()?;

    let start = out.stream_position()?;
    let table_size = layout.table_size();

    // Reserve the header and table; both are written for real at the end.
    out.seek(SeekFrom::Start(start + HEADER_SIZE as u64 + table_size))?;
    image.seek(SeekFrom::Start(0))?;

    let block_size = layout.block_size() as usize;
    let mut table = Vec::with_capacity(table_size as usize);
    let mut buffer = vec![0u8; block_size];
    let mut offset = layout.data_offset();
    let mut remaining = image_size;
    let mut compressed_blocks = 0u32;

    for index in 0..layout.blocks {
        // The final block is short and is zero-padded out to a whole block.
        let take = remaining.min(block_size as u64) as usize;
        buffer[..take].fill(0);
        image.read_exact(&mut buffer[..take])?;
        buffer[take..].fill(0);
        remaining -= take as u64;

        // Compress, and keep the result only if it earns its place. The
        // encrypted length must stay a multiple of 16, so a compressed block
        // is padded up to one.
        let mut payload = if options.compress {
            let packed = lzrc::compress(&buffer)?;
            if packed.len() * 100 / block_size < RATIO_LIMIT {
                compressed_blocks += 1;
                let mut padded = packed;
                padded.resize(padded.len().next_multiple_of(16), 0);
                padded
            } else {
                buffer.clone()
            }
        } else {
            buffer.clone()
        };

        let entry = encrypt_block(&mut payload, offset, &header_key, &version_key)
            .map_err(|e| Error::Crypto(format!("block {index}: {e}")))?;
        out.write_all(&payload)?;

        table.extend_from_slice(&entry.to_bytes());
        offset += u64::from(entry.size);
    }

    debug_assert_eq!(table.len() as u64, table_size);
    debug_assert_eq!(remaining, 0);

    // Only now does the data key exist.
    let data_key = data_key(&table, &version_key)?;

    let header = build_header(
        &HeaderFields {
            content_id: options.content_id.clone(),
            np_flags: options.np_flags,
            layout,
            header_key,
            data_key,
            padding: entropy.padding()?,
        },
        &version_key,
    )?;

    out.seek(SeekFrom::Start(start))?;
    out.write_all(&header)?;
    out.write_all(&table)?;

    // `offset` counts from the archive's own start, which is what the block
    // table records; the sink may be positioned anywhere in a larger file.
    out.seek(SeekFrom::Start(start + offset))?;
    out.flush()?;

    Ok(ArchiveSummary {
        layout,
        size: offset,
        header_key,
        data_key,
        compressed_blocks,
    })
}

/// Size of the archive [`write_archive`] would produce for an image.
///
/// Exact, because nothing is compressed.
pub fn archive_size_for(image_size: u64, block_basis: u32) -> Result<u64> {
    Ok(BlockLayout::new(image_size, block_basis)?.archive_size())
}

/// Bytes of block table for an image, for callers sizing a buffer.
pub fn table_size_for(image_size: u64, block_basis: u32) -> Result<u64> {
    Ok(BlockLayout::new(image_size, block_basis)?.blocks as u64 * ENTRY_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::random::PredictableEntropy;
    use crate::npdrm::table::BlockEntry;
    use crate::npdrm::{BbMacType, bbcipher, bbmac, decrypt_block, verify_header};
    use std::io::Cursor;

    const CONTENT_ID: &str = "UL0000-ABCD12345_00-0000000000000000";

    /// A synthetic image with enough structure that a misplaced block shows up
    /// as a mismatch rather than as a coincidence.
    fn image(size: usize) -> Vec<u8> {
        (0..size)
            .map(|i| (i.wrapping_mul(31).wrapping_add(i >> 11)) as u8)
            .collect()
    }

    /// Build with compression on, as a real archive would be.
    fn build(image_bytes: &[u8]) -> (Vec<u8>, ArchiveSummary, Key) {
        build_with(image_bytes, true)
    }

    /// Build with compression off, so sizes are exactly predictable.
    fn build_raw(image_bytes: &[u8]) -> (Vec<u8>, ArchiveSummary, Key) {
        build_with(image_bytes, false)
    }

    fn build_with(image_bytes: &[u8], compress: bool) -> (Vec<u8>, ArchiveSummary, Key) {
        let mut options = ArchiveOptions::fixed_key(CONTENT_ID);
        options.compress = compress;
        let version_key = options.resolve_version_key().unwrap();
        let mut out = Cursor::new(Vec::new());
        let summary = write_archive(
            &mut Cursor::new(image_bytes.to_vec()),
            image_bytes.len() as u64,
            &mut out,
            &options,
            &mut PredictableEntropy::new(0x11),
        )
        .unwrap();
        (out.into_inner(), summary, version_key)
    }

    /// Read the archive back the way the firmware would, and check it gives
    /// the image again.
    fn read_back(archive: &[u8], version_key: &Key) -> Vec<u8> {
        let header: [u8; HEADER_SIZE] = archive[..HEADER_SIZE].try_into().unwrap();
        let header_key: Key = header[0xA0..0xB0].try_into().unwrap();

        let mut body = header[0x40..0xA0].to_vec();
        bbcipher(&header_key, version_key, 0, &mut body).unwrap();
        let lba_end = u32::from_le_bytes(body[0x24..0x28].try_into().unwrap());
        let block_basis = u32::from_le_bytes(header[0x0C..0x10].try_into().unwrap());
        let blocks = (u64::from(lba_end) + 1) / u64::from(block_basis);

        let block_size = (block_basis * 2048) as usize;
        let mut image = Vec::new();
        for index in 0..blocks as usize {
            let entry =
                BlockEntry::from_bytes(&archive[HEADER_SIZE + index * ENTRY_SIZE..]).unwrap();
            let mut block = archive[entry.offset as usize..][..entry.size as usize].to_vec();
            decrypt_block(&mut block, &entry, &header_key, version_key).unwrap();

            // A block is compressed exactly when its entry is shorter than a
            // full block; nothing in the header records it.
            let plain = if entry.size as usize == block_size {
                block
            } else {
                crate::npdrm::lzrc::decompress(&block, block_size).unwrap()
            };
            image.extend_from_slice(&plain);
        }
        image
    }

    #[test]
    fn an_archive_reads_back_as_the_image_it_was_built_from() {
        // Sizes either side of a block boundary, so padding is exercised.
        for size in [1usize, 1000, 32768, 32769, 32768 * 3, 32768 * 3 + 17] {
            let original = image(size);
            let (archive, summary, version_key) = build_raw(&original);

            assert_eq!(archive.len() as u64, summary.size);
            assert_eq!(archive.len() as u64, summary.layout.archive_size());
            assert_eq!(&archive[..8], b"NPUMDIMG");

            let recovered = read_back(&archive, &version_key);
            assert_eq!(&recovered[..size], &original[..], "size {size}");
            assert!(
                recovered[size..].iter().all(|&b| b == 0),
                "size {size}: the final block is not zero-padded"
            );
        }
    }

    #[test]
    fn the_header_is_signed_and_authenticates() {
        let (archive, summary, version_key) = build(&image(32768 * 2));

        assert!(verify_header(&archive[..HEADER_SIZE]).unwrap());

        // The header hash covers everything before it, including the keys.
        let computed = bbmac(BbMacType::Type3, &archive[..0xC0], Some(&version_key)).unwrap();
        assert_eq!(computed[..], archive[0xC0..0xD0]);

        // And the data key is the MAC over the table we actually wrote.
        let table_size = summary.layout.table_size() as usize;
        let table = &archive[HEADER_SIZE..HEADER_SIZE + table_size];
        assert_eq!(data_key(table, &version_key).unwrap(), summary.data_key);
        assert_eq!(summary.data_key[..], archive[0xB0..0xC0]);
    }

    /// The table must describe a gapless run of blocks ending at the archive's
    /// end — the same property real archives were checked for.
    #[test]
    fn the_table_maps_the_archive_without_gaps() {
        let (archive, summary, _) = build_raw(&image(32768 * 5 + 99));
        let layout = summary.layout;

        let mut expected = layout.data_offset();
        for index in 0..layout.blocks as usize {
            let entry =
                BlockEntry::from_bytes(&archive[HEADER_SIZE + index * ENTRY_SIZE..]).unwrap();
            assert_eq!(u64::from(entry.offset), expected, "entry {index}");
            assert_eq!(entry.size, layout.block_size(), "entry {index}");
            expected += u64::from(entry.size);
        }
        assert_eq!(expected, archive.len() as u64);
    }

    /// The body decodes to the fields the format specifies, checked here
    /// against the same rules real Sony archives were checked against.
    #[test]
    fn the_body_holds_the_expected_geometry() {
        let (archive, summary, version_key) = build(&image(32768 * 4));
        let header_key: Key = archive[0xA0..0xB0].try_into().unwrap();

        let mut body = archive[0x40..0xA0].to_vec();
        bbcipher(&header_key, &version_key, 0, &mut body).unwrap();
        let w = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap());

        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 0x0800);
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 0xE000);
        assert_eq!(w(0x08), 0x1010);
        assert_eq!(w(0x14), 0, "lba_start");
        assert_eq!(w(0x1C), summary.layout.nsectors());
        assert_eq!(w(0x24), summary.layout.lba_end());
        assert_eq!(w(0x28), 0x0100_3FFE);
        assert_eq!(w(0x2C), HEADER_SIZE as u32);
        assert_eq!(&body[0x30..0x3A], b"ABCD-12345");
    }

    #[test]
    fn a_supplied_key_archive_needs_a_key_and_a_fixed_key_one_must_not_have_one() {
        let mut options = ArchiveOptions::fixed_key(CONTENT_ID);
        options.version_key = Some([1u8; 16]);
        assert!(options.resolve_version_key().is_err());

        let mut options = ArchiveOptions::fixed_key(CONTENT_ID);
        options.np_flags = 0x0000_0003;
        assert!(options.resolve_version_key().is_err());
        options.version_key = Some([1u8; 16]);
        assert!(options.resolve_version_key().is_ok());
    }

    #[test]
    fn a_bad_content_id_is_refused() {
        let mut out = Cursor::new(Vec::new());
        let mut entropy = PredictableEntropy::new(1);

        for id in [
            "",
            "too-short",
            &"A".repeat(0x31),
            "not-ascii-Ω-here-padded-out-more",
        ] {
            let options = ArchiveOptions::fixed_key(id);
            assert!(
                write_archive(
                    &mut Cursor::new(vec![0u8; 64]),
                    64,
                    &mut out,
                    &options,
                    &mut entropy
                )
                .is_err(),
                "content ID {id:?} was accepted"
            );
        }
    }

    #[test]
    fn an_empty_image_is_refused() {
        let options = ArchiveOptions::fixed_key(CONTENT_ID);
        assert!(
            write_archive(
                &mut Cursor::new(Vec::new()),
                0,
                &mut Cursor::new(Vec::new()),
                &options,
                &mut PredictableEntropy::new(1),
            )
            .is_err()
        );
    }

    /// The header key is random, so two builds of the same image differ — and
    /// they must differ from 0x40 on, not before, matching what two runs of
    /// the reference implementation do.
    #[test]
    fn two_builds_differ_only_where_the_format_requires() {
        let original = image(32768 * 2);
        let options = ArchiveOptions::fixed_key(CONTENT_ID);

        let mut a = Cursor::new(Vec::new());
        let mut b = Cursor::new(Vec::new());
        write_archive(
            &mut Cursor::new(original.clone()),
            original.len() as u64,
            &mut a,
            &options,
            &mut PredictableEntropy::new(0x11),
        )
        .unwrap();
        write_archive(
            &mut Cursor::new(original.clone()),
            original.len() as u64,
            &mut b,
            &options,
            &mut PredictableEntropy::new(0x22),
        )
        .unwrap();

        let (a, b) = (a.into_inner(), b.into_inner());
        assert_eq!(a.len(), b.len());
        assert_eq!(
            a[..0x40],
            b[..0x40],
            "the plaintext header should be stable"
        );
        assert_ne!(
            a[0x40..],
            b[0x40..],
            "a different header key changed nothing"
        );

        // Both still read back to the same image.
        let version_key = options.resolve_version_key().unwrap();
        assert_eq!(read_back(&a, &version_key), read_back(&b, &version_key));
    }

    /// Writing into the middle of a larger file must work.
    ///
    /// The block table records offsets from the archive's own start, not from
    /// the file's, and conflating the two is invisible whenever the archive
    /// happens to begin at zero — which every other test here does. An EG
    /// container puts the archive after a PBP header, so this is the case that
    /// actually ships.
    #[test]
    fn an_archive_can_be_written_at_a_non_zero_offset() {
        const PREFIX: usize = 0x123;
        let original = image(32768 * 2 + 40);
        let options = ArchiveOptions::fixed_key(CONTENT_ID);

        let mut out = Cursor::new(vec![0xEEu8; PREFIX]);
        out.set_position(PREFIX as u64);
        let summary = write_archive(
            &mut Cursor::new(original.clone()),
            original.len() as u64,
            &mut out,
            &options,
            &mut PredictableEntropy::new(0x11),
        )
        .unwrap();

        let bytes = out.into_inner();
        // The prefix is untouched, and the file ends where the archive does.
        assert!(bytes[..PREFIX].iter().all(|&b| b == 0xEE));
        assert_eq!(bytes.len() as u64, PREFIX as u64 + summary.size);
        assert_eq!(&bytes[PREFIX..PREFIX + 8], b"NPUMDIMG");

        // And it reads back, with offsets interpreted the archive's way.
        let version_key = options.resolve_version_key().unwrap();
        let recovered = read_back(&bytes[PREFIX..], &version_key);
        assert_eq!(&recovered[..original.len()], &original[..]);
    }

    /// Compression has to be doing something, and the result has to read back.
    ///
    /// A compressor that silently fell back to raw for every block would pass
    /// every round-trip test in this file, so the size is asserted too.
    #[test]
    fn compression_shrinks_the_archive_and_still_reads_back() {
        let original = image(32768 * 6 + 11);

        let (raw, raw_summary, version_key) = build_raw(&original);
        let (packed, packed_summary, _) = build(&original);

        assert_eq!(raw_summary.compressed_blocks, 0);
        assert_eq!(
            packed_summary.compressed_blocks, packed_summary.layout.blocks,
            "this input should compress in every block"
        );
        assert!(
            packed.len() < raw.len() / 2,
            "compressed archive is {} bytes against {} raw",
            packed.len(),
            raw.len()
        );

        // Both forms recover the same image.
        assert_eq!(
            read_back(&packed, &version_key),
            read_back(&raw, &version_key)
        );
        assert_eq!(
            &read_back(&packed, &version_key)[..original.len()],
            &original[..]
        );

        // The header still authenticates over the compressed body.
        assert!(verify_header(&packed[..HEADER_SIZE]).unwrap());
        let table_size = packed_summary.layout.table_size() as usize;
        assert_eq!(
            data_key(&packed[HEADER_SIZE..HEADER_SIZE + table_size], &version_key).unwrap(),
            packed_summary.data_key
        );
    }

    /// Incompressible blocks must be stored raw rather than stored larger.
    #[test]
    fn incompressible_blocks_fall_back_to_raw() {
        // A deterministic xorshift, which genuinely does not compress — a
        // multiplicative counter looks random but is not, and LZRC finds it.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let noise: Vec<u8> = (0..32768 * 2)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let (archive, summary, version_key) = build(&noise);

        assert_eq!(
            summary.compressed_blocks, 0,
            "noise should not have been kept compressed"
        );
        assert_eq!(archive.len() as u64, summary.layout.archive_size());
        assert_eq!(
            &read_back(&archive, &version_key)[..noise.len()],
            &noise[..]
        );
    }

    /// The size helpers describe an uncompressed build, which is the only
    /// case where the total is predictable without doing the work.
    #[test]
    fn the_size_helpers_agree_with_what_is_written() {
        let original = image(32768 * 3 + 5);
        let (archive, summary, _) = build_raw(&original);
        assert_eq!(
            archive_size_for(original.len() as u64, DEFAULT_BLOCK_BASIS).unwrap(),
            archive.len() as u64
        );
        assert_eq!(
            table_size_for(original.len() as u64, DEFAULT_BLOCK_BASIS).unwrap(),
            summary.layout.table_size()
        );
    }
}
