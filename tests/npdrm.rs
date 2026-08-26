//! The NPDRM primitives against a real NPUMDIMG archive.
//!
//! The unit tests in `src/npdrm` pin each primitive against known answers
//! captured from the reference implementation. They prove the arithmetic is
//! right, but not that it has been *pointed at the right bytes* — a MAC over
//! the wrong range, or a key derived from the wrong field, would pass every
//! one of them.
//!
//! This file closes that gap. It takes a finished EG `EBOOT.PBP`, reads
//! nothing but the archive's own 256-byte header, and reconstructs the two
//! values that header commits to: the version key, from the content ID, and
//! the header hash, from everything preceding it. Both have to come out equal
//! to what is already written in the file.
//!
//! An EG EBOOT cannot be checked into the repository, so these tests skip when
//! one is not available. Point `PSPBUILD_TEST_EG_PBP` at a file, or drop one
//! in `plans/`.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use pspbuild::crypto::aes::Key;
use pspbuild::npdrm::blocks::{SECTOR_SIZE, data_key};
use pspbuild::npdrm::keys::NPUMDIMG_PUBLIC_KEY;
use pspbuild::npdrm::table::ENTRY_SIZE;
use pspbuild::npdrm::{
    BbMacType, BlockEntry, BlockLayout, bbcipher, bbmac, decrypt_block, fixed_key, lzrc,
};
use pspbuild::pbp::{PbpSection, parse_layout};

/// Offsets within the NPUMDIMG header. See `docs/NPUMDIMG.md`.
mod field {
    pub const MAGIC: std::ops::Range<usize> = 0x00..0x08;
    pub const NP_FLAGS: std::ops::Range<usize> = 0x08..0x0C;
    pub const BLOCK_BASIS: std::ops::Range<usize> = 0x0C..0x10;
    pub const CONTENT_ID: std::ops::Range<usize> = 0x10..0x40;
    pub const BODY: std::ops::Range<usize> = 0x40..0xA0;
    pub const HEADER_KEY: std::ops::Range<usize> = 0xA0..0xB0;
    pub const HASHED: std::ops::Range<usize> = 0x00..0xC0;
    pub const HEADER_HASH: std::ops::Range<usize> = 0xC0..0xD0;
    pub const PADDING: std::ops::Range<usize> = 0xD0..0xD8;
    pub const SIGNATURE: std::ops::Range<usize> = 0xD8..0x100;
}

const HEADER_SIZE: usize = 0x100;
const NPUMDIMG_MAGIC: &[u8] = b"NPUMDIMG";

/// Read just the NPUMDIMG header out of an EG EBOOT.
///
/// The archive runs to a gigabyte or more, so this reads the container layout
/// and then seeks straight to the 256 bytes it needs. Loading the section
/// would mean a gigabyte of allocation to look at a quarter kilobyte of it.
fn read_npumdimg_header(path: &Path) -> Option<[u8; HEADER_SIZE]> {
    let mut file = std::fs::File::open(path).ok()?;
    let total = file.metadata().ok()?.len();

    let mut container_header = [0u8; pspbuild::pbp::HEADER_SIZE];
    file.read_exact(&mut container_header).ok()?;
    let layout = parse_layout(&container_header, total).ok()?;

    let (offset, size) = layout.section(PbpSection::DataPsar);
    if (size as usize) < HEADER_SIZE {
        return None;
    }
    file.seek(SeekFrom::Start(offset as u64)).ok()?;

    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header).ok()?;
    (header[field::MAGIC] == *NPUMDIMG_MAGIC).then_some(header)
}

fn find_header() -> Option<[u8; HEADER_SIZE]> {
    read_npumdimg_header(&locate()?)
}

fn locate() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PSPBUILD_TEST_EG_PBP") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let plans = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plans");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(plans)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("pbp"))
        })
        .collect();
    candidates.sort();
    candidates
        .into_iter()
        .find(|p| read_npumdimg_header(p).is_some())
}

macro_rules! header_or_skip {
    () => {
        match find_header() {
            Some(header) => header,
            None => {
                eprintln!("skipped: no EG EBOOT.PBP available");
                return;
            }
        }
    };
}

/// An archive opened for reading, positioned by absolute offsets within
/// `DATA.PSAR` rather than within the containing file.
struct Archive {
    file: std::fs::File,
    psar_start: u64,
    header: [u8; HEADER_SIZE],
}

impl Archive {
    fn open() -> Option<Self> {
        let path = locate()?;
        let mut file = std::fs::File::open(&path).ok()?;
        let total = file.metadata().ok()?.len();

        let mut container_header = [0u8; pspbuild::pbp::HEADER_SIZE];
        file.read_exact(&mut container_header).ok()?;
        let (offset, _) = parse_layout(&container_header, total)
            .ok()?
            .section(PbpSection::DataPsar);

        let psar_start = u64::from(offset);
        file.seek(SeekFrom::Start(psar_start)).ok()?;
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header).ok()?;

        Some(Archive {
            file,
            psar_start,
            header,
        })
    }

    fn read_at(&mut self, offset: u64, len: usize) -> Vec<u8> {
        self.file
            .seek(SeekFrom::Start(self.psar_start + offset))
            .expect("seek within the archive");
        let mut buf = vec![0u8; len];
        self.file
            .read_exact(&mut buf)
            .expect("read within the archive");
        buf
    }

    /// The version key, when the archive is one whose key can be derived.
    ///
    /// Only fixed-key archives qualify. A Store purchase carries `np_flags`
    /// without the fixed-key bit and its key arrives separately, in a
    /// `KEYS.BIN` tied to the account that bought it — so for those there is
    /// nothing to derive and nothing this crate can decrypt.
    fn version_key(&self) -> Option<Key> {
        fixed_key(
            &content_id(&self.header),
            u32_at(&self.header, field::NP_FLAGS),
        )
        .ok()
    }

    /// The archive's geometry, taken from the header rather than assumed.
    fn layout(&mut self) -> BlockLayout {
        let version_key = self
            .version_key()
            .expect("layout() is only reachable through keyed_archive_or_skip!");
        let header_key = key_at(&self.header, field::HEADER_KEY);
        let mut body = self.header[field::BODY].to_vec();
        bbcipher(&header_key, &version_key, 0, &mut body).expect("decrypt the body");

        let lba_end = u32::from_le_bytes(body[0x24..0x28].try_into().unwrap());
        let block_basis = u32_at(&self.header, field::BLOCK_BASIS);
        let iso_size = u64::from(lba_end + 1) * u64::from(SECTOR_SIZE);

        BlockLayout::new(iso_size, block_basis).expect("a real archive has a valid layout")
    }
}

macro_rules! archive_or_skip {
    () => {
        match Archive::open() {
            Some(archive) => archive,
            None => {
                eprintln!("skipped: no EG EBOOT.PBP available");
                return;
            }
        }
    };
}

/// Like [`archive_or_skip`], but also requires an archive whose version key
/// can be derived. Anything needing to decrypt content goes through this.
macro_rules! keyed_archive_or_skip {
    () => {{
        let archive = archive_or_skip!();
        if archive.version_key().is_none() {
            eprintln!("skipped: this archive uses a supplied version key, which is not available");
            return;
        }
        archive
    }};
}

/// A header together with the version key derived from it, skipping when the
/// archive's key is not derivable.
macro_rules! keyed_header_or_skip {
    () => {{
        let header = header_or_skip!();
        match fixed_key(&content_id(&header), u32_at(&header, field::NP_FLAGS)) {
            Ok(key) => (header, key),
            Err(_) => {
                eprintln!(
                    "skipped: this archive uses a supplied version key, which is not available"
                );
                return;
            }
        }
    }};
}

/// Locate the source image the reference archive was built from, if present.
fn find_source_iso() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PSPBUILD_TEST_ISO") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let plans = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plans");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(plans)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("iso"))
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

/// The content ID as the header stores it: ASCII, NUL-padded to 0x30.
fn content_id(header: &[u8; HEADER_SIZE]) -> String {
    let raw = &header[field::CONTENT_ID];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn key_at(header: &[u8; HEADER_SIZE], range: std::ops::Range<usize>) -> Key {
    header[range].try_into().expect("16 bytes")
}

fn u32_at(header: &[u8; HEADER_SIZE], range: std::ops::Range<usize>) -> u32 {
    u32::from_le_bytes(header[range].try_into().expect("4 bytes"))
}

/// The archive's own header must authenticate under a key derived from the
/// archive's own content ID.
///
/// This is the test that matters. It exercises `fixed_key` (which is itself a
/// BB-MAC), then BB-MAC type 3 over a 0xC0-byte range that includes a
/// BB-Cipher-encrypted body — so a fault in any one of the three primitives,
/// or in the range they are applied over, breaks it.
#[test]
fn the_header_hash_recomputes_from_the_header_itself() {
    let (header, version_key) = keyed_header_or_skip!();

    let computed = bbmac(BbMacType::Type3, &header[field::HASHED], Some(&version_key))
        .expect("BB-MAC over the header");

    assert_eq!(
        computed,
        key_at(&header, field::HEADER_HASH),
        "recomputed header hash does not match the one in the file"
    );
}

/// Decrypting the body must produce the documented field values.
///
/// The header hash test would still pass if BB-Cipher were wrong, because the
/// MAC covers the body as ciphertext either way. This is what actually pins
/// the cipher: the plaintext has to be structured, and the structure has to
/// agree with the rest of the header.
#[test]
fn the_body_decrypts_to_coherent_fields() {
    let (header, version_key) = keyed_header_or_skip!();
    let header_key = key_at(&header, field::HEADER_KEY);

    let mut body = header[field::BODY].to_vec();
    bbcipher(&header_key, &version_key, 0, &mut body).expect("BB-Cipher over the body");

    let at = |off: usize| u32::from_le_bytes(body[off..off + 4].try_into().unwrap());

    // Sector size and the table offset are constants the loader relies on.
    assert_eq!(
        u16::from_le_bytes([body[0], body[1]]),
        0x0800,
        "sector_size"
    );
    assert_eq!(at(0x2C), 0x100, "block_entry_offset");
    assert_eq!(at(0x08), 0x1010, "unk_8");
    assert_eq!(at(0x28), 0x0100_3FFE, "unk_40");

    // lba_end is derived from the block count, so it has to agree with
    // block_basis in the plaintext part of the header.
    let block_basis = u32_at(&header, field::BLOCK_BASIS);
    let lba_end = at(0x24);
    assert_eq!(
        (lba_end + 1) % block_basis,
        0,
        "lba_end + 1 = {} is not a whole number of {block_basis}-sector blocks",
        lba_end + 1
    );

    // nsectors tracks lba_end but saturates at a single-layer UMD's capacity,
    // so on a disc larger than that the two fields legitimately disagree.
    const UMD_MAX_SECTOR: u32 = 0x6C0BF;
    assert_eq!(
        at(0x1C),
        lba_end.min(UMD_MAX_SECTOR),
        "nsectors should be lba_end clamped to {UMD_MAX_SECTOR:#X}"
    );

    // disc_id is rebuilt from the content ID rather than stored separately.
    let disc_id = String::from_utf8_lossy(&body[0x30..0x3A]).into_owned();
    let cid = content_id(&header);
    let expected = format!("{}-{}", &cid[7..11], &cid[11..16]);
    assert_eq!(disc_id, expected, "disc_id disagrees with the content ID");
}

/// The archive's ECDSA signature must verify under the published public key.
///
/// This is the only check in the project that exercises the signing path
/// against something we did not produce. A signature cannot be recomputed and
/// compared — it depends on a random nonce — so verifying a real one is the
/// only way to confirm the curve parameters, the digest range and the R/S
/// encoding all at once. Any one of them wrong and this fails.
#[test]
fn the_archives_signature_verifies_under_the_published_key() {
    let header = header_or_skip!();
    assert!(
        pspbuild::npdrm::verify_header(&header).expect("a full-size header"),
        "the reference archive's signature did not verify"
    );
}

/// The digest must be over the header alone, with no length prefix.
///
/// The reference hands KIRK a buffer whose first four bytes are the length
/// 0xD8, which reads like a length-prefixed message and was documented as one.
/// It is really a command header that KIRK strips. This pins the distinction
/// against a real signature, since that is the only thing that can tell them
/// apart.
#[test]
fn the_signed_digest_excludes_the_kirk_length_word() {
    let header = header_or_skip!();
    let signature =
        pspbuild::npdrm::Signature::from_bytes(&header[field::SIGNATURE]).expect("40 bytes");

    let bare = pspbuild::npdrm::header_digest(&header).expect("digest");
    assert!(
        pspbuild::npdrm::ecdsa::verify(&bare, &NPUMDIMG_PUBLIC_KEY, &signature),
        "the header-only digest should verify"
    );

    let mut prefixed = 0xD8u32.to_le_bytes().to_vec();
    prefixed.extend_from_slice(&header[..0xD8]);
    let prefixed = pspbuild::crypto::sha1::sha1(&prefixed);
    assert!(
        !pspbuild::npdrm::ecdsa::verify(&prefixed, &NPUMDIMG_PUBLIC_KEY, &signature),
        "the length-prefixed digest should not verify"
    );
}

/// Re-signing a real header with our own key must produce something that
/// verifies.
///
/// Whether the result differs from what was there before depends on where the
/// header came from, and both outcomes are correct:
///
/// - Sony's tooling and `sign_np` draw a random nonce, so their signature sits
///   on a different point and ours will differ.
/// - Our own signing is deterministic (RFC 6979), so re-signing a header this
///   crate produced reproduces the identical signature.
///
/// Asserting a difference would therefore fail on our own output, which is
/// exactly the case worth being able to run this against.
#[test]
fn we_can_re_sign_a_real_header() {
    let mut header = header_or_skip!();
    let original = header[field::SIGNATURE].to_vec();

    pspbuild::npdrm::sign_header(&mut header).expect("signing succeeds");
    assert!(
        pspbuild::npdrm::verify_header(&header).unwrap(),
        "our own signature does not verify"
    );

    // Signing is a function of the header, so doing it twice must agree.
    let once = header[field::SIGNATURE].to_vec();
    pspbuild::npdrm::sign_header(&mut header).expect("signing succeeds");
    assert_eq!(
        once,
        header[field::SIGNATURE],
        "signing is not deterministic"
    );

    if once != original {
        // A foreign header: the bytes it covers are unchanged, so the old
        // signature must still verify over them too.
        let mut restored = header;
        restored[field::SIGNATURE].copy_from_slice(&original);
        assert!(
            pspbuild::npdrm::verify_header(&restored).unwrap(),
            "the original signature stopped verifying"
        );
    }
}

/// A fixed-key archive is decryptable by anyone who knows its content ID, so
/// the ID has to be the one the derivation was actually run on.
#[test]
fn a_wrong_content_id_does_not_authenticate() {
    let (header, version_key) = keyed_header_or_skip!();

    let mut wrong = content_id(&header).into_bytes();
    let last = wrong.len() - 1;
    wrong[last] ^= 0x01;
    let wrong = String::from_utf8(wrong).expect("still ASCII");

    let key = fixed_key(&wrong, u32_at(&header, field::NP_FLAGS)).expect("derivation still runs");
    assert_ne!(key, version_key, "a changed content ID gave the same key");

    let computed = bbmac(BbMacType::Type3, &header[field::HASHED], Some(&key)).expect("BB-MAC");
    assert_ne!(computed, key_at(&header, field::HEADER_HASH));
}

/// Every byte before the hash is covered by it.
#[test]
fn tampering_anywhere_in_the_hashed_range_is_detected() {
    let (header, version_key) = keyed_header_or_skip!();
    let stored = key_at(&header, field::HEADER_HASH);

    for offset in [0x00, 0x08, 0x0C, 0x10, 0x3F, 0x40, 0x9F, 0xA0, 0xBF] {
        let mut tampered = header;
        tampered[offset] ^= 0x01;
        let computed = bbmac(
            BbMacType::Type3,
            &tampered[field::HASHED],
            Some(&version_key),
        )
        .expect("BB-MAC");
        assert_ne!(
            computed, stored,
            "a flipped bit at {offset:#04X} went unnoticed"
        );
    }
}

/// The two fields the header hash does *not* cover, recorded so the boundary
/// stays deliberate. Both are outside it: the padding is random, and the
/// signature is computed over the hash and so cannot be inside it.
#[test]
fn padding_and_signature_are_present_but_unhashed() {
    let header = header_or_skip!();
    assert!(
        header[field::PADDING].iter().any(|&b| b != 0),
        "padding should be PRNG output, not zeros"
    );
    assert!(
        header[field::SIGNATURE].iter().any(|&b| b != 0),
        "signature field should not be empty"
    );
}
/// The block table has to decode to a coherent map of the archive.
///
/// This is the first test that touches the archive *body*. It reads every
/// entry, undoes the obfuscation, and checks the offsets and sizes describe a
/// gapless run of blocks. Nothing here needs a key: if the deobfuscation were
/// wrong, the offsets would be noise and none of it would line up.
///
/// Blocks may be individually compressed, so a size below the block size is
/// expected rather than suspicious. What must hold either way is that they are
/// contiguous, that none exceeds a full block, and that they end where the
/// section does.
#[test]
fn the_block_table_maps_the_whole_archive() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let mut expected_offset = layout.data_offset();
    let mut compressed = 0usize;

    for index in 0..layout.blocks as usize {
        let entry = BlockEntry::from_bytes(&table[index * ENTRY_SIZE..])
            .unwrap_or_else(|e| panic!("entry {index} does not decode: {e}"));

        assert_eq!(
            u64::from(entry.offset),
            expected_offset,
            "entry {index} does not follow the previous block"
        );
        assert!(
            entry.size > 0 && entry.size <= layout.block_size(),
            "entry {index} has an impossible size of {}",
            entry.size
        );
        if entry.size < layout.block_size() {
            compressed += 1;
        }
        expected_offset += u64::from(entry.size);
    }

    // An uncompressed archive lands exactly on the computed size. A compressed
    // one is necessarily smaller, and cannot exceed it.
    assert!(
        expected_offset <= layout.archive_size(),
        "blocks run past where an uncompressed archive would end"
    );
    if compressed == 0 {
        assert_eq!(
            expected_offset,
            layout.archive_size(),
            "an uncompressed archive should end exactly where its geometry says"
        );
    }
    eprintln!(
        "  {} blocks, {compressed} compressed, ending at {expected_offset:#X}",
        layout.blocks
    );
}

/// The data key in the header must be the MAC over the table that follows it.
///
/// This is what ties the body to the signed header: the key is a *result* of
/// the finished table, so recomputing it proves the table has not been
/// altered since the header was made.
#[test]
fn the_data_key_is_the_mac_over_the_block_table() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let computed = data_key(&table, &version_key).expect("MAC over the table");

    // data_key sits at 0xB0, inside the region the header hash covers.
    let stored: Key = archive.header[0xB0..0xC0].try_into().unwrap();
    assert_eq!(
        computed, stored,
        "recomputed data key does not match the header"
    );
}

/// Every sampled block must match the MAC its table entry carries.
///
/// This is the check that works on any archive, compressed or not: the MAC is
/// over the block's *ciphertext*, so it needs no decompression and no
/// knowledge of what the block contains. It validates BB-MAC, the version key
/// and the table's offsets and sizes together against real data — if any one
/// of them were wrong, the MACs would not reproduce.
#[test]
fn every_sampled_block_matches_its_mac() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);

    for index in sample_indices(layout.blocks) {
        let entry =
            BlockEntry::from_bytes(&table[index as usize * ENTRY_SIZE..]).expect("entry decodes");
        let block = archive.read_at(u64::from(entry.offset), entry.size as usize);

        let mac = bbmac(BbMacType::Type3, &block, Some(&version_key)).expect("BB-MAC");
        assert_eq!(
            mac, entry.mac,
            "block {index} does not match its recorded MAC"
        );
    }
}

/// Decrypting the archive's blocks must give back the original image.
///
/// This is the strongest check available, and also the narrowest: it needs the
/// very image the archive was built from, and it needs the blocks stored
/// uncompressed, since LZRC is not implemented. When either is missing the
/// test skips rather than pretending.
#[test]
fn blocks_decrypt_back_to_the_source_image() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let Some(iso_path) = find_source_iso() else {
        eprintln!("skipped: no source ISO to compare against");
        return;
    };
    let mut iso = std::fs::File::open(&iso_path).expect("source image opens");
    if iso.metadata().unwrap().len() != layout.iso_size {
        eprintln!("skipped: the available ISO is not the source of this archive");
        return;
    }

    for index in sample_indices(layout.blocks) {
        let entry =
            BlockEntry::from_bytes(&table[index as usize * ENTRY_SIZE..]).expect("entry decodes");

        let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
        decrypt_block(&mut block, &entry, &header_key, &version_key)
            .unwrap_or_else(|e| panic!("block {index} does not decrypt: {e}"));

        let plain = if entry.size == layout.block_size() {
            block
        } else {
            lzrc::decompress(&block, layout.block_size() as usize)
                .unwrap_or_else(|e| panic!("block {index} does not decompress: {e}"))
        };

        // The final block is padded out, so compare only the image's own bytes.
        let start = u64::from(index) * u64::from(layout.block_size());
        let len = plain.len().min((layout.iso_size - start) as usize);
        let mut original = vec![0u8; len];
        iso.seek(SeekFrom::Start(start)).expect("seek in the image");
        iso.read_exact(&mut original).expect("read from the image");

        assert_eq!(
            plain[..len],
            original[..],
            "block {index} does not match the source image"
        );
    }
}

/// A block whose ciphertext has been altered must fail its MAC rather than
/// decrypt to something.
#[test]
fn a_tampered_block_is_rejected() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let entry = BlockEntry::from_bytes(&table).expect("first entry decodes");

    let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
    let victim = block.len() / 2;
    block[victim] ^= 0x01;

    assert!(
        decrypt_block(&mut block, &entry, &header_key, &version_key).is_err(),
        "a flipped bit in the ciphertext was not caught"
    );
}

/// First, last, and a spread in between, so the position-dependent cipher seed
/// is exercised at both small and large offsets.
fn sample_indices(blocks: u32) -> Vec<u32> {
    let last = blocks - 1;
    let mut indices = vec![0, last / 3, last / 2, last];
    if last >= 1 {
        indices.push(1);
        indices.push(last - 1);
    }
    indices.sort_unstable();
    indices.dedup();
    indices
}

/// Every compressed block must expand to exactly one full block.
///
/// LZRC carries no length of its own — the decoder is told how big the result
/// should be and the stream ends with a marker. If the decoder were subtly
/// wrong, the overwhelmingly likely symptom is a stream that ends early or
/// runs long, so the length is a sharp check even before the contents are
/// looked at.
#[test]
fn compressed_blocks_decompress_to_full_blocks() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);

    let mut compressed = 0;
    let mut stored = 0;
    for index in sample_indices(layout.blocks) {
        let entry =
            BlockEntry::from_bytes(&table[index as usize * ENTRY_SIZE..]).expect("entry decodes");
        let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
        decrypt_block(&mut block, &entry, &header_key, &version_key).expect("block decrypts");

        if entry.size == layout.block_size() {
            stored += 1;
            continue;
        }
        compressed += 1;

        let plain = lzrc::decompress(&block, layout.block_size() as usize)
            .unwrap_or_else(|e| panic!("block {index} does not decompress: {e}"));
        assert_eq!(
            plain.len(),
            layout.block_size() as usize,
            "block {index} decompressed to the wrong length"
        );
    }
    eprintln!("  sampled {compressed} compressed and {stored} stored blocks");
}

/// The decompressed image has to be a UMD, and it has to be *this* archive's
/// UMD.
///
/// The ISO9660 primary volume descriptor lives at sector 16, which is inside
/// the second block, so decoding one block is enough to reach it. Two things
/// are then checked against the outer NPUMDIMG header: the volume size, and
/// the disc ID embedded in the image against the archive's own content ID.
///
/// That cross-check is what makes this test worth more than a magic-number
/// comparison. The image and the header are produced independently, so they
/// can only agree if the block was decrypted, decompressed and placed
/// correctly.
#[test]
fn the_decompressed_image_is_this_archives_umd() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);

    // Sector 16, where the primary volume descriptor sits.
    const PVD_SECTOR: u32 = 16;
    let block_index = PVD_SECTOR / layout.block_basis;
    let sector_in_block = (PVD_SECTOR % layout.block_basis) as usize;

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let entry =
        BlockEntry::from_bytes(&table[block_index as usize * ENTRY_SIZE..]).expect("entry decodes");

    let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
    decrypt_block(&mut block, &entry, &header_key, &version_key).expect("block decrypts");

    let plain = if entry.size == layout.block_size() {
        block
    } else {
        lzrc::decompress(&block, layout.block_size() as usize).expect("block decompresses")
    };

    let pvd = &plain[sector_in_block * SECTOR_SIZE as usize..][..SECTOR_SIZE as usize];
    assert_eq!(pvd[0], 1, "not a primary volume descriptor");
    assert_eq!(&pvd[1..6], b"CD001", "missing the ISO9660 signature");

    // Volume size, as a both-endian field; the little-endian half is at 0x50.
    let volume_blocks = u32::from_le_bytes(pvd[0x50..0x54].try_into().unwrap());
    assert_eq!(
        u64::from(volume_blocks) * u64::from(SECTOR_SIZE),
        layout.iso_size,
        "the image's own volume size disagrees with the archive header"
    );

    // A PSP UMD names itself in the system identifier. The volume identifier
    // next to it is blank on real discs, which is why this uses the former.
    let system_id = String::from_utf8_lossy(&pvd[0x08..0x28]);
    assert_eq!(
        system_id.trim_end(),
        "PSP GAME",
        "the decompressed image does not identify as a PSP UMD"
    );
}

/// Rebuild the entire image and check it parses as a UMD.
///
/// This is the whole pipeline at once — every block decrypted, MAC-checked,
/// decompressed and reassembled — and then handed to this crate's own ISO9660
/// reader, which knows nothing about NPDRM and will simply fail if the result
/// is not a real filesystem.
///
/// It reconstructs hundreds of megabytes, so it is opt-in: set
/// `PSPBUILD_TEST_SLOW=1`. It is the strongest evidence the decoder is
/// correct and is worth running whenever LZRC changes.
#[test]
fn the_whole_image_reconstructs_and_parses() {
    if std::env::var("PSPBUILD_TEST_SLOW").is_err() {
        eprintln!("skipped: set PSPBUILD_TEST_SLOW=1 to rebuild the whole image");
        return;
    }

    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);
    let mut image = Vec::with_capacity(layout.iso_size as usize);

    for index in 0..layout.blocks as usize {
        let entry = BlockEntry::from_bytes(&table[index * ENTRY_SIZE..]).expect("entry decodes");
        let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
        decrypt_block(&mut block, &entry, &header_key, &version_key)
            .unwrap_or_else(|e| panic!("block {index}: {e}"));

        let plain = if entry.size == layout.block_size() {
            block
        } else {
            lzrc::decompress(&block, layout.block_size() as usize)
                .unwrap_or_else(|e| panic!("block {index}: {e}"))
        };
        assert_eq!(plain.len(), layout.block_size() as usize, "block {index}");
        image.extend_from_slice(&plain);
    }

    image.truncate(layout.iso_size as usize);
    assert_eq!(image.len() as u64, layout.iso_size);

    // Hand it to the ISO reader, which has no idea where these bytes came from.
    let mut iso = pspbuild::iso::Iso::new(std::io::Cursor::new(image))
        .expect("the reconstructed image is not a valid ISO9660 filesystem");

    let sfo_bytes = iso
        .read_file("/PSP_GAME/PARAM.SFO")
        .expect("the image has no PSP_GAME/PARAM.SFO");
    let sfo = pspbuild::Sfo::parse(&sfo_bytes).expect("PARAM.SFO parses");

    // A UMD's own PARAM.SFO is CATEGORY=UG, and its DISC_ID is the same title
    // the outer archive names in its content ID.
    assert_eq!(sfo.get_text("CATEGORY").as_deref(), Some("UG"));
    let disc_id = sfo.get_text("DISC_ID").expect("DISC_ID is present");
    assert!(
        content_id(&archive.header).contains(&disc_id),
        "the image's DISC_ID {disc_id:?} is not in the archive's content ID"
    );

    assert!(
        iso.exists("/PSP_GAME/SYSDIR/EBOOT.BIN"),
        "no bootable executable in the reconstructed image"
    );
}

/// Sony's own `DATA.PSP` must verify under the published key.
///
/// This is a separate signature from the archive header's, over a different
/// message — the container's `PARAM.SFO` followed by the content ID — so it
/// confirms that reading independently of everything else. It needs no version
/// key, so it works on supplied-key archives too.
#[test]
fn the_containers_data_psp_signature_verifies() {
    let Some(path) = locate() else {
        eprintln!("skipped: no EG EBOOT.PBP available");
        return;
    };
    let bytes = std::fs::read(&path).expect("the container reads");
    let pbp = pspbuild::pbp::Pbp::parse(&bytes).expect("it is a PBP");

    let param_sfo = pbp.section(PbpSection::ParamSfo);
    let data_psp = pbp.section(PbpSection::DataPsp);
    if data_psp.len() < pspbuild::npdrm::data_psp::DATA_PSP_SIZE {
        eprintln!("skipped: DATA.PSP is too small to be an EG licence stub");
        return;
    }

    assert!(
        pspbuild::npdrm::data_psp::verify(data_psp, param_sfo).unwrap(),
        "the container's DATA.PSP signature does not verify"
    );

    // The content ID and flags it declares must agree with the archive's.
    let header = read_npumdimg_header(&path).expect("the archive header reads");
    assert_eq!(
        pspbuild::npdrm::data_psp::content_id(data_psp).unwrap(),
        content_id(&header),
        "DATA.PSP names a different title from the archive"
    );
    assert_eq!(
        pspbuild::npdrm::data_psp::np_flags(data_psp).unwrap(),
        u32_at(&header, field::NP_FLAGS),
        "DATA.PSP declares different np_flags from the archive"
    );
}

/// Recompress Sony's own blocks and check we hold up on both counts.
///
/// Real disc data is the only honest test of a compressor: synthetic input
/// either compresses implausibly well or not at all. This decompresses genuine
/// blocks, compresses them again with our encoder, and checks two things —
/// that the result decodes back to the same bytes, and that it is not
/// meaningfully larger than what Sony shipped for the same block.
///
/// The ratio matters because a correct-but-poor encoder would pass every
/// round-trip test while making archives a third bigger, which was the whole
/// reason for writing one.
#[test]
fn our_compression_matches_sonys_on_their_own_blocks() {
    let mut archive = keyed_archive_or_skip!();
    let layout = archive.layout();
    let version_key = archive
        .version_key()
        .expect("checked by keyed_archive_or_skip");
    let header_key = key_at(&archive.header, field::HEADER_KEY);
    let block_size = layout.block_size() as usize;

    let table = archive.read_at(HEADER_SIZE as u64, layout.table_size() as usize);

    let (mut theirs, mut ours, mut raw, mut sampled) = (0usize, 0usize, 0usize, 0usize);
    for index in (0..layout.blocks).step_by(97) {
        let entry =
            BlockEntry::from_bytes(&table[index as usize * ENTRY_SIZE..]).expect("entry decodes");
        let mut block = archive.read_at(u64::from(entry.offset), entry.size as usize);
        decrypt_block(&mut block, &entry, &header_key, &version_key).expect("block decrypts");

        let plain = if entry.size as usize == block_size {
            block
        } else {
            lzrc::decompress(&block, block_size).expect("block decompresses")
        };

        let packed = lzrc::compress(&plain).expect("block compresses");
        assert_eq!(
            lzrc::decompress(&packed, block_size).expect("our output decodes"),
            plain,
            "block {index} did not survive our own round trip"
        );

        theirs += entry.size as usize;
        ours += packed.len().min(block_size);
        raw += block_size;
        sampled += 1;
    }

    if sampled == 0 {
        eprintln!("skipped: no blocks to sample");
        return;
    }
    let pct = |n: usize| 100.0 * n as f64 / raw as f64;
    eprintln!(
        "  {sampled} blocks: sony {:.1}%, ours {:.1}% of raw",
        pct(theirs),
        pct(ours)
    );

    // Ours must be in the same league. A 10% allowance covers a different
    // match-finding strategy without letting a genuinely bad encoder through.
    assert!(
        ours <= theirs + theirs / 10,
        "our compression is materially worse than Sony's: {ours} vs {theirs} bytes"
    );
}

/// Sony's own `OPNSSMP` container must pass the one check that needs no secret.
///
/// A PGD's DNAS MAC is keyed by a published constant rather than by the
/// content key, so it can be verified on any container. It covers the whole
/// header — magic, mode fields, both wrapped keys, the sizes and the header
/// MAC — so agreeing with it confirms the layout and the mode derivation
/// together on real data.
///
/// The rest of a Sony PGD is keyed by the content key, and every container
/// here that carries one is a supplied-key title. Those bodies cannot be
/// decrypted, and the test says so rather than pretending otherwise.
#[test]
fn sonys_opnssmp_passes_the_check_that_needs_no_key() {
    let Some(path) = locate() else {
        eprintln!("skipped: no EG EBOOT.PBP available");
        return;
    };
    let bytes = std::fs::read(&path).expect("the container reads");
    let pbp = pspbuild::pbp::Pbp::parse(&bytes).expect("it is a PBP");
    let data_psp = pbp.section(PbpSection::DataPsp);

    let Some(pgd) = pspbuild::npdrm::data_psp::opnssmp(data_psp) else {
        eprintln!("skipped: this container carries no OPNSSMP");
        return;
    };

    assert!(
        pspbuild::npdrm::pgd::verify_dnas(pgd).expect("the PGD header parses"),
        "Sony's OPNSSMP fails its DNAS MAC"
    );
    eprintln!("  OPNSSMP: {} bytes, DNAS MAC verified", pgd.len());
}

/// A container's `STARTDAT` must be a PNG behind the documented header.
#[test]
fn sonys_startdat_is_a_png_behind_the_documented_header() {
    let Some(path) = locate() else {
        eprintln!("skipped: no EG EBOOT.PBP available");
        return;
    };
    let bytes = std::fs::read(&path).expect("the container reads");
    let pbp = pspbuild::pbp::Pbp::parse(&bytes).expect("it is a PBP");
    let data_psp = pbp.section(PbpSection::DataPsp);

    let Some(block) = pspbuild::npdrm::data_psp::startdat(data_psp) else {
        eprintln!("skipped: this container carries no STARTDAT");
        return;
    };

    let parsed = pspbuild::npdrm::startdat::StartDat::parse(block).expect("STARTDAT parses");
    assert_eq!(parsed.header_size, 0x50, "unexpected STARTDAT header size");

    let image = parsed.image(block);
    assert_eq!(
        &image[..8],
        &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        "the STARTDAT payload is not a PNG"
    );
    eprintln!("  STARTDAT: {} byte PNG", image.len());
}
