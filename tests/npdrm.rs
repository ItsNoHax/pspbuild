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
use pspbuild::npdrm::{BbMacType, bbcipher, bbmac, fixed_key};
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
    let header = header_or_skip!();
    let np_flags = u32_at(&header, field::NP_FLAGS);

    let version_key = fixed_key(&content_id(&header), np_flags)
        .expect("a fixed-key archive derives its own version key");

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
    let header = header_or_skip!();
    let np_flags = u32_at(&header, field::NP_FLAGS);
    let version_key = fixed_key(&content_id(&header), np_flags).expect("version key");
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

/// A fixed-key archive is decryptable by anyone who knows its content ID, so
/// the ID has to be the one the derivation was actually run on.
#[test]
fn a_wrong_content_id_does_not_authenticate() {
    let header = header_or_skip!();
    let np_flags = u32_at(&header, field::NP_FLAGS);

    let mut wrong = content_id(&header).into_bytes();
    let last = wrong.len() - 1;
    wrong[last] ^= 0x01;
    let wrong = String::from_utf8(wrong).expect("still ASCII");

    let key = fixed_key(&wrong, np_flags).expect("derivation still runs");
    let computed = bbmac(BbMacType::Type3, &header[field::HASHED], Some(&key)).expect("BB-MAC");

    assert_ne!(computed, key_at(&header, field::HEADER_HASH));
}

/// Every byte before the hash is covered by it.
#[test]
fn tampering_anywhere_in_the_hashed_range_is_detected() {
    let header = header_or_skip!();
    let np_flags = u32_at(&header, field::NP_FLAGS);
    let version_key = fixed_key(&content_id(&header), np_flags).expect("version key");
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
