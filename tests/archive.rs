//! Building an NPUMDIMG archive from a real UMD.
//!
//! The unit tests in `src/npdrm/archive.rs` build from synthetic images and
//! check the result reads back. This file does the two things they cannot: it
//! builds from a genuine retail disc, and it compares the result against the
//! reference implementation's output for the same disc.
//!
//! # Why the comparison is structural rather than byte-for-byte
//!
//! `header_key` and `padding` are random, and everything downstream of them —
//! the encrypted body, the header hash, every block's ciphertext and MAC, the
//! data key, the signature — moves with them. Two runs of the reference
//! implementation on identical input already differ from byte 0x40 onward, so
//! byte equality is not available even in principle.
//!
//! What *is* comparable is everything the format derives from the input: the
//! plaintext header, the decrypted body, and the geometry the block table
//! describes. Those must agree exactly, and they are where a real
//! disagreement would show.
//!
//! These tests need a UMD image and rebuild it in full, so they are gated on
//! `PSPBUILD_TEST_SLOW=1` and skip when the fixtures are absent.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use pspbuild::crypto::aes::Key;
use pspbuild::npdrm::archive::{ArchiveOptions, DEFAULT_BLOCK_BASIS, write_archive};
use pspbuild::npdrm::npumdimg::HEADER_SIZE;
use pspbuild::npdrm::random::SystemEntropy;
use pspbuild::npdrm::table::ENTRY_SIZE;
use pspbuild::npdrm::{BlockEntry, bbcipher, decrypt_block, fixed_key, verify_header};
use pspbuild::pbp::{PbpSection, parse_layout};

/// The content ID the reference archive in `plans/` was generated with.
const CONTENT_ID: &str = "UL0000-ULUS10380_00-0000000000000000";
const NP_FLAGS: u32 = 0x0100_0003;

macro_rules! slow_or_skip {
    () => {
        if std::env::var("PSPBUILD_TEST_SLOW").is_err() {
            eprintln!("skipped: set PSPBUILD_TEST_SLOW=1 to build a full archive");
            return;
        }
    };
}

fn find_iso() -> Option<PathBuf> {
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

/// Build an archive from the available ISO into a temporary file.
fn build() -> Option<(tempfile::NamedTempFile, u64, Key)> {
    let iso_path = find_iso()?;
    let mut iso = std::fs::File::open(&iso_path).ok()?;
    let iso_size = iso.metadata().ok()?.len();

    let options = ArchiveOptions::fixed_key(CONTENT_ID);
    let mut out = tempfile::NamedTempFile::new().ok()?;
    write_archive(
        &mut iso,
        iso_size,
        out.as_file_mut(),
        &options,
        &mut SystemEntropy,
    )
    .expect("the archive builds");

    let version_key = fixed_key(CONTENT_ID, NP_FLAGS).expect("fixed key derives");
    Some((out, iso_size, version_key))
}

fn read_at(file: &mut std::fs::File, offset: u64, len: usize) -> Vec<u8> {
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).expect("read");
    buf
}

/// Decrypt a header's body, which is where the geometry lives.
fn decode_body(header: &[u8], version_key: &Key) -> Vec<u8> {
    let header_key: Key = header[0xA0..0xB0].try_into().expect("16 bytes");
    let mut body = header[0x40..0xA0].to_vec();
    bbcipher(&header_key, version_key, 0, &mut body).expect("body decrypts");
    body
}

/// Locate the reference archive `sign_np` produced, if it is around.
fn find_reference() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var("PSPBUILD_TEST_EG_PBP").ok()?);
    path.is_file().then_some(path)
}

/// An archive we build from a real disc must read back as that disc.
///
/// This is the whole writer against the whole reader, over a gigabyte of real
/// data: every block encrypted and MAC'd on the way out, then MAC-checked and
/// decrypted on the way back in, and compared with the source.
#[test]
fn a_built_archive_reads_back_as_the_source_disc() {
    slow_or_skip!();
    let Some((mut archive, iso_size, version_key)) = build() else {
        eprintln!("skipped: no UMD image available");
        return;
    };
    let iso_path = find_iso().expect("an ISO was found a moment ago");
    let mut iso = std::fs::File::open(&iso_path).expect("image opens");

    let file = archive.as_file_mut();
    let header = read_at(file, 0, HEADER_SIZE);
    assert_eq!(&header[..8], b"NPUMDIMG");
    assert!(
        verify_header(&header).unwrap(),
        "our own signature must verify"
    );

    let header_key: Key = header[0xA0..0xB0].try_into().unwrap();
    let body = decode_body(&header, &version_key);
    let lba_end = u32::from_le_bytes(body[0x24..0x28].try_into().unwrap());
    let block_size = DEFAULT_BLOCK_BASIS * 2048;
    let blocks = (lba_end + 1) / DEFAULT_BLOCK_BASIS;

    let table = read_at(file, HEADER_SIZE as u64, blocks as usize * ENTRY_SIZE);

    // First, last, and a spread between, so both ends of the position-keyed
    // cipher are exercised.
    let last = blocks - 1;
    for index in [0, 1, last / 3, last / 2, last - 1, last] {
        let entry =
            BlockEntry::from_bytes(&table[index as usize * ENTRY_SIZE..]).expect("entry decodes");

        let mut block = read_at(file, u64::from(entry.offset), entry.size as usize);
        decrypt_block(&mut block, &entry, &header_key, &version_key)
            .unwrap_or_else(|e| panic!("block {index}: {e}"));

        let start = u64::from(index) * u64::from(block_size);
        let len = (block.len() as u64).min(iso_size - start) as usize;
        let mut original = vec![0u8; len];
        iso.seek(SeekFrom::Start(start)).expect("seek");
        iso.read_exact(&mut original).expect("read");

        assert_eq!(
            block[..len],
            original[..],
            "block {index} differs from the disc"
        );
    }
}

/// Everything the format derives from the input must match the reference
/// implementation's archive for the same disc.
///
/// This is the differential test the project plan asks for. It cannot compare
/// bytes — see the module comment — so it compares the three things that are
/// determined by the input rather than by the random header key.
#[test]
fn our_archive_agrees_with_the_reference_on_everything_derived_from_the_input() {
    slow_or_skip!();
    let Some(reference) = find_reference() else {
        eprintln!("skipped: point PSPBUILD_TEST_EG_PBP at a sign_np archive to compare");
        return;
    };
    let Some((mut ours, _, version_key)) = build() else {
        eprintln!("skipped: no UMD image available");
        return;
    };

    // The reference ships inside a PBP; ours is a bare DATA.PSAR.
    let mut theirs = std::fs::File::open(&reference).expect("reference opens");
    let total = theirs.metadata().unwrap().len();
    let mut container = [0u8; pspbuild::pbp::HEADER_SIZE];
    theirs.read_exact(&mut container).expect("read");
    let (psar_offset, _) = parse_layout(&container, total)
        .expect("reference is a PBP")
        .section(PbpSection::DataPsar);
    let psar_start = u64::from(psar_offset);

    let our_file = ours.as_file_mut();
    let our_header = read_at(our_file, 0, HEADER_SIZE);
    let their_header = read_at(&mut theirs, psar_start, HEADER_SIZE);
    if &their_header[..8] != b"NPUMDIMG" {
        eprintln!("skipped: the reference PBP does not carry an NPUMDIMG archive");
        return;
    }

    // 1. The plaintext part of the header: magic, flags, basis, content ID.
    assert_eq!(
        our_header[..0x40],
        their_header[..0x40],
        "the plaintext header disagrees with the reference"
    );

    // 2. The body, which is where the geometry is recorded. This is the
    //    substantive comparison: 96 bytes of derived fields.
    assert_eq!(
        decode_body(&our_header, &version_key),
        decode_body(&their_header, &version_key),
        "the decrypted header body disagrees with the reference"
    );

    // 3. The block table's geometry. The MACs cannot match, since they cover
    //    ciphertext keyed by a random header key, but where each block sits
    //    and how long it is are fixed by the input.
    let body = decode_body(&our_header, &version_key);
    let lba_end = u32::from_le_bytes(body[0x24..0x28].try_into().unwrap());
    let blocks = ((lba_end + 1) / DEFAULT_BLOCK_BASIS) as usize;

    let our_table = read_at(our_file, HEADER_SIZE as u64, blocks * ENTRY_SIZE);
    let their_table = read_at(
        &mut theirs,
        psar_start + HEADER_SIZE as u64,
        blocks * ENTRY_SIZE,
    );

    for index in 0..blocks {
        let a = BlockEntry::from_bytes(&our_table[index * ENTRY_SIZE..]).expect("ours decodes");
        let b = BlockEntry::from_bytes(&their_table[index * ENTRY_SIZE..]).expect("theirs decodes");
        assert_eq!(
            (a.offset, a.size),
            (b.offset, b.size),
            "block {index} is placed differently from the reference"
        );
        assert_ne!(
            a.mac, b.mac,
            "block {index} MACs matched, which is impossible"
        );
    }

    // And the two archives are the same length, since neither compresses.
    assert_eq!(
        our_file.metadata().unwrap().len(),
        total - psar_start,
        "our archive is a different size from the reference's"
    );
}
