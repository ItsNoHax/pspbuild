//! Compatibility with the PSPSDK reference implementation.
//!
//! `ref_tiny.prx` was produced by the reference `PrxEncrypter` C tool. Being
//! able to parse and fully decrypt it proves this crate's understanding of the
//! `~PSP` header, the tag key stream and the KIRK container matches the real
//! format rather than merely being self-consistent.
//!
//! Byte-for-byte equality with the reference output is *not* expected: the
//! reference copies a fixed-capacity template, whereas this crate sizes the
//! container from the payload. The semantic fields are compared instead.

mod common;

use common::PSP_HEADER_SIZE;
use pspbuild::psp::header::PspModuleHeader;
use pspbuild::{inspect_prx, psp::tag, verify_prx};

/// Output of the reference PSPSDK `PrxEncrypter` for a 4 KiB input.
const REFERENCE_OUTPUT: &[u8] = include_bytes!("fixtures/ref_tiny.prx");

#[test]
fn reference_header_parses_and_its_hash_verifies() {
    // parse_header recomputes and checks the SHA-1, so this failing would mean
    // our key stream or field layout is wrong.
    let (info, fields) = tag::parse_header(REFERENCE_OUTPUT).expect("reference header must parse");

    assert_eq!(info.tag, tag::TAG_DEMO_280.tag);
    assert_eq!(&fields.metadata[..4], b"~PSP");

    let data_offset = u32::from_le_bytes(fields.size_metadata[4..8].try_into().unwrap());
    assert_eq!(data_offset, 0x80, "predata size is fixed by the format");
}

#[test]
fn reference_metadata_matches_the_file_it_describes() {
    let (_info, fields) = tag::parse_header(REFERENCE_OUTPUT).unwrap();
    let meta = PspModuleHeader::parse(&fields.metadata).unwrap();

    // psp_size is the total file size: header plus aligned payload.
    assert_eq!(meta.psp_size as usize, REFERENCE_OUTPUT.len());

    let comp_size = u32::from_le_bytes(fields.size_metadata[0..4].try_into().unwrap());
    let aligned = (comp_size as usize + 15) & !15;
    assert_eq!(PSP_HEADER_SIZE + aligned, REFERENCE_OUTPUT.len());
}

#[test]
fn reference_output_passes_full_verification() {
    // Exercises the whole chain: header SHA-1, both CMAC tags, AES-CBC
    // decryption and gzip decompression of a genuinely foreign file.
    let result = verify_prx(REFERENCE_OUTPUT).expect("reference output must verify");
    assert!(result.checks.iter().any(|c| c.contains("CMAC")));
    assert!(result.checks.iter().any(|c| c.contains("SHA-1")));
    assert!(result.recovered_size > 0);
}

#[test]
fn reference_output_can_be_inspected() {
    let info = inspect_prx(REFERENCE_OUTPUT).unwrap();
    assert!(info.encrypted);
    assert_eq!(info.tag, Some(tag::TAG_DEMO_280.tag));
    assert_eq!(info.total_size, REFERENCE_OUTPUT.len() as u64);
}

#[test]
fn reference_output_demonstrates_the_fixed_template_problem() {
    // The reference encrypted a 4 KiB input into a 360 KiB file, because the
    // smallest available template had that capacity. This is the behaviour the
    // dynamic sizing in this crate removes.
    let (_info, fields) = tag::parse_header(REFERENCE_OUTPUT).unwrap();
    let comp_size = u32::from_le_bytes(fields.size_metadata[0..4].try_into().unwrap());

    assert!(
        comp_size > 300_000,
        "expected template-sized payload, got {comp_size}"
    );
    assert_eq!(REFERENCE_OUTPUT.len(), 368_544);
}
