//! The headline requirement: output size tracks the payload, not a template.

mod common;

use common::{PSP_HEADER_SIZE, make_prx, make_prx_with};
use pspbuild::{EncryptOptions, decrypt_prx, encrypt_prx, output_size_for, verify_prx};

fn no_compress() -> EncryptOptions {
    EncryptOptions { compress: false }
}

/// The fixture sizes called out in the implementation plan.
const FIXTURE_SIZES: &[usize] = &[
    1,          // tiny
    1024,       // small
    100 * 1024, // ~100 KB
    700 * 1024, // ~700 KB - the case that motivated this project
    1024 * 1024,
    3 * 1024 * 1024, // multiple MB
];

#[test]
fn output_is_header_plus_aligned_payload_at_every_size() {
    for &size in FIXTURE_SIZES {
        let prx = make_prx("sized", size);
        let enc = encrypt_prx(&prx, &no_compress()).unwrap();

        let expected = output_size_for(prx.len() as u64) as usize;
        assert_eq!(enc.data.len(), expected, "payload {size}");
        // Overhead is exactly the header, never a template's spare capacity.
        assert!(
            enc.data.len() - prx.len() < PSP_HEADER_SIZE + 16,
            "size {size}: overhead {} bytes",
            enc.data.len() - prx.len()
        );
    }
}

#[test]
fn a_700_kib_module_does_not_become_multiple_megabytes() {
    // The legacy implementation emits 5,583,952 bytes for an input this size
    // because it selects a 5 MiB template.
    let prx = make_prx("seven_hundred", 700 * 1024);
    let enc = encrypt_prx(&prx, &no_compress()).unwrap();

    assert!(
        enc.data.len() < 800 * 1024,
        "expected ~700 KiB, got {} bytes",
        enc.data.len()
    );
    assert!(enc.data.len() < 5_583_952 / 5);
}

#[test]
fn alignment_boundaries_are_handled() {
    // Payload exactly aligned, one below, one above.
    for size in [4096usize, 4095, 4097, 16, 15, 17] {
        let prx = make_prx_with("aligned", size, |i| i as u8);
        let enc = encrypt_prx(&prx, &no_compress()).unwrap();

        let aligned = (prx.len() + 15) & !15;
        assert_eq!(enc.data.len(), PSP_HEADER_SIZE + aligned, "size {size}");
        assert_eq!(decrypt_prx(&enc.data).unwrap(), prx, "size {size}");
    }
}

#[test]
fn every_fixture_size_round_trips_and_verifies() {
    for &size in FIXTURE_SIZES {
        let prx = make_prx("round", size);
        for options in [no_compress(), EncryptOptions::default()] {
            let enc = encrypt_prx(&prx, &options).unwrap();
            verify_prx(&enc.data).unwrap_or_else(|e| panic!("size {size}: {e}"));
            assert_eq!(decrypt_prx(&enc.data).unwrap(), prx, "size {size}");
        }
    }
}

#[test]
fn compression_shrinks_the_output_further() {
    // A highly compressible module: the container must be sized from the
    // compressed payload, so the output is far smaller than the input.
    let prx = make_prx_with("compressible", 500_000, |_| 0);
    let compressed = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();
    let plain = encrypt_prx(&prx, &no_compress()).unwrap();

    assert!(compressed.compressed);
    assert!(compressed.data.len() < plain.data.len() / 10);
    assert_eq!(decrypt_prx(&compressed.data).unwrap(), prx);
}

#[test]
fn compression_never_makes_the_output_bigger() {
    // Whatever the input, enabling compression must never cost bytes: the
    // encrypter stores the payload plain if gzip would not help.
    for size in [1usize, 64, 4096, 64 * 1024] {
        let prx = make_prx("maybe_compressible", size);
        let with = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();
        let without = encrypt_prx(&prx, &no_compress()).unwrap();

        assert!(
            with.data.len() <= without.data.len(),
            "size {size}: compression grew the output"
        );
        assert!(with.payload_size as usize <= prx.len(), "size {size}");
        assert_eq!(decrypt_prx(&with.data).unwrap(), prx, "size {size}");
    }
}

#[test]
fn output_is_reproducible() {
    let prx = make_prx("determinism", 50_000);
    let a = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();
    let b = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();
    assert_eq!(a.data, b.data);
}
