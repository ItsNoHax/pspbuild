//! Malformed input must always produce an error, never a panic.

mod common;

use common::{PSP_HEADER_SIZE, make_prx};
use proptest::prelude::*;
use pspbuild::format::{align_to_block, try_align_up};
use pspbuild::{
    EncryptOptions, decrypt_prx, encrypt_prx, inspect_prx, output_size_for, verify_prx,
};

/// Run every public entry point over `data`; none may panic.
fn exercise_all(data: &[u8]) {
    let _ = encrypt_prx(data, &EncryptOptions::default());
    let _ = encrypt_prx(
        data,
        &EncryptOptions {
            compress: false,
            ..Default::default()
        },
    );
    let _ = inspect_prx(data);
    let _ = verify_prx(data);
    let _ = decrypt_prx(data);
}

#[test]
fn hand_picked_malformed_inputs() {
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xFF; 3],
        b"~PSP".to_vec(),
        b"\x7fELF".to_vec(),
        vec![0u8; PSP_HEADER_SIZE],
        vec![0xAA; PSP_HEADER_SIZE + 15],
    ];

    // A valid ELF header with an absurd segment count.
    let mut bad = make_prx("bad", 64);
    bad[0x2C..0x2E].copy_from_slice(&0xFFFFu16.to_le_bytes());
    cases.push(bad);

    // A valid ELF truncated at every interesting boundary.
    let good = make_prx("good", 4096);
    for cut in [1, 4, 16, 52, 53, 84, 0x100, 0x140, good.len() - 1] {
        cases.push(good[..cut].to_vec());
    }

    // A valid encrypted file, truncated.
    let enc = encrypt_prx(&good, &EncryptOptions::default()).unwrap();
    for cut in [1, 0x80, 0xD0, 0x14F, PSP_HEADER_SIZE, enc.data.len() - 1] {
        cases.push(enc.data[..cut].to_vec());
    }

    for case in cases {
        exercise_all(&case);
    }
}

#[test]
fn every_single_byte_corruption_of_a_header_is_caught_or_errors() {
    let prx = make_prx("corrupt", 2048);
    let enc = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();

    // Flipping any bit in the header must break verification, never panic.
    for offset in 0..PSP_HEADER_SIZE {
        let mut bad = enc.data.clone();
        bad[offset] ^= 0x80;
        assert!(
            verify_prx(&bad).is_err(),
            "corruption at {offset:#X} was accepted"
        );
    }
}

#[test]
fn every_payload_block_corruption_is_caught() {
    let prx = make_prx("payload_corrupt", 1024);
    let enc = encrypt_prx(&prx, &EncryptOptions::default()).unwrap();

    for offset in (PSP_HEADER_SIZE..enc.data.len()).step_by(16) {
        let mut bad = enc.data.clone();
        bad[offset] ^= 0x01;
        assert!(
            verify_prx(&bad).is_err(),
            "payload corruption at {offset:#X} was accepted"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes must never panic any entry point.
    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        exercise_all(&data);
    }

    /// Arbitrary bytes carrying a plausible magic must also be safe.
    #[test]
    fn arbitrary_bytes_with_psp_magic_never_panic(
        tail in prop::collection::vec(any::<u8>(), 0..2048)
    ) {
        let mut data = b"~PSP".to_vec();
        data.extend_from_slice(&tail);
        exercise_all(&data);
    }

    #[test]
    fn arbitrary_bytes_with_elf_magic_never_panic(
        tail in prop::collection::vec(any::<u8>(), 0..2048)
    ) {
        let mut data = b"\x7fELF".to_vec();
        data.extend_from_slice(&tail);
        exercise_all(&data);
    }

    /// Alignment is monotone, idempotent and adds less than one block.
    #[test]
    fn alignment_properties(value in 0u64..u64::MAX/2) {
        let aligned = align_to_block(value);
        prop_assert!(aligned >= value);
        prop_assert!(aligned - value < 16);
        prop_assert_eq!(aligned % 16, 0);
        prop_assert_eq!(align_to_block(aligned), aligned);
    }

    #[test]
    fn alignment_never_overflows(value in any::<u64>()) {
        // Must return None rather than wrapping near the top of the range.
        if let Some(aligned) = try_align_up(value, 16) {
            prop_assert!(aligned >= value);
        }
    }

    /// Output size is always exactly the header plus the aligned payload.
    #[test]
    fn output_size_is_predictable(payload_len in 1usize..8192) {
        let prx = make_prx("prop", payload_len);
        let enc = encrypt_prx(&prx, &EncryptOptions {
            compress: false,
            ..Default::default()
        }).unwrap();

        prop_assert_eq!(enc.data.len() as u64, output_size_for(prx.len() as u64));
        prop_assert_eq!(
            enc.data.len(),
            PSP_HEADER_SIZE + ((prx.len() + 15) & !15)
        );
    }

    /// Anything we encrypt, we can decrypt back byte for byte.
    #[test]
    fn round_trip_is_lossless(payload_len in 1usize..4096, compress in any::<bool>()) {
        let prx = make_prx("prop_round", payload_len);
        let enc = encrypt_prx(&prx, &EncryptOptions { compress, ..Default::default() }).unwrap();
        prop_assert_eq!(decrypt_prx(&enc.data).unwrap(), prx);
    }
}
