//! AES-CMAC (RFC 4493) and the CMAC *forge* operation used by KIRK.
//!
//! The PSP reference implementation ships its own RFC 4493 code; this module
//! uses the `cmac` crate for the standard direction and implements the forge
//! direction directly, since it is not a standard primitive.

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};

use super::aes::{Aes128Ctx, BLOCK_SIZE, Key};
use crate::error::{Error, Result};

/// A 128-bit CMAC tag.
pub type Mac128 = [u8; 16];

/// Compute AES-CMAC-128 over `data`.
pub fn aes_cmac(key: &Key, data: &[u8]) -> Mac128 {
    let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("AES-128 key is 16 bytes");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derive the RFC 4493 subkeys K1 and K2.
///
/// K1 = dbl(AES(K, 0^128)), K2 = dbl(K1), where `dbl` is multiplication by x
/// in GF(2^128) with reduction polynomial 0x87.
fn generate_subkeys(ctx: &Aes128Ctx) -> (Mac128, Mac128) {
    let l = ctx.encrypt_block(&[0u8; BLOCK_SIZE]);
    let k1 = dbl(&l);
    let k2 = dbl(&k1);
    (k1, k2)
}

fn dbl(input: &Mac128) -> Mac128 {
    let mut out = [0u8; 16];
    let msb_set = input[0] & 0x80 != 0;
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }
    if msb_set {
        out[15] ^= 0x87;
    }
    out
}

/// Rewrite the final 16-byte block of `data` so that `aes_cmac(key, data)`
/// equals `target`.
///
/// # Why this exists
///
/// A KIRK CMD1 header carries two CMAC tags: one over the 0x30-byte header
/// region and one over the header plus the whole payload. In the legacy
/// template-based flow those tags are copied verbatim from a genuine Sony
/// module, so they cannot be recomputed — instead the *data* is adjusted until
/// it hashes to the already-known tag.
///
/// # Why it works
///
/// CMAC finalises as `T = AES(K, X_{n-1} XOR M_n XOR K1)` where `X_{n-1}` is
/// the CBC-MAC state over all preceding blocks and `M_n` is the last block.
/// Every term except `M_n` is fixed, and `AES` is a bijection, so the required
/// last block is `M_n' = AES^-1(K, T) XOR X_{n-1} XOR K1` — a single inverse
/// cipher call, no search involved.
///
/// # Constraints
///
/// `data.len()` must be a non-zero multiple of the block size, so that the
/// final block is complete and K1 (not K2, with its padding) applies. The last
/// block is overwritten, so it must not hold data that matters.
pub fn aes_cmac_forge(key: &Key, data: &mut [u8], target: &Mac128) -> Result<()> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidAlignment(format!(
            "CMAC forge needs a non-zero multiple of {BLOCK_SIZE} bytes, got {}",
            data.len()
        )));
    }

    let ctx = Aes128Ctx::new(key);
    let (k1, _k2) = generate_subkeys(&ctx);
    let last_start = data.len() - BLOCK_SIZE;

    // CBC-MAC state over every block except the last.
    let mut x = [0u8; BLOCK_SIZE];
    let (blocks, _rest) = data[..last_start].as_chunks::<BLOCK_SIZE>();
    for block in blocks {
        for i in 0..BLOCK_SIZE {
            x[i] ^= block[i];
        }
        x = ctx.encrypt_block(&x);
    }

    // Required pre-cipher value, then peel off the fixed terms.
    let pre = ctx.decrypt_block(target);
    let mut new_last = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        new_last[i] = pre[i] ^ x[i] ^ k1[i];
    }
    data[last_start..].copy_from_slice(&new_last);

    debug_assert_eq!(
        &aes_cmac(key, data),
        target,
        "forge must hit the target tag"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4493 test key.
    const RFC_KEY: Key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    const RFC_MSG: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];

    #[test]
    fn rfc4493_example_1_empty() {
        assert_eq!(
            aes_cmac(&RFC_KEY, &[]),
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46
            ]
        );
    }

    #[test]
    fn rfc4493_example_2_one_block() {
        assert_eq!(
            aes_cmac(&RFC_KEY, &RFC_MSG[..16]),
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c
            ]
        );
    }

    #[test]
    fn rfc4493_example_3_partial_block() {
        assert_eq!(
            aes_cmac(&RFC_KEY, &RFC_MSG[..40]),
            [
                0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
                0xc8, 0x27
            ]
        );
    }

    #[test]
    fn rfc4493_example_4_full_blocks() {
        assert_eq!(
            aes_cmac(&RFC_KEY, &RFC_MSG),
            [
                0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36,
                0x3c, 0xfe
            ]
        );
    }

    #[test]
    fn subkeys_match_rfc4493() {
        let ctx = Aes128Ctx::new(&RFC_KEY);
        let (k1, k2) = generate_subkeys(&ctx);
        assert_eq!(
            k1,
            [
                0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36,
                0xa8, 0xde
            ]
        );
        assert_eq!(
            k2,
            [
                0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d,
                0x51, 0x3b
            ]
        );
    }

    #[test]
    fn forge_hits_the_target_tag() {
        let target: Mac128 = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
        for len in [16usize, 32, 64, 4096] {
            let mut data = vec![0xAAu8; len];
            aes_cmac_forge(&RFC_KEY, &mut data, &target).unwrap();
            assert_eq!(aes_cmac(&RFC_KEY, &data), target, "len {len}");
        }
    }

    #[test]
    fn forge_only_touches_the_last_block() {
        let target: Mac128 = [0x5A; 16];
        let original = vec![0x33u8; 64];
        let mut data = original.clone();
        aes_cmac_forge(&RFC_KEY, &mut data, &target).unwrap();
        assert_eq!(data[..48], original[..48]);
        assert_ne!(data[48..], original[48..]);
    }

    #[test]
    fn forge_rejects_unusable_lengths() {
        let target: Mac128 = [0; 16];
        assert!(aes_cmac_forge(&RFC_KEY, &mut [], &target).is_err());
        assert!(aes_cmac_forge(&RFC_KEY, &mut [0u8; 24], &target).is_err());
    }
}
