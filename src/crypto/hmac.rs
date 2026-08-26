//! HMAC-SHA1 (RFC 2104).
//!
//! Present for one caller: RFC 6979, which derives an ECDSA nonce
//! deterministically from the message and the private key. See
//! [`crate::npdrm::ecdsa::sign_deterministic`].
//!
//! This is not a PSP primitive. Nothing in any PSP format uses HMAC — it is
//! this crate's own machinery for producing signatures safely.

use crate::crypto::sha1::{Digest160, sha1_chunks};

/// SHA-1's input block size, which sets the width HMAC pads keys to.
const BLOCK_SIZE: usize = 64;

/// Compute HMAC-SHA1 of `data` under `key`.
pub fn hmac_sha1(key: &[u8], data: &[&[u8]]) -> Digest160 {
    // A key longer than the block is replaced by its own hash; a shorter one
    // is zero-padded.
    let mut padded = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        padded[..20].copy_from_slice(&sha1_chunks(&[key]));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5Cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }

    let mut inner_input: Vec<&[u8]> = Vec::with_capacity(data.len() + 1);
    inner_input.push(&ipad);
    inner_input.extend_from_slice(data);
    let inner = sha1_chunks(&inner_input);

    sha1_chunks(&[&opad, &inner])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
            .collect()
    }

    /// The RFC 2202 test vectors, which is the only way to be sure the padding
    /// and key handling are right rather than merely self-consistent.
    #[test]
    fn matches_the_rfc_2202_vectors() {
        let cases: &[(Vec<u8>, Vec<u8>, &str)] = &[
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            ),
            (
                unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                vec![0xcd; 50],
                "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            ),
            (
                vec![0x0c; 20],
                b"Test With Truncation".to_vec(),
                "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            ),
            (
                // A key longer than the block, which must be hashed first.
                vec![0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            ),
            (
                vec![0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One \
                  Block-Size Data"
                    .to_vec(),
                "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            ),
        ];

        for (i, (key, data, want)) in cases.iter().enumerate() {
            // The last vector's data is written with line-continuation
            // whitespace; normalise it back to the RFC's bytes.
            let data: Vec<u8> = if i == 6 {
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                    .to_vec()
            } else {
                data.clone()
            };
            assert_eq!(
                hmac_sha1(key, &[&data]).to_vec(),
                unhex(want),
                "RFC 2202 case {}",
                i + 1
            );
        }
    }

    /// Chunked input must hash the same as the concatenation, since RFC 6979
    /// feeds several pieces at once.
    #[test]
    fn chunking_the_message_changes_nothing() {
        let key = b"key";
        let whole = b"one two three";
        assert_eq!(
            hmac_sha1(key, &[whole]),
            hmac_sha1(key, &[b"one ", b"two ", b"three"])
        );
    }

    #[test]
    fn the_key_matters() {
        assert_ne!(hmac_sha1(b"a", &[b"msg"]), hmac_sha1(b"b", &[b"msg"]));
    }
}
