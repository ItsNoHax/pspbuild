//! BB-Cipher, the stream cipher NPDRM uses for content.
//!
//! # What it actually is
//!
//! A counter-mode keystream generator, XORed into the data. The firmware API
//! (`sceDrmBBCipherInit`/`Update`/`Final`) presents it as a block cipher with
//! internal chunking, but the transformation is its own inverse: encryption
//! and decryption are the same call.
//!
//! ```text
//! S = AES-ECB-dec(K39, header_key ^ version_key ^ AMCTRL_KEY3) ^ AMCTRL_KEY2
//!
//! B[j]  = S[0..12] || LE32(seed + 1 + j)          the counter blocks
//! B[-1] = 0                        when seed == 0
//!       = S[0..12] || LE32(seed)   otherwise      the chain's initial value
//!
//! keystream[j] = AES-ECB-dec(K63, B[j]) ^ B[j-1]
//! ```
//!
//! The keystream is a CBC *decryption* of the counter blocks, which is why the
//! previous counter block feeds forward. Only the low four bytes of each
//! counter block vary, so `S` is derived once per stream.
//!
//! # The seed is a position, not a nonce
//!
//! NPUMDIMG passes each block's byte offset divided by 16, so the counter is
//! effectively an absolute 16-byte index into the archive. Every block is
//! keyed to where it sits, and blocks cannot be reordered or relocated without
//! re-encrypting them.
//!
//! # Scope
//!
//! Only type 1 / mode 2 is implemented — the one combination NPUMDIMG uses.
//!
//! - **Type 2** derives through KIRK command 5, which uses a key derived from
//!   the console's fuse ID. It cannot be computed off-console.
//! - **Mode 1** *generates* a `header_key` rather than accepting one. NPUMDIMG
//!   takes its header key straight from the KIRK PRNG instead, so mode 1 is
//!   never reached.

use crate::crypto::aes::{Aes128Ctx, BLOCK_SIZE, Key};
use crate::error::{Error, Result};
use crate::kirk::keys::kirk7_key;
use crate::npdrm::keys::{AMCTRL_KEY2, AMCTRL_KEY3};

/// The KIRK slot that derives the per-stream value `S`.
const DERIVE_SLOT: u8 = 0x39;

/// The KIRK slot that generates the keystream.
const STREAM_SLOT: u8 = 0x63;

/// A BB-Cipher keystream, positioned at a given 16-byte offset.
pub struct BbCipher {
    /// The per-stream derived value; only its first 12 bytes are used.
    derived: Key,
    /// The next counter value.
    counter: u32,
    /// The previous counter block, which the current one chains from.
    chain: [u8; BLOCK_SIZE],
    stream: Aes128Ctx,
}

impl BbCipher {
    /// Start a keystream for data beginning at `seed` 16-byte units into the
    /// archive.
    pub fn new(header_key: &Key, version_key: &Key, seed: u32) -> Result<Self> {
        let mut input = *header_key;
        for (i, b) in input.iter_mut().enumerate() {
            *b ^= version_key[i] ^ AMCTRL_KEY3[i];
        }

        let mut derived = Aes128Ctx::new(kirk7_key(DERIVE_SLOT)?).decrypt_block(&input);
        for (d, k) in derived.iter_mut().zip(AMCTRL_KEY2.iter()) {
            *d ^= k;
        }

        let counter = seed.wrapping_add(1);
        // The chain starts from the counter block that *would* have preceded
        // this one — except at counter 1, where the firmware starts from zero
        // rather than from the block for counter 0.
        let chain = if counter == 1 {
            [0u8; BLOCK_SIZE]
        } else {
            counter_block(&derived, seed)
        };

        Ok(BbCipher {
            derived,
            counter,
            chain,
            stream: Aes128Ctx::new(kirk7_key(STREAM_SLOT)?),
        })
    }

    /// Encrypt or decrypt `data` in place — the operation is the same either
    /// way — advancing the stream position.
    ///
    /// `data.len()` must be a multiple of 16. The counter advances per block,
    /// so a partial block would desynchronise every subsequent call rather
    /// than fail visibly; refusing it keeps that from happening silently.
    pub fn apply(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidAlignment(format!(
                "BB-Cipher needs a whole number of {BLOCK_SIZE}-byte blocks, got {}",
                data.len()
            )));
        }

        for chunk in data.chunks_mut(BLOCK_SIZE) {
            let block = counter_block(&self.derived, self.counter);
            let mut keystream = self.stream.decrypt_block(&block);
            for (k, c) in keystream.iter_mut().zip(self.chain.iter()) {
                *k ^= c;
            }
            for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
                *d ^= k;
            }
            self.chain = block;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

/// `derived[0..12] || LE32(counter)`.
fn counter_block(derived: &Key, counter: u32) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block[..12].copy_from_slice(&derived[..12]);
    block[12..].copy_from_slice(&counter.to_le_bytes());
    block
}

/// Encrypt or decrypt a buffer in one call.
pub fn bbcipher(header_key: &Key, version_key: &Key, seed: u32, data: &mut [u8]) -> Result<()> {
    BbCipher::new(header_key, version_key, seed)?.apply(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::test_vectors::{HEADER_KEY, VERSION_KEY, filler, unhex};

    /// Known answers from the reference implementation: `(seed, length, first
    /// 48 bytes of output, last 16 bytes of output)`.
    ///
    /// The seeds cover the special case at 0, its neighbours, and values large
    /// enough to exercise the counter's upper bytes. The lengths straddle the
    /// 0x800 chunk the reference processes in.
    #[rustfmt::skip]
    const CIPHER_VECTORS: &[(u32, usize, &str, &str)] = &[
        (0, 16, "d56bc53995a7249903bd8cbf3e0c2aee", "d56bc53995a7249903bd8cbf3e0c2aee"),
        (0, 32, "d56bc53995a7249903bd8cbf3e0c2aee770bdb4fa4cf4b35c1ef838f1ba31940", "770bdb4fa4cf4b35c1ef838f1ba31940"),
        (0, 48, "d56bc53995a7249903bd8cbf3e0c2aee770bdb4fa4cf4b35c1ef838f1ba319402e7f2e802a5390ebaef5dd37f68e43bf", "2e7f2e802a5390ebaef5dd37f68e43bf"),
        (0, 192, "d56bc53995a7249903bd8cbf3e0c2aee770bdb4fa4cf4b35c1ef838f1ba319402e7f2e802a5390ebaef5dd37f68e43bf", "2ab4fab749afb1d27b5ffd9601cac2f0"),
        (0, 2048, "d56bc53995a7249903bd8cbf3e0c2aee770bdb4fa4cf4b35c1ef838f1ba319402e7f2e802a5390ebaef5dd37f68e43bf", "eaac795069b6410817cab5b44c041a4b"),
        (0, 4096, "d56bc53995a7249903bd8cbf3e0c2aee770bdb4fa4cf4b35c1ef838f1ba319402e7f2e802a5390ebaef5dd37f68e43bf", "26835ceb4526759100c6eaaefffaaebf"),
        (1, 16, "e7fb2bdf347ffb85517ff3ff8b33a9f0", "e7fb2bdf347ffb85517ff3ff8b33a9f0"),
        (131071, 32, "3aeece78bb786c9ddc715fec237ef65bd1e033608f39d688d81ecaa327ea766d", "d1e033608f39d688d81ecaa327ea766d"),
        (131071, 48, "3aeece78bb786c9ddc715fec237ef65bd1e033608f39d688d81ecaa327ea766d3ce8f5fe5a4d1b560f13bbc65f54fea4", "3ce8f5fe5a4d1b560f13bbc65f54fea4"),
        (131071, 192, "3aeece78bb786c9ddc715fec237ef65bd1e033608f39d688d81ecaa327ea766d3ce8f5fe5a4d1b560f13bbc65f54fea4", "9813a31f3eb4fd5b0061807829977d7b"),
        (131071, 2048, "3aeece78bb786c9ddc715fec237ef65bd1e033608f39d688d81ecaa327ea766d3ce8f5fe5a4d1b560f13bbc65f54fea4", "12dcbf6986b3593be43a44dd6e38e10f"),
        (131071, 4096, "3aeece78bb786c9ddc715fec237ef65bd1e033608f39d688d81ecaa327ea766d3ce8f5fe5a4d1b560f13bbc65f54fea4", "1dc46525172d107130a5c172f2af457a"),
    ];

    #[test]
    fn output_matches_the_reference() {
        for &(seed, len, head, tail) in CIPHER_VECTORS {
            let mut data = filler(len, 2);
            bbcipher(&HEADER_KEY, &VERSION_KEY, seed, &mut data).unwrap();

            let want_head = unhex(head);
            assert_eq!(
                &data[..want_head.len()],
                &want_head[..],
                "seed {seed}, {len} bytes"
            );
            assert_eq!(
                &data[len - 16..],
                &unhex(tail)[..],
                "seed {seed}, {len} bytes tail"
            );
        }
    }

    #[test]
    fn applying_it_twice_returns_the_original() {
        for seed in [0u32, 1, 2, 0x1000, u32::MAX - 4] {
            let original = filler(1024, 5);
            let mut data = original.clone();
            bbcipher(&HEADER_KEY, &VERSION_KEY, seed, &mut data).unwrap();
            assert_ne!(data, original, "seed {seed} left the data untouched");
            bbcipher(&HEADER_KEY, &VERSION_KEY, seed, &mut data).unwrap();
            assert_eq!(data, original, "seed {seed} did not round-trip");
        }
    }

    /// The reference splits its input into 0x800-byte chunks internally and
    /// recomputes the chain value at each boundary. That reconstruction has to
    /// land on exactly the previous counter block, or the streams diverge —
    /// so a split has to produce the same bytes as a single call.
    #[test]
    fn splitting_the_data_does_not_change_the_output() {
        let original = filler(4096, 2);

        let mut whole = original.clone();
        bbcipher(&HEADER_KEY, &VERSION_KEY, 0, &mut whole).unwrap();

        let mut split = original.clone();
        let mut cipher = BbCipher::new(&HEADER_KEY, &VERSION_KEY, 0).unwrap();
        let (first, rest) = split.split_at_mut(0x400);
        cipher.apply(first).unwrap();
        cipher.apply(rest).unwrap();

        assert_eq!(split, whole);
    }

    /// Two blocks at different positions must not share a keystream, which is
    /// the whole point of seeding from the offset.
    #[test]
    fn the_seed_positions_the_keystream() {
        let mut at_zero = vec![0u8; 32];
        bbcipher(&HEADER_KEY, &VERSION_KEY, 0, &mut at_zero).unwrap();

        // The keystream for the second block at seed 0 is the first block at
        // seed 1 -- except that seed 0 starts its chain from zero rather than
        // from a counter block, so only the later blocks can line up.
        let mut at_one = vec![0u8; 32];
        bbcipher(&HEADER_KEY, &VERSION_KEY, 1, &mut at_one).unwrap();
        assert_ne!(at_zero[..16], at_one[..16]);
        assert_eq!(at_zero[16..], at_one[..16]);
    }

    #[test]
    fn a_partial_block_is_refused() {
        let mut data = vec![0u8; 24];
        assert!(matches!(
            bbcipher(&HEADER_KEY, &VERSION_KEY, 0, &mut data).unwrap_err(),
            Error::InvalidAlignment(_)
        ));
    }

    #[test]
    fn either_key_changes_the_stream() {
        let base = filler(64, 7);
        let mut a = base.clone();
        bbcipher(&HEADER_KEY, &VERSION_KEY, 0, &mut a).unwrap();

        let mut flipped_header = HEADER_KEY;
        flipped_header[0] ^= 0x01;
        let mut b = base.clone();
        bbcipher(&flipped_header, &VERSION_KEY, 0, &mut b).unwrap();
        assert_ne!(a, b);

        let mut flipped_version = VERSION_KEY;
        flipped_version[15] ^= 0x80;
        let mut c = base.clone();
        bbcipher(&HEADER_KEY, &flipped_version, 0, &mut c).unwrap();
        assert_ne!(a, c);
    }
}
