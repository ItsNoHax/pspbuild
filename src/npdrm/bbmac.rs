//! BB-MAC, the authentication primitive used throughout NPDRM.
//!
//! # What it actually is
//!
//! Despite the bespoke firmware API — `sceDrmBBMacInit`/`Update`/`Final`, with
//! its own chunked buffering and hand-written subkey shifts — the core of
//! BB-MAC is ordinary **AES-CMAC (RFC 4493)** under a KIRK key-vault slot.
//! That is worth stating plainly because the reference implementation gives no
//! hint of it: the CBC chaining is spread across a streaming buffer, and the
//! `<< 1` with the 0x87 reduction is open-coded rather than named.
//!
//! Once the CMAC is out, three cheap steps finish the tag:
//!
//! ```text
//! tag = CMAC(K38, message)
//! tag ^= AMCTRL_KEY1
//! tag ^= version_key            (only when a version key is supplied)
//! tag  = AES-ECB(K38, tag)      (only when a version key is supplied)
//! tag  = AES-ECB(K63, tag)      (type 3 only)
//! ```
//!
//! so the whole primitive collapses to a CMAC and at most two block
//! encryptions. This was verified against the reference implementation for
//! every message length in [`tests`], not inferred from reading it.
//!
//! # Types
//!
//! The firmware defines types 1, 2 and 3. Types 1 and 3 differ only in the
//! trailing `K63` encryption, which the reference exposes as a separate
//! `bbmac_build_final2` call; here it is folded into [`BbMac::finish`], since
//! every NPUMDIMG call site invokes the two back to back.
//!
//! **Type 2 is deliberately absent.** Its finalisation routes through KIRK
//! command 5, which encrypts under a key derived from the console's fuse ID.
//! That key does not exist off-console, so a type 2 implementation here could
//! only produce a wrong answer convincingly. NPUMDIMG does not use it.

use crate::crypto::aes::{Aes128Ctx, Key};
use crate::error::Result;
use crate::kirk::keys::kirk7_key;
use crate::npdrm::keys::AMCTRL_KEY1;

use aes::Aes128;
use cmac::{Cmac, KeyInit, Mac};

/// The KIRK slot backing BB-MAC's block cipher for types 1 and 3.
const MAC_SLOT: u8 = 0x38;

/// The KIRK slot applied to a type 3 tag as a final whitening step.
const FINAL2_SLOT: u8 = 0x63;

/// Which BB-MAC variant to compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbMacType {
    /// Used by `sceNpDrmGetFixedKey`.
    Type1,
    /// Used by every NPUMDIMG MAC: header hash, block MACs and the data key.
    Type3,
}

/// A streaming BB-MAC.
///
/// Streaming matters here: the block MACs run over 32 KiB of ciphertext each
/// and the data key runs over a block table that can reach a megabyte, so
/// neither should require the message to be contiguous in memory.
pub struct BbMac {
    kind: BbMacType,
    cmac: Cmac<Aes128>,
}

impl BbMac {
    /// Start a BB-MAC of the given type.
    pub fn new(kind: BbMacType) -> Result<Self> {
        let key = kirk7_key(MAC_SLOT)?;
        Ok(BbMac {
            kind,
            cmac: <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("AES-128 key is 16 bytes"),
        })
    }

    /// Absorb more of the message. May be called any number of times, with
    /// chunks of any size.
    pub fn update(&mut self, data: &[u8]) {
        self.cmac.update(data);
    }

    /// Finish the MAC.
    ///
    /// `version_key` is the NPDRM per-content key. Passing `None` produces the
    /// intermediate form the reference implementation calls a MAC with a null
    /// `vkey`, which `sceNpDrmGetFixedKey` uses as a derivation step rather
    /// than as an authentication tag.
    pub fn finish(self, version_key: Option<&Key>) -> Result<Key> {
        let kind = self.kind;
        let mut tag: Key = self.cmac.finalize().into_bytes().into();

        xor_into(&mut tag, &AMCTRL_KEY1);

        if let Some(vkey) = version_key {
            xor_into(&mut tag, vkey);
            tag = Aes128Ctx::new(kirk7_key(MAC_SLOT)?).encrypt_block(&tag);
        }

        if kind == BbMacType::Type3 {
            tag = Aes128Ctx::new(kirk7_key(FINAL2_SLOT)?).encrypt_block(&tag);
        }

        Ok(tag)
    }
}

/// Compute a BB-MAC over a contiguous message.
pub fn bbmac(kind: BbMacType, data: &[u8], version_key: Option<&Key>) -> Result<Key> {
    let mut mac = BbMac::new(kind)?;
    mac.update(data);
    mac.finish(version_key)
}

fn xor_into(dst: &mut Key, src: &Key) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::test_vectors::{VERSION_KEY, filler, unhex};

    /// Known answers captured from the reference implementation. Each row is
    /// `(message length, version key used, type 1 tag, type 3 tag)`.
    ///
    /// The lengths are chosen around every boundary the reference's buffering
    /// has: empty, sub-block, exactly one block, one past a block, and either
    /// side of the 0x800 chunk size it processes the message in.
    #[rustfmt::skip]
    const MAC_VECTORS: &[(usize, bool, &str, &str)] = &[
        (0, false, "da1f8f35a51bc2533c4311dcf1d34f05", "cc2091b18679f0af1f6c8d7558ea217c"),
        (0, true, "da5f7aabab2a2a66e4edd7781da165fa", "893fc8cdf37566a2294471319ea836cd"),
        (1, false, "dd819ee96ec98147a9930b8c2de072ed", "b25a2b259d2020d4f92b4d603f05c0c7"),
        (1, true, "d51dd740199bed59780944f591d3e3a6", "1852550109c7a8f06e3e7247c65bd905"),
        (15, false, "b2a9f41a8a75927d31d59cee671d5708", "954ca3f69ccec29f6d1a8744d5b10d4f"),
        (15, true, "261a6742a8e86e3febc64b7943719632", "319c19e749dea32057106a0c62ed2683"),
        (16, false, "7f417e59eda0c594a277021fe3702a2c", "61a65c456d58cd932db9ab7af1e7f80b"),
        (16, true, "a53bb7d76238fc44420c99f4a0f27fbf", "00210c2f73b0a6f009959d87d9324c91"),
        (17, false, "00eb1cacc8fcd4262e12e23cafb342a5", "f3837d8484b19a95ba1cfd0bdb5b4e1e"),
        (17, true, "5a69a06f8661d0f6e2371c6c4ef07123", "5fa66376f4d88ec350f8073ad8282ff7"),
        (32, false, "1fe75ca65ddf9f84013a1dab82875be0", "314724bf149ab133c61cc3954c46dcc2"),
        (32, true, "c8308f1501552908f83ded1ba99f1056", "0c01285a0fc7cb14d5ada60776cdf13d"),
        (48, false, "dc8ed30399a8e7b3e3966c328c97be6c", "029191db4f1fae4934163414f35eba01"),
        (48, true, "139bc14785e77a258f66c683500e0519", "3927c5b3f551269ad2c9e73098a04cb1"),
        (192, false, "097da3cb5ea8f2902c9a6ef2d673a408", "b8082515fee652ddc8fbdb37ae1b8ee9"),
        (192, true, "5d3817e78491abaedd8940acd3ae8368", "059bc577354575017208b068cdfb7bdc"),
        (2047, false, "cc876f5506d27e8bba9590baf1c1dc42", "ac4c04fb41d3340c1485546bc69949af"),
        (2047, true, "127e54d5f4599097c97d898be389f31a", "2390e5497311a232a83449994409ffac"),
        (2048, false, "0cb967bdd15ff77d9910ef55985e8d62", "10531cc74902cf4b39b15a9ff4c54451"),
        (2048, true, "2961e1585914e76f7594d0b487a116f1", "96a20d30c1e58ad3fb77b779791e7a74"),
        (2049, false, "ab26baaea1279261bc65f75e79d25c84", "ec4d91edbc705523b22cd9e8f82e032c"),
        (2049, true, "da23fbc82569a63dd9bf5b57c15c4b33", "8ef3c5071b2eec866a58e9ac9e347fc7"),
        (4096, false, "372e974ca6a3ef6013c0e8368b987d94", "08d9366421a99b1048baec4e9f92ecd4"),
        (4096, true, "ddd74e31e78fd7523c78f8a8b49cce7c", "fd5c55638f985da18d6c84b057849cbb"),
        (4660, false, "18aca0fc767d0a1b562f9a1ba6fc5441", "deaf7e9f84fb272553ba492ea39997ab"),
        (4660, true, "9562875b88e51c0cef304270540ccb51", "8aac094106875b1ead5ce2a3e14507c5"),
    ];

    #[test]
    fn both_types_match_the_reference_at_every_length() {
        for &(len, with_key, want1, want3) in MAC_VECTORS {
            let msg = filler(len, 1);
            let vkey = with_key.then_some(&VERSION_KEY);

            assert_eq!(
                bbmac(BbMacType::Type1, &msg, vkey).unwrap().to_vec(),
                unhex(want1),
                "type 1, {len} bytes, version key: {with_key}"
            );
            assert_eq!(
                bbmac(BbMacType::Type3, &msg, vkey).unwrap().to_vec(),
                unhex(want3),
                "type 3, {len} bytes, version key: {with_key}"
            );
        }
    }

    /// The reference buffers the message internally and only feeds whole
    /// 0x800-byte chunks to the cipher, holding 1..16 bytes back. Splitting a
    /// message at awkward points is therefore the case most likely to expose a
    /// difference, so the reference was driven the same way to capture these.
    #[test]
    fn splitting_the_message_does_not_change_the_tag() {
        #[rustfmt::skip]
        const SPLIT_VECTORS: &[(&[usize], &str)] = &[
            (&[1, 1, 1], "7eed65489c86ee96b45c54c4bffa2465"),
            (&[15, 1], "0a234ed007f736dc17fc67810efda2cc"),
            (&[2047, 3, 2048], "f436178fe68a4651a7425b609630349e"),
            (&[5, 2048, 7], "53f7a8d35eea8a0aad6a663afd8edfd0"),
        ];

        for &(chunks, want) in SPLIT_VECTORS {
            let mut mac = BbMac::new(BbMacType::Type3).unwrap();
            let mut whole = Vec::new();
            for (i, &len) in chunks.iter().enumerate() {
                let part = filler(len, i + 1);
                mac.update(&part);
                whole.extend_from_slice(&part);
            }
            let streamed = mac.finish(Some(&VERSION_KEY)).unwrap();
            assert_eq!(streamed.to_vec(), unhex(want), "chunks {chunks:?}");

            // And the same bytes fed in one go must agree, which is the
            // property the block-table pass actually relies on.
            let contiguous = bbmac(BbMacType::Type3, &whole, Some(&VERSION_KEY)).unwrap();
            assert_eq!(contiguous, streamed, "chunks {chunks:?}");
        }
    }

    /// The reference implementation silently discards buffered data in one
    /// specific state, and this test exists to record that we do not.
    ///
    /// `sceDrmBBMacUpdate` holds 1..=16 bytes back in a pad. When that pad is
    /// *exactly* full and the next update is 1..=16 bytes long, it computes
    /// how much to carry forward, finds nothing left to process, and skips the
    /// loop — leaving the 16 pad bytes it had just staged unprocessed and then
    /// overwriting them. Those 16 bytes never reach the MAC.
    ///
    /// The trigger was mapped exhaustively over pad 0..=16 against updates of
    /// 1..=20 bytes: a full pad followed by at most a block is the only case,
    /// and only the pad's own 16 bytes are lost, not the state before them.
    ///
    /// This does not affect any archive. Every NPUMDIMG MAC — header hash,
    /// per-block MAC, data key — is computed from a single update, so the
    /// reference never enters the state. It matters only because a
    /// transliteration would have inherited the fault, and because our tag
    /// legitimately differs from the reference's if anyone drives it this way.
    #[test]
    fn we_do_not_reproduce_the_references_dropped_block() {
        let first = filler(16, 1);
        let second = filler(16, 2);

        let mut mac = BbMac::new(BbMacType::Type3).unwrap();
        mac.update(&first);
        mac.update(&second);
        let ours = mac.finish(Some(&VERSION_KEY)).unwrap();

        // What the reference returns here: the tag of the second chunk alone.
        let reference = unhex("b493f2a98153f9d446762ef69cfc6454");
        assert_eq!(
            bbmac(BbMacType::Type3, &second, Some(&VERSION_KEY))
                .unwrap()
                .to_vec(),
            reference,
            "the reference's answer should be the second chunk's own tag"
        );
        assert_ne!(ours.to_vec(), reference, "we dropped the first chunk too");

        // Ours covers both chunks, as a MAC over both chunks should.
        let mut whole = first.clone();
        whole.extend_from_slice(&second);
        assert_eq!(
            ours,
            bbmac(BbMacType::Type3, &whole, Some(&VERSION_KEY)).unwrap()
        );
    }

    #[test]
    fn the_version_key_changes_the_tag() {
        let msg = filler(64, 1);
        let with = bbmac(BbMacType::Type3, &msg, Some(&VERSION_KEY)).unwrap();
        let without = bbmac(BbMacType::Type3, &msg, None).unwrap();
        assert_ne!(with, without);
    }

    #[test]
    fn a_single_flipped_bit_changes_the_tag() {
        let mut msg = filler(256, 1);
        let before = bbmac(BbMacType::Type3, &msg, Some(&VERSION_KEY)).unwrap();
        msg[128] ^= 0x01;
        assert_ne!(
            bbmac(BbMacType::Type3, &msg, Some(&VERSION_KEY)).unwrap(),
            before
        );
    }
}
