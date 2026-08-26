//! The randomness an archive genuinely needs.
//!
//! Two fields in an NPUMDIMG header are unpredictable in Sony's output, and
//! both come from the KIRK hardware PRNG there:
//!
//! - `header_key`, which is XORed with the version key to derive the key every
//!   block is encrypted under.
//! - `padding`, eight bytes covered by the header hash and the signature.
//!
//! # What is deliberately *not* here
//!
//! The ECDSA nonce. It is the one value where a weak generator is
//! catastrophic — two signatures sharing a nonce hand over the private key —
//! so it is derived deterministically from the key and the message instead,
//! by RFC 6979. See [`crate::npdrm::ecdsa::sign_deterministic`]. There is no
//! function in this module that could be misused for it.
//!
//! # Reproducibility
//!
//! Because `header_key` is random, two archives built from identical inputs
//! differ from byte 0x40 of the header onward, exactly as two `sign_np` runs
//! do. That is a property of the format, not a choice made here.
//! [`Entropy`] exists so tests can pin those bytes and compare the rest.

use crate::crypto::aes::Key;
use crate::error::{Error, Result};

/// Bytes of PRNG output the header carries at 0xD0.
pub const PADDING_SIZE: usize = 8;

/// Where an archive's unpredictable header fields come from.
///
/// Implemented by [`SystemEntropy`] for real builds and by a fixed source in
/// tests, so that everything except these two fields can be compared byte for
/// byte between runs.
pub trait Entropy {
    /// Fill `buf` with unpredictable bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;

    /// A fresh per-archive header key.
    fn header_key(&mut self) -> Result<Key> {
        let mut key = [0u8; 16];
        self.fill(&mut key)?;
        Ok(key)
    }

    /// The header's eight padding bytes.
    fn padding(&mut self) -> Result<[u8; PADDING_SIZE]> {
        let mut padding = [0u8; PADDING_SIZE];
        self.fill(&mut padding)?;
        Ok(padding)
    }
}

/// The operating system's cryptographic random number generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf)
            .map_err(|e| Error::Crypto(format!("the system random number generator failed: {e}")))
    }
}

/// A fixed, repeating byte source. **Test use only.**
///
/// Named to be conspicuous at a call site: an archive built with this has a
/// predictable header key, and on a supplied-key title that would weaken the
/// content encryption.
#[derive(Debug, Clone)]
pub struct PredictableEntropy {
    counter: u8,
}

impl PredictableEntropy {
    pub fn new(seed: u8) -> Self {
        PredictableEntropy { counter: seed }
    }
}

impl Entropy for PredictableEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        for byte in buf.iter_mut() {
            *byte = self.counter;
            self.counter = self.counter.wrapping_add(0x3B);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_source_produces_different_keys_each_time() {
        let mut entropy = SystemEntropy;
        let a = entropy.header_key().unwrap();
        let b = entropy.header_key().unwrap();
        assert_ne!(a, b, "two header keys came out identical");
        assert_ne!(a, [0u8; 16], "the header key is all zeros");
    }

    #[test]
    fn the_system_source_fills_the_whole_buffer() {
        // A generator that filled only part of the buffer would leave zeros,
        // which for a 16-byte key is the difference between random and not.
        let mut entropy = SystemEntropy;
        let mut all_zero_somewhere = [true; 32];
        for _ in 0..16 {
            let mut buf = [0u8; 32];
            entropy.fill(&mut buf).unwrap();
            for (i, b) in buf.iter().enumerate() {
                if *b != 0 {
                    all_zero_somewhere[i] = false;
                }
            }
        }
        assert!(
            !all_zero_somewhere.iter().any(|&z| z),
            "some byte position was never filled"
        );
    }

    #[test]
    fn padding_is_eight_bytes_and_varies() {
        let mut entropy = SystemEntropy;
        assert_ne!(entropy.padding().unwrap(), entropy.padding().unwrap());
    }

    #[test]
    fn the_predictable_source_repeats_for_a_given_seed() {
        let a = PredictableEntropy::new(7).header_key().unwrap();
        let b = PredictableEntropy::new(7).header_key().unwrap();
        let c = PredictableEntropy::new(8).header_key().unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
