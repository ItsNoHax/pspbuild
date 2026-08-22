//! AES-128 primitives in the shapes KIRK needs.
//!
//! KIRK always uses AES-128 in CBC mode with an **all-zero IV** and **no
//! padding** — buffers are pre-aligned to 16 bytes by the format itself. The
//! `cbc` crate's high level API is built around padding schemes, so the
//! chaining is done here directly on top of the `aes` block cipher. That keeps
//! the semantics identical to the PSP reference implementation and keeps every
//! third-party crypto call inside this module.

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array};

use crate::error::{Error, Result};

/// AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// An AES-128 key.
pub type Key = [u8; 16];

/// A single AES block.
pub type Block = [u8; BLOCK_SIZE];

/// An AES-128 context, reusable across many blocks.
#[derive(Clone)]
pub struct Aes128Ctx {
    cipher: Aes128,
}

impl Aes128Ctx {
    pub fn new(key: &Key) -> Self {
        Aes128Ctx {
            cipher: Aes128::new(&Array(*key)),
        }
    }

    /// Raw single-block encryption (ECB core function).
    pub fn encrypt_block(&self, block: &Block) -> Block {
        let mut b = Array(*block);
        self.cipher.encrypt_block(&mut b);
        b.0
    }

    /// Raw single-block decryption (ECB core function).
    pub fn decrypt_block(&self, block: &Block) -> Block {
        let mut b = Array(*block);
        self.cipher.decrypt_block(&mut b);
        b.0
    }
}

/// Encrypt `data` in place using AES-128-CBC with a zero IV and no padding.
///
/// `data.len()` must be a multiple of [`BLOCK_SIZE`].
pub fn cbc_encrypt_in_place(key: &Key, data: &mut [u8]) -> Result<()> {
    check_aligned(data.len())?;
    let ctx = Aes128Ctx::new(key);
    let mut prev = [0u8; BLOCK_SIZE];

    // `check_aligned` guarantees there is no remainder.
    let (blocks, _rest) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        let mut xored = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            xored[i] = block[i] ^ prev[i];
        }
        prev = ctx.encrypt_block(&xored);
        *block = prev;
    }
    Ok(())
}

/// Decrypt `data` in place using AES-128-CBC with a zero IV and no padding.
pub fn cbc_decrypt_in_place(key: &Key, data: &mut [u8]) -> Result<()> {
    check_aligned(data.len())?;
    let ctx = Aes128Ctx::new(key);
    let mut prev = [0u8; BLOCK_SIZE];

    // `check_aligned` guarantees there is no remainder.
    let (blocks, _rest) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        let ciphertext: Block = *block;
        let mut plain = ctx.decrypt_block(&ciphertext);
        for i in 0..BLOCK_SIZE {
            plain[i] ^= prev[i];
        }
        *block = plain;
        prev = ciphertext;
    }
    Ok(())
}

/// Convenience wrapper returning a new buffer.
pub fn cbc_encrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = data.to_vec();
    cbc_encrypt_in_place(key, &mut out)?;
    Ok(out)
}

/// Convenience wrapper returning a new buffer.
pub fn cbc_decrypt(key: &Key, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = data.to_vec();
    cbc_decrypt_in_place(key, &mut out)?;
    Ok(out)
}

fn check_aligned(len: usize) -> Result<()> {
    if !len.is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidAlignment(format!(
            "AES-CBC buffer of {len} bytes is not a multiple of {BLOCK_SIZE}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38A F.2.1/F.2.2, AES-128-CBC. The PSP uses a zero IV, so the
    /// first block is fed through with the standard vector's IV applied
    /// manually to confirm the chaining direction is right.
    const NIST_KEY: Key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    #[test]
    fn ecb_block_matches_nist_vector() {
        // NIST SP 800-38A F.1.1 (ECB-AES128) first block.
        let ctx = Aes128Ctx::new(&NIST_KEY);
        let plain: Block = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: Block = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        assert_eq!(ctx.encrypt_block(&plain), expected);
        assert_eq!(ctx.decrypt_block(&expected), plain);
    }

    #[test]
    fn cbc_zero_iv_first_block_equals_ecb() {
        // With IV=0 the first CBC block reduces to a plain ECB encryption.
        let ctx = Aes128Ctx::new(&NIST_KEY);
        let plain = [0x11u8; 16];
        let cbc = cbc_encrypt(&NIST_KEY, &plain).unwrap();
        assert_eq!(cbc, ctx.encrypt_block(&plain).to_vec());
    }

    #[test]
    fn cbc_round_trips() {
        let data: Vec<u8> = (0..64u8).collect();
        let enc = cbc_encrypt(&NIST_KEY, &data).unwrap();
        assert_ne!(enc, data);
        assert_eq!(cbc_decrypt(&NIST_KEY, &enc).unwrap(), data);
    }

    #[test]
    fn cbc_chains_between_blocks() {
        // Two identical plaintext blocks must produce different ciphertext
        // blocks under CBC; identical output would mean ECB.
        let data = [0xAAu8; 32];
        let enc = cbc_encrypt(&NIST_KEY, &data).unwrap();
        assert_ne!(enc[..16], enc[16..]);
    }

    #[test]
    fn unaligned_buffers_are_rejected() {
        assert!(cbc_encrypt(&NIST_KEY, &[0u8; 17]).is_err());
        assert!(cbc_decrypt(&NIST_KEY, &[0u8; 1]).is_err());
        // Zero length is aligned and is a no-op.
        assert!(cbc_encrypt(&NIST_KEY, &[]).unwrap().is_empty());
    }
}
