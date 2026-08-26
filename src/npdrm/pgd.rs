//! PGD, the container an `OPNSSMP.BIN` module travels in.
//!
//! ```text
//! 0x00  u8[4]   magic         00 "PGD"
//! 0x04  u32     key_index     1
//! 0x08  u32     drm_type      1
//! 0x10  u8[16]  header_key    random; decrypts the block below
//! 0x30  ...     encrypted block, 0x30 bytes:
//!         0x30  u8[16]  data_key      random; decrypts the body
//!         0x44  u32     data_size
//!         0x48  u32     block_size
//!         0x4C  u32     data_offset   0x90
//!         0x60  u8[16]  table_mac     over the per-block MAC table
//! 0x70  u8[16]  header_mac    over 0x00..0x70, keyed by the content key
//! 0x80  u8[16]  dnas_mac      over 0x00..0x80, keyed by a published constant
//! 0x90  ...     the encrypted body, then one MAC per block
//! ```
//!
//! # What is verified against Sony, and what is not
//!
//! The `dnas_mac` is keyed by a *published constant*, so it can be checked
//! without knowing anything secret — and it does check out on all three Sony
//! containers that carry an OPNSSMP, under BB-MAC type 1. That confirms the
//! header layout, the mode derivation and the MAC together on real data.
//!
//! Everything else in a Sony PGD is keyed by the content key, and the three
//! containers that have one are all supplied-key titles whose key ships in a
//! `KEYS.BIN` tied to the buying account. So their bodies cannot be decrypted
//! here, and this module's decryption path is exercised against its own output
//! rather than against Sony's.
//!
//! # The reference throws its key away
//!
//! `sign_np` generates a random PGD key, encrypts with it, and never stores it
//! anywhere — it is a stack local that goes out of scope. Any OPNSSMP it
//! writes is therefore undecryptable by anything, including the console.
//!
//! This takes the key as a parameter instead, and [`crate::eg`] passes the
//! archive's version key. That is an inference rather than a measured fact:
//! Sony's choice is not observable without their content key, and the
//! reference's behaviour cannot be the model because it does not work. It is
//! recorded here so the next person knows it was a decision and not a reading.

use crate::crypto::aes::Key;
use crate::error::{Error, Result};
use crate::npdrm::bbcipher::bbcipher;
use crate::npdrm::bbmac::{BbMacType, bbmac};
use crate::npdrm::random::Entropy;

/// Bytes of header before the body.
pub const DATA_OFFSET: usize = 0x90;

/// The block size Sony's containers use.
pub const DEFAULT_BLOCK_SIZE: usize = 2048;

const MAGIC: [u8; 4] = [0x00, b'P', b'G', b'D'];

/// One of the two published DNAS constants. `open_flag & 2` selects this one,
/// which is what `drm_type = 1` with `key_index = 1` produces.
const DNAS_KEY_1A90: Key = [
    0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43,
];

/// The other, selected by `open_flag & 1`.
const DNAS_KEY_1AA0: Key = [
    0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83,
];

/// How a PGD's `key_index` and `drm_type` decide the modes it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Modes {
    mac: BbMacType,
    dnas_key: Key,
}

impl Modes {
    /// `flag` is the caller's open flag; the container's own fields extend it.
    fn resolve(key_index: u32, drm_type: u32, flag: u32) -> Result<Self> {
        if drm_type != 1 {
            // drm_type 2 uses BB-MAC and BB-Cipher type 2, which derive through
            // a key held in the console's fuses and cannot be computed here.
            return Err(Error::Crypto(format!(
                "PGD drm_type {drm_type} needs the console's per-unit key and \
                 cannot be built or read off-console"
            )));
        }
        if key_index > 1 {
            return Err(Error::Crypto(format!(
                "PGD key_index {key_index} selects a variant not seen in any \
                 container examined; refusing rather than guessing"
            )));
        }

        let flag = flag | 4;
        let dnas_key = if flag & 1 == 1 {
            DNAS_KEY_1AA0
        } else if flag & 2 == 2 {
            DNAS_KEY_1A90
        } else {
            return Err(Error::Crypto(format!(
                "PGD open flag {flag:#x} selects neither DNAS key"
            )));
        };

        Ok(Modes {
            mac: BbMacType::Type1,
            dnas_key,
        })
    }
}

/// The open flag Sony's containers are built with.
pub const DEFAULT_FLAG: u32 = 2;

/// Wrap and encrypt `data` as a PGD.
pub fn encrypt<E: Entropy>(
    data: &[u8],
    key: &Key,
    block_size: usize,
    entropy: &mut E,
) -> Result<Vec<u8>> {
    if block_size == 0 || !block_size.is_multiple_of(16) {
        return Err(Error::Crypto(format!(
            "PGD block size {block_size} must be a non-zero multiple of 16"
        )));
    }
    let modes = Modes::resolve(1, 1, DEFAULT_FLAG)?;

    let aligned = data.len().next_multiple_of(16);
    let blocks = aligned.div_ceil(block_size);
    let table_offset = DATA_OFFSET + aligned;
    let mut pgd = vec![0u8; table_offset + blocks * 16];

    pgd[..4].copy_from_slice(&MAGIC);
    pgd[4..8].copy_from_slice(&1u32.to_le_bytes()); // key_index
    pgd[8..12].copy_from_slice(&1u32.to_le_bytes()); // drm_type
    pgd[DATA_OFFSET..DATA_OFFSET + data.len()].copy_from_slice(data);

    // The two random keys sit at 0x10 and 0x30 and are drawn together.
    entropy.fill(&mut pgd[0x10..0x40])?;

    pgd[0x44..0x48].copy_from_slice(&(data.len() as u32).to_le_bytes());
    pgd[0x48..0x4C].copy_from_slice(&(block_size as u32).to_le_bytes());
    pgd[0x4C..0x50].copy_from_slice(&(DATA_OFFSET as u32).to_le_bytes());

    // Body first, keyed by the data key, then a MAC per block over the result.
    let data_key: Key = pgd[0x30..0x40].try_into().expect("16 bytes");
    bbcipher(&data_key, key, 0, &mut pgd[DATA_OFFSET..table_offset])?;

    for index in 0..blocks {
        let start = DATA_OFFSET + index * block_size;
        let len = block_size.min(table_offset - start);
        let mac = bbmac(modes.mac, &pgd[start..start + len], Some(key))?;
        pgd[table_offset + index * 16..][..16].copy_from_slice(&mac);
    }

    let table_mac = bbmac(modes.mac, &pgd[table_offset..], Some(key))?;
    pgd[0x60..0x70].copy_from_slice(&table_mac);

    // Now seal the header block, which carries the data key and the sizes.
    let header_key: Key = pgd[0x10..0x20].try_into().expect("16 bytes");
    bbcipher(&header_key, key, 0, &mut pgd[0x30..0x60])?;

    let header_mac = bbmac(modes.mac, &pgd[..0x70], Some(key))?;
    pgd[0x70..0x80].copy_from_slice(&header_mac);

    let dnas_mac = bbmac(modes.mac, &pgd[..0x80], Some(&modes.dnas_key))?;
    pgd[0x80..0x90].copy_from_slice(&dnas_mac);

    Ok(pgd)
}

/// Check a PGD's DNAS MAC, which needs no secret.
///
/// This is the only integrity check available on a container whose content key
/// is not to hand, and it still covers the whole header.
pub fn verify_dnas(pgd: &[u8]) -> Result<bool> {
    let header = header_fields(pgd)?;
    let modes = Modes::resolve(header.key_index, header.drm_type, DEFAULT_FLAG)?;
    let mac = bbmac(modes.mac, &pgd[..0x80], Some(&modes.dnas_key))?;
    Ok(mac[..] == pgd[0x80..0x90])
}

/// Decrypt a PGD, checking both MACs first.
pub fn decrypt(pgd: &[u8], key: &Key) -> Result<Vec<u8>> {
    let header = header_fields(pgd)?;
    let modes = Modes::resolve(header.key_index, header.drm_type, DEFAULT_FLAG)?;

    if !verify_dnas(pgd)? {
        return Err(Error::IntegrityCheck("PGD fails its DNAS MAC".into()));
    }
    let header_mac = bbmac(modes.mac, &pgd[..0x70], Some(key))?;
    if header_mac[..] != pgd[0x70..0x80] {
        return Err(Error::IntegrityCheck(
            "PGD fails its header MAC; the key is wrong or the header is damaged".into(),
        ));
    }

    // Unseal the header block to recover the data key and the sizes.
    let mut block = pgd[0x30..0x60].to_vec();
    let header_key: Key = pgd[0x10..0x20].try_into().expect("16 bytes");
    bbcipher(&header_key, key, 0, &mut block)?;

    let word = |o: usize| u32::from_le_bytes(block[o..o + 4].try_into().expect("4 bytes"));
    let data_size = word(0x14) as usize;
    let block_size = word(0x18) as usize;
    let data_offset = word(0x1C) as usize;
    let data_key: Key = block[..16].try_into().expect("16 bytes");

    if block_size == 0 || !block_size.is_multiple_of(16) || data_offset != DATA_OFFSET {
        return Err(Error::Crypto(format!(
            "PGD declares block size {block_size} at offset {data_offset:#x}, which is not usable"
        )));
    }
    let aligned = data_size.next_multiple_of(16);
    let table_offset = data_offset
        .checked_add(aligned)
        .ok_or_else(|| Error::Crypto("PGD sizes overflow".into()))?;
    if table_offset > pgd.len() {
        return Err(Error::TooShort {
            expected: table_offset,
            actual: pgd.len(),
        });
    }

    // Per-block MACs cover the ciphertext, so they check before decrypting.
    let blocks = aligned.div_ceil(block_size);
    for index in 0..blocks {
        let start = data_offset + index * block_size;
        let len = block_size.min(table_offset - start);
        let mac = bbmac(modes.mac, &pgd[start..start + len], Some(key))?;
        let stored = pgd
            .get(table_offset + index * 16..table_offset + index * 16 + 16)
            .ok_or_else(|| Error::Crypto(format!("PGD has no MAC for block {index}")))?;
        if mac[..] != *stored {
            return Err(Error::IntegrityCheck(format!(
                "PGD block {index} fails its MAC"
            )));
        }
    }

    let mut body = pgd[data_offset..table_offset].to_vec();
    bbcipher(&data_key, key, 0, &mut body)?;
    body.truncate(data_size);
    Ok(body)
}

struct HeaderFields {
    key_index: u32,
    drm_type: u32,
}

fn header_fields(pgd: &[u8]) -> Result<HeaderFields> {
    if pgd.len() < DATA_OFFSET {
        return Err(Error::TooShort {
            expected: DATA_OFFSET,
            actual: pgd.len(),
        });
    }
    if pgd[..4] != MAGIC {
        return Err(Error::Crypto("not a PGD container".into()));
    }
    Ok(HeaderFields {
        key_index: u32::from_le_bytes(pgd[4..8].try_into().expect("4 bytes")),
        drm_type: u32::from_le_bytes(pgd[8..12].try_into().expect("4 bytes")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::random::PredictableEntropy;

    const KEY: Key = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];

    fn module(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 + (i >> 8)) as u8).collect()
    }

    #[test]
    fn a_container_round_trips() {
        // Sizes either side of a block boundary and of the 16-byte alignment.
        for len in [1usize, 15, 16, 100, 2048, 2049, 5000] {
            let data = module(len);
            let pgd = encrypt(
                &data,
                &KEY,
                DEFAULT_BLOCK_SIZE,
                &mut PredictableEntropy::new(3),
            )
            .unwrap();

            assert_eq!(&pgd[..4], &[0x00, b'P', b'G', b'D']);
            assert!(verify_dnas(&pgd).unwrap(), "len {len}");
            assert_eq!(decrypt(&pgd, &KEY).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn the_body_is_not_left_in_the_clear() {
        let data = module(4096);
        let pgd = encrypt(
            &data,
            &KEY,
            DEFAULT_BLOCK_SIZE,
            &mut PredictableEntropy::new(3),
        )
        .unwrap();
        assert_ne!(&pgd[DATA_OFFSET..DATA_OFFSET + data.len()], &data[..]);
    }

    #[test]
    fn the_wrong_key_is_refused_rather_than_returning_rubbish() {
        let pgd = encrypt(
            &module(1000),
            &KEY,
            DEFAULT_BLOCK_SIZE,
            &mut PredictableEntropy::new(3),
        )
        .unwrap();
        let mut wrong = KEY;
        wrong[0] ^= 0x01;
        assert!(matches!(
            decrypt(&pgd, &wrong).unwrap_err(),
            Error::IntegrityCheck(_)
        ));
    }

    /// The DNAS MAC needs no secret, so tampering anywhere in the header is
    /// detectable by anyone holding the file.
    #[test]
    fn tampering_is_caught_without_the_content_key() {
        let pgd = encrypt(
            &module(1000),
            &KEY,
            DEFAULT_BLOCK_SIZE,
            &mut PredictableEntropy::new(3),
        )
        .unwrap();
        for offset in [0x04, 0x10, 0x30, 0x44, 0x60, 0x70, 0x7F] {
            let mut bad = pgd.clone();
            bad[offset] ^= 0x01;
            assert!(
                !verify_dnas(&bad).unwrap_or(false),
                "a flipped bit at {offset:#x} passed the DNAS MAC"
            );
        }
    }

    #[test]
    fn a_tampered_body_fails_its_block_mac() {
        let pgd = encrypt(
            &module(4096),
            &KEY,
            DEFAULT_BLOCK_SIZE,
            &mut PredictableEntropy::new(3),
        )
        .unwrap();
        let mut bad = pgd.clone();
        bad[DATA_OFFSET + 500] ^= 0x01;
        assert!(decrypt(&bad, &KEY).is_err());
    }

    /// The variants that route through the console's fuse key must be refused
    /// rather than silently producing something wrong.
    #[test]
    fn off_console_variants_are_refused() {
        assert!(Modes::resolve(1, 2, DEFAULT_FLAG).is_err(), "drm_type 2");
        assert!(Modes::resolve(2, 1, DEFAULT_FLAG).is_err(), "key_index 2");
        assert!(Modes::resolve(1, 1, 0).is_err(), "no DNAS key selected");
        assert!(Modes::resolve(1, 1, DEFAULT_FLAG).is_ok());
    }

    #[test]
    fn malformed_containers_are_errors_not_panics() {
        assert!(decrypt(&[], &KEY).is_err());
        assert!(decrypt(&[0u8; 0x90], &KEY).is_err());
        assert!(verify_dnas(&[0u8; 0x40]).is_err());
        assert!(
            encrypt(&module(10), &KEY, 0, &mut PredictableEntropy::new(1)).is_err(),
            "zero block size"
        );
    }
}
