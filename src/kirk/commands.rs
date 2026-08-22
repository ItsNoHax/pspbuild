//! KIRK command implementations.
//!
//! These reproduce the behaviour of the PSP KIRK engine for the operations PRX
//! encryption needs. Command *formatting* lives here; the AES and CMAC
//! mathematics lives in [`crate::crypto`].

use crate::crypto::aes;
use crate::crypto::cmac::{Mac128, aes_cmac};
use crate::error::{Error, Result};
use crate::kirk::header::{CMAC_HEADER_LEN, CMAC_REGION_START, HEADER_SIZE, KirkCmd1Header};
use crate::kirk::keys::{KIRK1_KEY, kirk7_key};

/// KIRK command 7: AES-128-CBC **decrypt** with a zero IV under a key-vault
/// slot. Used to unwrap the tag-derived key stream in a PSP header.
pub fn kirk7_decrypt(data: &mut [u8], key_seed: u8) -> Result<()> {
    let key = kirk7_key(key_seed)?;
    aes::cbc_decrypt_in_place(key, data)
}

/// KIRK command 4: AES-128-CBC **encrypt** with a zero IV under a key-vault
/// slot. The exact inverse of [`kirk7_decrypt`], needed to *build* a header.
pub fn kirk4_encrypt(data: &mut [u8], key_seed: u8) -> Result<()> {
    let key = kirk7_key(key_seed)?;
    aes::cbc_encrypt_in_place(key, data)
}

/// Unwrap the per-module AES and CMAC keys sitting at the front of a KIRK CMD1
/// header. The wrapped form is `AES-CBC(KIRK1_KEY, aes_key || cmac_key)`.
pub fn unwrap_keys(wrapped: &[u8]) -> Result<([u8; 16], [u8; 16])> {
    if wrapped.len() < 32 {
        return Err(Error::TooShort {
            expected: 32,
            actual: wrapped.len(),
        });
    }
    let plain = aes::cbc_decrypt(&KIRK1_KEY, &wrapped[..32])?;
    let mut aes_key = [0u8; 16];
    let mut cmac_key = [0u8; 16];
    aes_key.copy_from_slice(&plain[..16]);
    cmac_key.copy_from_slice(&plain[16..32]);
    Ok((aes_key, cmac_key))
}

/// Wrap the per-module keys for storage in a KIRK CMD1 header.
pub fn wrap_keys(aes_key: &[u8; 16], cmac_key: &[u8; 16]) -> Result<[u8; 32]> {
    let mut plain = [0u8; 32];
    plain[..16].copy_from_slice(aes_key);
    plain[16..].copy_from_slice(cmac_key);
    aes::cbc_encrypt_in_place(&KIRK1_KEY, &mut plain)?;
    Ok(plain)
}

/// The two CMAC tags carried by a CMD1 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacPair {
    pub header: Mac128,
    pub data: Mac128,
}

/// Compute the CMAC over the header region, `container[0x60..0x90]`.
pub fn calculate_header_cmac(cmac_key: &[u8; 16], container: &[u8]) -> Result<Mac128> {
    let end = CMAC_REGION_START + CMAC_HEADER_LEN;
    let region = container
        .get(CMAC_REGION_START..end)
        .ok_or(Error::TooShort {
            expected: end,
            actual: container.len(),
        })?;
    Ok(aes_cmac(cmac_key, region))
}

/// Compute the CMAC over the header region plus the predata and the aligned
/// payload, i.e. `container[0x60 .. 0x90 + data_offset + align16(data_size)]`.
pub fn calculate_data_cmac(
    cmac_key: &[u8; 16],
    container: &[u8],
    header: &KirkCmd1Header,
) -> Result<Mac128> {
    let range = header.data_cmac_range();
    let region = container.get(range.clone()).ok_or(Error::TooShort {
        expected: range.end,
        actual: container.len(),
    })?;
    Ok(aes_cmac(cmac_key, region))
}

/// KIRK command 0: build an encrypted CMD1 container.
///
/// `container` arrives as
/// `plaintext header (0x90) || predata (data_offset) || payload`
/// with the header carrying **plaintext** keys, and leaves fully encrypted and
/// authenticated. The steps, in the order the hardware performs them:
///
/// 1. Validate the header and confirm the buffer is large enough.
/// 2. Read the per-module keys from the plaintext header.
/// 3. AES-CBC encrypt the payload in place (predata stays in the clear).
/// 4. Compute the header CMAC over `0x60..0x90`.
/// 5. Compute the data CMAC over `0x60..end of aligned payload`.
/// 6. Store both tags in the header.
/// 7. Wrap the per-module keys with KIRK1_KEY.
///
/// The payload region must already be padded to a 16-byte boundary.
pub fn cmd0_encrypt(container: &mut [u8]) -> Result<CmacPair> {
    // 1. Validate.
    let header = KirkCmd1Header::parse(container)?;
    header.validate()?;

    let total = header.container_size() as usize;
    if container.len() < total {
        return Err(Error::TooShort {
            expected: total,
            actual: container.len(),
        });
    }

    // 2. Keys are plaintext at this point.
    let aes_key = header.aes_key;
    let cmac_key = header.cmac_key;

    // 3. Encrypt the payload in place.
    let payload_start = HEADER_SIZE + header.data_offset as usize;
    let payload_end = payload_start + header.aligned_data_size() as usize;
    aes::cbc_encrypt_in_place(&aes_key, &mut container[payload_start..payload_end])?;

    // 4/5. Authenticate.
    let macs = CmacPair {
        header: calculate_header_cmac(&cmac_key, container)?,
        data: calculate_data_cmac(&cmac_key, container, &header)?,
    };

    // 6. Store the tags.
    container[0x20..0x30].copy_from_slice(&macs.header);
    container[0x30..0x40].copy_from_slice(&macs.data);

    // 7. Wrap the keys.
    let wrapped = wrap_keys(&aes_key, &cmac_key)?;
    container[..32].copy_from_slice(&wrapped);

    Ok(macs)
}

/// KIRK command 1: decrypt a CMD1 container, verifying both CMAC tags.
///
/// Returns the decrypted payload, truncated to `data_size`.
pub fn cmd1_decrypt(container: &[u8], verify: bool) -> Result<Vec<u8>> {
    let header = KirkCmd1Header::parse(container)?;
    header.validate()?;

    let (aes_key, cmac_key) = unwrap_keys(container)?;
    // Report sizes against the real buffer before trusting the header.
    let total = header.container_size() as usize;
    if container.len() < total {
        return Err(Error::TooShort {
            expected: total,
            actual: container.len(),
        });
    }

    if verify {
        let expected_header = calculate_header_cmac(&cmac_key, container)?;
        if expected_header != header.cmac_header_hash {
            return Err(Error::IntegrityCheck("KIRK header CMAC mismatch".into()));
        }
        let expected_data = calculate_data_cmac(&cmac_key, container, &header)?;
        if expected_data != header.cmac_data_hash {
            return Err(Error::IntegrityCheck("KIRK data CMAC mismatch".into()));
        }
    }

    let payload_start = HEADER_SIZE + header.data_offset as usize;
    let payload_end = payload_start + header.aligned_data_size() as usize;
    let mut payload = container[payload_start..payload_end].to_vec();
    aes::cbc_decrypt_in_place(&aes_key, &mut payload)?;
    payload.truncate(header.data_size as usize);
    // `header` holds plaintext keys; its Drop zeroes them.
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kirk::header::KirkCmd1Header;

    const DATA_OFFSET: u32 = 0x80;

    /// Build a plaintext container around `payload`.
    fn build(payload: &[u8]) -> (Vec<u8>, KirkCmd1Header) {
        let header = KirkCmd1Header::new([0x11; 16], [0x22; 16], payload.len() as u32, DATA_OFFSET);
        let mut buf = vec![0u8; header.container_size() as usize];
        buf[..HEADER_SIZE].copy_from_slice(&header.to_bytes());
        let start = HEADER_SIZE + DATA_OFFSET as usize;
        buf[start..start + payload.len()].copy_from_slice(payload);
        (buf, header)
    }

    #[test]
    fn key_wrapping_round_trips() {
        let aes_key = [0x01u8; 16];
        let cmac_key = [0x02u8; 16];
        let wrapped = wrap_keys(&aes_key, &cmac_key).unwrap();
        assert_ne!(&wrapped[..16], &aes_key);
        assert_eq!(unwrap_keys(&wrapped).unwrap(), (aes_key, cmac_key));
    }

    #[test]
    fn cmd0_then_cmd1_round_trips() {
        for len in [1usize, 15, 16, 17, 255, 4096, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let (mut container, _) = build(&payload);
            cmd0_encrypt(&mut container).unwrap();
            let out = cmd1_decrypt(&container, true).unwrap();
            assert_eq!(out, payload, "len {len}");
        }
    }

    #[test]
    fn cmd0_encrypts_the_payload_but_not_the_predata() {
        let payload = vec![0x5Au8; 64];
        let (mut container, _) = build(&payload);
        let predata_before = container[HEADER_SIZE..HEADER_SIZE + 0x80].to_vec();

        cmd0_encrypt(&mut container).unwrap();

        assert_eq!(
            &container[HEADER_SIZE..HEADER_SIZE + 0x80],
            &predata_before[..]
        );
        let start = HEADER_SIZE + 0x80;
        assert_ne!(&container[start..start + 64], &payload[..]);
    }

    #[test]
    fn cmd0_wraps_the_keys_in_place() {
        let (mut container, header) = build(&[0u8; 32]);
        cmd0_encrypt(&mut container).unwrap();
        assert_ne!(&container[..16], &header.aes_key[..]);
        assert_eq!(unwrap_keys(&container).unwrap().0, header.aes_key);
    }

    #[test]
    fn tampering_with_the_payload_fails_verification() {
        let (mut container, _) = build(&[0xAAu8; 128]);
        cmd0_encrypt(&mut container).unwrap();
        assert!(cmd1_decrypt(&container, true).is_ok());

        let last = container.len() - 1;
        container[last] ^= 0x01;
        let err = cmd1_decrypt(&container, true).unwrap_err();
        assert!(matches!(err, Error::IntegrityCheck(_)));
        // Without verification it still decrypts (to garbage), never panics.
        assert!(cmd1_decrypt(&container, false).is_ok());
    }

    #[test]
    fn tampering_with_the_header_fails_verification() {
        let (mut container, _) = build(&[0xAAu8; 128]);
        cmd0_encrypt(&mut container).unwrap();
        // Flip a byte inside the header CMAC region (0x60..0x90).
        container[0x88] ^= 0x01;
        assert!(cmd1_decrypt(&container, true).is_err());
    }

    #[test]
    fn cmac_regions_have_the_documented_extent() {
        let payload = vec![0u8; 0x100];
        let (container, header) = build(&payload);
        assert_eq!(header.data_cmac_range(), 0x60..container.len());
        assert_eq!(container.len(), 0x90 + 0x80 + 0x100);
    }

    #[test]
    fn malformed_containers_error_cleanly() {
        // Truncated buffer.
        assert!(cmd0_encrypt(&mut [0u8; 16]).is_err());
        // Valid header claiming far more data than the buffer holds.
        let header = KirkCmd1Header::new([0; 16], [0; 16], 0x00FF_FFFF, DATA_OFFSET);
        let mut buf = vec![0u8; HEADER_SIZE + 0x80 + 16];
        buf[..HEADER_SIZE].copy_from_slice(&header.to_bytes());
        assert!(matches!(
            cmd0_encrypt(&mut buf).unwrap_err(),
            Error::TooShort { .. }
        ));
        assert!(cmd1_decrypt(&buf, true).is_err());
    }
}
