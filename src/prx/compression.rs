//! Payload compression.
//!
//! The PSP accepts a gzip-compressed payload when the `~PSP` header's
//! compression attribute is set. Compression is a pipeline stage in its own
//! right: it runs *before* any size is committed to, so the KIRK container is
//! always sized from the post-compression payload.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::error::{Error, Result};

/// Compress with gzip at maximum level, matching the reference implementation's
/// `deflateInit2(..., 9, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY)`.
pub fn gzip_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .map_err(|e| Error::Compression(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| Error::Compression(e.to_string()))
}

/// Decompress a gzip payload.
///
/// Bytes after the end of the gzip member are ignored. This matters for
/// compatibility: the reference implementation pads the payload out to its
/// template's capacity, so a genuine file routinely carries trailing garbage
/// after the compressed stream.
pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::Compression(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for data in [
            vec![],
            vec![0u8; 1],
            vec![0x41u8; 100_000],
            (0..50_000u32).map(|i| (i % 251) as u8).collect(),
        ] {
            assert_eq!(
                gzip_decompress(&gzip_compress(&data).unwrap()).unwrap(),
                data
            );
        }
    }

    #[test]
    fn compressible_data_shrinks() {
        let data = vec![0xAAu8; 100_000];
        assert!(gzip_compress(&data).unwrap().len() < data.len() / 10);
    }

    #[test]
    fn output_has_a_gzip_header() {
        let out = gzip_compress(b"hello").unwrap();
        assert_eq!(&out[..2], &[0x1F, 0x8B], "gzip magic");
    }

    #[test]
    fn is_deterministic() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 97) as u8).collect();
        assert_eq!(gzip_compress(&data).unwrap(), gzip_compress(&data).unwrap());
    }

    #[test]
    fn rejects_garbage_on_decompress() {
        assert!(gzip_decompress(b"definitely not gzip data").is_err());
        assert!(gzip_decompress(&[]).is_err());
    }

    #[test]
    fn ignores_padding_after_the_gzip_member() {
        // The reference encrypter pads the payload to its template capacity,
        // leaving arbitrary bytes after the compressed stream.
        let data = b"payload contents".to_vec();
        let mut padded = gzip_compress(&data).unwrap();
        padded.extend_from_slice(&[0xCD; 512]);
        assert_eq!(gzip_decompress(&padded).unwrap(), data);

        let mut zero_padded = gzip_compress(&data).unwrap();
        zero_padded.extend_from_slice(&[0u8; 16]);
        assert_eq!(gzip_decompress(&zero_padded).unwrap(), data);
    }
}
