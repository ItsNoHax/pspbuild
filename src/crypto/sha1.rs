//! SHA-1, used by the PSP header integrity check.

use sha1::{Digest, Sha1};

/// A SHA-1 digest.
pub type Digest160 = [u8; 20];

/// Compute SHA-1 over a sequence of chunks, as if they were concatenated.
///
/// The PSP header hash is computed over several non-contiguous regions, so a
/// streaming interface avoids building a temporary joined buffer.
pub fn sha1_chunks(chunks: &[&[u8]]) -> Digest160 {
    let mut hasher = Sha1::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// Compute SHA-1 over a single buffer.
pub fn sha1(data: &[u8]) -> Digest160 {
    sha1_chunks(&[data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // FIPS 180-1 / RFC 3174 sample vectors.
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn chunking_matches_concatenation() {
        let joined = sha1(b"hello world");
        assert_eq!(sha1_chunks(&[b"hello ", b"world"]), joined);
        assert_eq!(sha1_chunks(&[b"h", b"ello", b" ", b"world"]), joined);
        assert_eq!(sha1_chunks(&[b"", b"hello world", b""]), joined);
    }
}
