//! Checks for the XMB's PNG sections: `ICON0`, `PIC0` and `PIC1`.
//!
//! Only the header chunks are read: enough for the size and whether the image
//! carries alpha. Every finding is a warning, never an error. The XMB scales
//! an image of the wrong size rather than refusing it, and the evidence on
//! alpha is mixed (see `docs/PBP.md`).

use crate::error::{Error, Result};
use crate::pbp::PbpSection;

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

/// What a PNG's header says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PngInfo {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    /// PNG colour type: 0 grey, 2 RGB, 3 palette, 4 grey + alpha, 6 RGBA.
    pub color_type: u8,
    /// An alpha channel, or a `tRNS` chunk that makes some pixels transparent.
    pub alpha: bool,
}

/// Read a PNG's size and colour format from its header chunks.
pub fn png_info(data: &[u8]) -> Result<PngInfo> {
    if !data.starts_with(&SIGNATURE) {
        return Err(Error::InvalidImage("not a PNG".into()));
    }
    let mut info = None;
    let mut at = SIGNATURE.len();
    while at + 8 <= data.len() {
        let length = u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes")) as usize;
        let kind = &data[at + 4..at + 8];
        let body = data
            .get(at + 8..at + 8 + length)
            .ok_or_else(|| Error::InvalidImage("a chunk runs past the end of the file".into()))?;
        match kind {
            b"IHDR" if length == 13 => {
                info = Some(PngInfo {
                    width: u32::from_be_bytes(body[0..4].try_into().expect("4 bytes")),
                    height: u32::from_be_bytes(body[4..8].try_into().expect("4 bytes")),
                    bit_depth: body[8],
                    color_type: body[9],
                    alpha: matches!(body[9], 4 | 6),
                });
            }
            b"IHDR" => return Err(Error::InvalidImage("IHDR is not 13 bytes".into())),
            b"tRNS" => {
                if let Some(info) = &mut info {
                    info.alpha = true;
                }
            }
            // Ancillary chunks that matter come before the image data.
            b"IDAT" | b"IEND" => break,
            _ => {}
        }
        if info.is_none() {
            return Err(Error::InvalidImage("IHDR is not the first chunk".into()));
        }
        at += 12 + length;
    }
    info.ok_or_else(|| Error::InvalidImage("no IHDR chunk".into()))
}

/// The size the XMB draws a PNG section at, for the sections that are PNGs.
pub fn slot_size(section: PbpSection) -> Option<(u32, u32)> {
    match section {
        PbpSection::Icon0Png => Some((144, 80)),
        PbpSection::Pic0Png => Some((310, 180)),
        PbpSection::Pic1Png => Some((480, 272)),
        _ => None,
    }
}

/// Warnings about a PNG section, each prefixed with the section's name. An
/// empty section, or one that is not a PNG slot, has none.
pub fn check_slot(section: PbpSection, data: &[u8]) -> Vec<String> {
    let Some((width, height)) = slot_size(section) else {
        return Vec::new();
    };
    if data.is_empty() {
        return Vec::new();
    }
    let name = section.name();
    let info = match png_info(data) {
        Ok(info) => info,
        Err(e) => return vec![format!("{name}: {e}")],
    };
    let mut warnings = Vec::new();
    if (info.width, info.height) != (width, height) {
        warnings.push(format!(
            "{name}: {} x {}, but the XMB draws it at {width} x {height}",
            info.width, info.height
        ));
    }
    // PIC0 is an overlay; its transparency is the point.
    if info.alpha && section != PbpSection::Pic0Png {
        warnings.push(format!(
            "{name}: has transparency, which some firmware and packers are reported to reject \
             (an RGBA ICON0 shows on a PSP Slim, 6.61)"
        ));
    }
    warnings
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A PNG's header chunks: signature, IHDR, optionally tRNS, then IEND.
    /// CRCs are not checked, so they are zero.
    pub(crate) fn png(width: u32, height: u32, color_type: u8, trns: bool) -> Vec<u8> {
        let mut d = SIGNATURE.to_vec();
        let mut chunk = |kind: &[u8], body: &[u8]| {
            d.extend_from_slice(&(body.len() as u32).to_be_bytes());
            d.extend_from_slice(kind);
            d.extend_from_slice(body);
            d.extend_from_slice(&[0; 4]);
        };
        let mut ihdr = width.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, color_type, 0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        if trns {
            chunk(b"tRNS", &[0, 0]);
        }
        chunk(b"IEND", &[]);
        d
    }

    #[test]
    fn reads_size_and_alpha() {
        let info = png_info(&png(144, 80, 6, false)).unwrap();
        assert_eq!((info.width, info.height, info.alpha), (144, 80, true));
        assert!(!png_info(&png(144, 80, 2, false)).unwrap().alpha);
        assert!(png_info(&png(144, 80, 3, true)).unwrap().alpha);
    }

    #[test]
    fn rejects_what_is_not_a_png() {
        assert!(png_info(b"GIF89a").is_err());
        assert!(png_info(&SIGNATURE).is_err());
        let mut truncated = png(144, 80, 2, false);
        truncated.truncate(20);
        assert!(png_info(&truncated).is_err());
    }

    #[test]
    fn checks_each_slot() {
        assert!(check_slot(PbpSection::Icon0Png, &png(144, 80, 2, false)).is_empty());
        assert!(check_slot(PbpSection::Pic0Png, &png(310, 180, 6, false)).is_empty());
        let wrong = check_slot(PbpSection::Pic1Png, &png(480, 270, 6, false));
        assert_eq!(wrong.len(), 2, "{wrong:?}");
        assert!(wrong[0].contains("480 x 272"));
        assert_eq!(check_slot(PbpSection::Icon0Png, b"not a png").len(), 1);
        assert!(check_slot(PbpSection::Snd0At3, b"anything").is_empty());
        assert!(check_slot(PbpSection::Icon0Png, &[]).is_empty());
    }
}
