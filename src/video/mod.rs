//! Video for the XMB: turning ordinary video files into `ICON1.PMF`.
//!
//! ```no_run
//! use pspbuild::video::make_icon1;
//!
//! let icon1 = make_icon1(std::path::Path::new("icon.mp4"))?;
//! std::fs::write("ICON1.PMF", &icon1.data)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Pipeline
//!
//! ```text
//! any video -> ffmpeg/libx264: 144x80, 29.97 fps, Main 2.1, I/P, 59-frame GOPs
//!           -> Annex B access units -> PSMF program stream -> ICON1.PMF
//! ```
//!
//! Unlike the rest of pspbuild, encoding needs an external tool: there is no
//! H.264 encoder in pure Rust that writes the CABAC Main-profile stream the
//! XMB decodes, so a video is encoded by running `ffmpeg` (with `libx264`).
//! An H.264 Annex B stream that is already encoded is muxed without it, and a
//! PMF is passed through. The format rules are in `docs/VIDEO.md`.

pub mod pmf;

pub use pmf::{ICON1_HEIGHT, ICON1_WIDTH, Pmf, is_annex_b, is_pmf, mux};

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

/// How an ICON1 came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon1Source {
    /// The input was already a PMF and is used byte for byte.
    PassedThrough,
    /// The input was an H.264 Annex B stream, muxed as-is.
    Muxed,
    /// The input was encoded with ffmpeg, then muxed.
    Encoded,
}

/// A finished `ICON1.PMF`.
#[derive(Debug, Clone)]
pub struct Icon1 {
    pub data: Vec<u8>,
    pub source: Icon1Source,
    /// Pictures and GOPs, when pspbuild muxed the file.
    pub frames: Option<usize>,
    pub gops: Option<usize>,
}

/// The x264 settings that reproduce the reference icon's stream.
fn x264_params() -> String {
    [
        format!("keyint={}", pmf::GOP_FRAMES),
        format!("min-keyint={}", pmf::GOP_FRAMES),
        "scenecut=0".into(),
        "bframes=0".into(),
        "ref=1".into(),
        "weightp=0".into(),
        "aud=1".into(),
        "nal-hrd=vbr".into(),
        "pic-struct=1".into(),
        "force-cfr=1".into(),
        // The P-STD buffer is 85 KiB; keep the VBV well inside it.
        "vbv-maxrate=600".into(),
        "vbv-bufsize=600".into(),
    ]
    .join(":")
}

/// Encode any video ffmpeg can read into the H.264 Annex B stream an ICON1
/// carries. Audio is dropped.
pub fn encode_h264(input: &Path) -> Result<Vec<u8>> {
    let scale = format!("scale={ICON1_WIDTH}:{ICON1_HEIGHT},fps=30000/1001");
    let output = Command::new("ffmpeg")
        .args(["-nostdin", "-v", "error", "-i"])
        .arg(input)
        .args(["-an", "-vf", &scale, "-pix_fmt", "yuv420p"])
        .args(["-c:v", "libx264", "-profile:v", "main", "-level", "2.1"])
        .args(["-crf", "18", "-x264-params", &x264_params()])
        .args(["-bsf:v", "h264_mp4toannexb", "-f", "h264", "-"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            Error::Encoder(format!(
                "could not run ffmpeg ({e}); it is needed, with libx264, to encode video"
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Encoder(format!(
            "ffmpeg failed on {}: {}",
            input.display(),
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

/// Turn a video, an H.264 Annex B stream or a PMF into an `ICON1.PMF`.
pub fn make_icon1(input: &Path) -> Result<Icon1> {
    let bytes = std::fs::read(input).map_err(|e| Error::io(input, e))?;
    if is_pmf(&bytes) {
        return Ok(Icon1 {
            data: bytes,
            source: Icon1Source::PassedThrough,
            frames: None,
            gops: None,
        });
    }
    let (stream, source) = if is_annex_b(&bytes) {
        (bytes, Icon1Source::Muxed)
    } else {
        (encode_h264(input)?, Icon1Source::Encoded)
    };
    let muxed = mux(&stream)?;
    Ok(Icon1 {
        data: muxed.data,
        source,
        frames: Some(muxed.frames),
        gops: Some(muxed.gops),
    })
}
