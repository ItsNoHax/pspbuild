//! Error types for the PRX encrypter.
//!
//! Every fallible operation in this crate returns [`Error`]. Malformed user
//! input must always surface as an `Err`, never as a panic.

use std::path::PathBuf;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid PRX header: {0}")]
    InvalidPrxHeader(String),

    #[error("unsupported PRX version: {0}")]
    UnsupportedPrxVersion(u32),

    #[error("payload exceeds supported size: {size} bytes (maximum {max})")]
    PayloadTooLarge { size: u64, max: u64 },

    #[error("invalid KIRK header: {0}")]
    InvalidKirkHeader(String),

    #[error("invalid alignment: {0}")]
    InvalidAlignment(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("unsupported PSPemu/PBOOT format: {0}")]
    UnsupportedPspEmu(String),

    #[error("invalid PBP container: {0}")]
    InvalidPbp(String),

    #[error("invalid PARAM.SFO: {0}")]
    InvalidSfo(String),

    #[error("expected a {expected} PBP but PARAM.SFO says CATEGORY={actual}")]
    CategoryMismatch { expected: String, actual: String },

    #[error("invalid ISO image: {0}")]
    InvalidIso(String),

    #[error("ISO is missing {0}")]
    IsoMissingFile(String),

    #[error("{pipeline} pipeline is not implemented yet: {detail}")]
    Unimplemented {
        pipeline: &'static str,
        detail: String,
    },

    #[error("unknown encryption tag {tag:#010X}")]
    UnknownTag { tag: u32 },

    #[error("input is too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("compression failed: {0}")]
    Compression(String),

    #[error("integrity check failed: {0}")]
    IntegrityCheck(String),

    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("i/o error: {0}")]
    BareIo(#[from] std::io::Error),
}

impl Error {
    /// Attach a path to an [`std::io::Error`] for a better message.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
