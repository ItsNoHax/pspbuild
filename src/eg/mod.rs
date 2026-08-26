//! The EG pipeline: a UMD image as a signed NPDRM `EBOOT.PBP`.
//!
//! See `docs/EG.md` for what this path is and how it differs from MG, and
//! `docs/NPUMDIMG.md` for the archive format it produces.

pub mod eboot;

pub use eboot::{EgEboot, build_eg_eboot};
