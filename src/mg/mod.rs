//! The MG security path: memory-stick games, which is what homebrew is.
//!
//! `CATEGORY=MG` tells the firmware the executable is an encrypted PRX sitting
//! in the container's `DATA.PSP` section. There is no NPDRM, no `DATA.PSAR`
//! archive and no signature — the whole security path is the `~PSP` header and
//! its KIRK container, which [`crate::prx`] already implements.
//!
//! ```text
//! PRX -> optional gzip -> KIRK CMD1 + ~PSP header -> DATA.PSP -> EBOOT.PBP
//!                                                       ^
//!                                              PARAM.SFO (CATEGORY=MG)
//! ```
//!
//! This is deliberately kept separate from the EG path. The two use different
//! cryptography and a build must never cross from one to the other silently;
//! see `docs/MG.md`.

pub mod eboot;

pub use eboot::{MgEboot, MgEbootRequest, build_mg_eboot};
