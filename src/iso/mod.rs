//! Reading PSP UMD images.
//!
//! A PSP ISO is plain ISO9660. There is no Joliet supplementary descriptor and
//! no Rock Ridge — the volume descriptor set on a retail UMD is a primary
//! descriptor followed immediately by a terminator — so the primary descriptor
//! and its 8.3 names are the whole story.
//!
//! The EG pipeline needs two things from an image: the `PSP_GAME` assets that
//! become PBP sections, and the raw sectors that become the encrypted archive.
//! [`reader::Iso`] provides both without loading the image into memory, which
//! matters when a UMD runs to 1.8 GB.
//!
//! See `docs/ISO.md`.

pub mod reader;

pub use reader::{Iso, IsoEntry, SECTOR_SIZE, VolumeInfo};

/// Paths the EG pipeline looks for, in PBP section order.
///
/// A UMD is not required to carry all of them. `SND0.AT3` in particular is
/// frequently absent, so a missing asset is a normal outcome rather than a
/// malformed image.
pub const PSP_GAME_ASSETS: [(&str, crate::pbp::PbpSection); 6] = [
    ("/PSP_GAME/PARAM.SFO", crate::pbp::PbpSection::ParamSfo),
    ("/PSP_GAME/ICON0.PNG", crate::pbp::PbpSection::Icon0Png),
    ("/PSP_GAME/ICON1.PMF", crate::pbp::PbpSection::Icon1Pmf),
    ("/PSP_GAME/PIC0.PNG", crate::pbp::PbpSection::Pic0Png),
    ("/PSP_GAME/PIC1.PNG", crate::pbp::PbpSection::Pic1Png),
    ("/PSP_GAME/SND0.AT3", crate::pbp::PbpSection::Snd0At3),
];

/// The module a UMD boots.
pub const EBOOT_BIN: &str = "/PSP_GAME/SYSDIR/EBOOT.BIN";

/// The unencrypted twin of `EBOOT.BIN` present on most retail discs.
pub const BOOT_BIN: &str = "/PSP_GAME/SYSDIR/BOOT.BIN";

/// Disc identification, e.g. `ULUS-10380|B9A094E266C83E96|0001|G`.
pub const UMD_DATA_BIN: &str = "/UMD_DATA.BIN";
