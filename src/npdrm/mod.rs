//! NPDRM primitives.
//!
//! The cryptography behind Store content: BB-MAC for authentication,
//! BB-Cipher for confidentiality, and the fixed-key derivation that lets a
//! title be decrypted from its content ID alone. Together these are what the
//! firmware calls AMCTRL.
//!
//! These are primitives only. The [`NPUMDIMG`] archive that uses them is
//! specified but not yet built.
//!
//! # How these were established
//!
//! Each primitive is pinned by known-answer tests captured from the reference
//! implementation across every length and boundary its internal buffering
//! distinguishes — not by transliterating its source. That distinction earned
//! its keep immediately: the reference's own caller passes `type` and `mode`
//! in the opposite order to how the earlier specification recorded them, which
//! a transliteration would have preserved and a known-answer test caught.
//!
//! Two firmware variants are deliberately missing, both for the same reason:
//! BB-MAC type 2 and BB-Cipher type 2 route through KIRK command 5, which
//! encrypts under a key derived from the console's fuse ID. Off-console that
//! key does not exist, so the only possible implementation would be a
//! confidently wrong one. Neither is used by NPUMDIMG.
//!
//! [`NPUMDIMG`]: https://github.com/ItsNoHax/pspbuild/blob/main/docs/NPUMDIMG.md

pub mod bbcipher;
pub mod bbmac;
pub mod blocks;
pub mod ecdsa;
pub mod fixed_key;
pub mod keys;
pub mod lzrc;
pub mod npumdimg;
pub mod table;

#[cfg(test)]
mod test_vectors;

pub use bbcipher::{BbCipher, bbcipher};
pub use bbmac::{BbMac, BbMacType, bbmac};
pub use blocks::{BlockLayout, decrypt_block, encrypt_block};
pub use ecdsa::Signature;
pub use fixed_key::{FIXED_KEY_FLAG, fixed_key};
pub use npumdimg::{header_digest, sign_header, verify_header};
pub use table::{BlockEntry, ENTRY_SIZE};
