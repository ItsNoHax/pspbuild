//! Cryptographic primitives.
//!
//! Every third-party crypto crate call in this project lives under this
//! module; the KIRK and PSP layers call these wrappers only.

pub mod aes;
pub mod cmac;
pub mod ec;
pub mod hmac;
pub mod sha1;
