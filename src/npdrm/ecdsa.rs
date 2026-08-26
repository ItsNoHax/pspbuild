//! ECDSA on KIRK's curve — the signature over an NPUMDIMG header.
//!
//! # The curve
//!
//! KIRK signs on a 160-bit prime curve of Sony's own choosing, not a published
//! standard one, which is why no general-purpose ECDSA crate can be used. The
//! parameters below back KIRK commands 12, 13, 16 and 17; command 1 uses a
//! different `b`, `n` and `G` over the same `p` and is not implemented here.
//!
//! ```text
//! p = FFFFFFFF FFFFFFFF 00000001 FFFFFFFF FFFFFFFF
//! a = p - 3
//! b = A68BEDC3 3418029C 1D3CE33B 9A321FCC BB9E0F0B
//! n = FFFFFFFF FFFFFFFE FFFFB5AE 3C523E63 944F2127
//! ```
//!
//! Each parameter was checked rather than trusted: `a` really is `p - 3`, `G`
//! satisfies the curve equation, and `n * G` really is the point at infinity —
//! see [`tests`].
//!
//! # The signature is standard ECDSA
//!
//! Despite the KIRK command wrapper, the mathematics is textbook:
//!
//! ```text
//! e = SHA-1(message) mod n
//! R = x(k * G)
//! S = (e + R * d) / k  mod n
//! ```
//!
//! and the 40-byte signature field is `R || S`, each a 20-byte big-endian
//! integer.
//!
//! # What the KIRK key wrapping is, and why it is absent
//!
//! The reference implementation does not pass the private key to
//! `KIRK_CMD_ECDSA_SIGN` directly. It runs `encrypt_kirk16_private` over it
//! first, and the command's own implementation runs `decrypt_kirk16_private`
//! to get it back. Both halves key off the console's fuse ID, so on a real PSP
//! this binds a wrapped key to one machine.
//!
//! Off-console the two are exact inverses under whatever fuse ID is
//! configured, so the pair cancels and the signing routine receives the plain
//! scalar. It is an artifact of the *hardware interface* — how you hand a key
//! to the KIRK engine — and not part of the signature format. Reproducing it
//! here would be ceremony around a round trip that changes nothing.

use num_bigint::BigUint;

use crate::crypto::hmac::hmac_sha1;

use crate::crypto::ec::{Curve, Point, mod_inverse};
use crate::crypto::sha1::Digest160;
use crate::error::{Error, Result};

/// Size of a curve coordinate or scalar, in bytes.
pub const SCALAR_SIZE: usize = 20;

/// Size of a signature: `R || S`.
pub const SIGNATURE_SIZE: usize = 40;

/// Size of a public key: the base point's `x || y`.
pub const PUBLIC_KEY_SIZE: usize = 40;

const P: [u8; SCALAR_SIZE] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
];
const B: [u8; SCALAR_SIZE] = [
    0xA6, 0x8B, 0xED, 0xC3, 0x34, 0x18, 0x02, 0x9C, 0x1D, 0x3C, 0xE3, 0x3B, 0x9A, 0x32, 0x1F, 0xCC,
    0xBB, 0x9E, 0x0F, 0x0B,
];
const N: [u8; SCALAR_SIZE] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xB5, 0xAE, 0x3C, 0x52, 0x3E, 0x63,
    0x94, 0x4F, 0x21, 0x27,
];
const GX: [u8; SCALAR_SIZE] = [
    0x12, 0x8E, 0xC4, 0x25, 0x64, 0x87, 0xFD, 0x8F, 0xDF, 0x64, 0xE2, 0x43, 0x7B, 0xC0, 0xA1, 0xF6,
    0xD5, 0xAF, 0xDE, 0x2C,
];
const GY: [u8; SCALAR_SIZE] = [
    0x59, 0x58, 0x55, 0x7E, 0xB1, 0xDB, 0x00, 0x12, 0x60, 0x42, 0x55, 0x24, 0xDB, 0xC3, 0x79, 0xD5,
    0xAC, 0x5F, 0x4A, 0xDF,
];

/// KIRK's signing curve.
pub fn curve() -> Curve {
    let p = BigUint::from_bytes_be(&P);
    Curve {
        a: &p - 3u32,
        p,
        b: BigUint::from_bytes_be(&B),
        n: BigUint::from_bytes_be(&N),
        g: Point::new(BigUint::from_bytes_be(&GX), BigUint::from_bytes_be(&GY)),
    }
}

/// An ECDSA signature, stored the way the format stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; SCALAR_SIZE],
    pub s: [u8; SCALAR_SIZE],
}

impl Signature {
    /// Parse the 40-byte `R || S` field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::TooShort {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Signature {
            r: bytes[..SCALAR_SIZE].try_into().expect("20 bytes"),
            s: bytes[SCALAR_SIZE..].try_into().expect("20 bytes"),
        })
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..SCALAR_SIZE].copy_from_slice(&self.r);
        out[SCALAR_SIZE..].copy_from_slice(&self.s);
        out
    }
}

/// Sign `digest` with `private_key`, deriving the nonce deterministically.
///
/// # Why this rather than a random nonce
///
/// ECDSA's one catastrophic failure mode is nonce reuse: two signatures made
/// under the same key with the same `k` expose the private key by elementary
/// algebra. The usual defence is a good random number generator, which means
/// the security of every signature rests on something that is easy to get
/// wrong, impossible to check by looking at the output, and — in a build tool
/// that may run in a container or a CI runner — not always well seeded.
///
/// RFC 6979 removes the failure mode instead of guarding it. The nonce is
/// derived by HMAC-SHA1 from the private key and the message, so two different
/// messages cannot collide and the same message always signs identically.
/// There is no entropy source to get wrong.
///
/// The signature is a normal ECDSA signature and verifies as one; nothing
/// about the format cares how `k` was chosen. A pleasant side effect is that
/// signing becomes reproducible, so a built archive differs between runs only
/// where the format genuinely requires randomness.
pub fn sign_deterministic(
    digest: &Digest160,
    private_key: &[u8; SCALAR_SIZE],
) -> Result<Signature> {
    let curve = curve();
    let n = &curve.n;

    let d = BigUint::from_bytes_be(private_key);
    if d == BigUint::ZERO || d >= *n {
        return Err(Error::Crypto(
            "ECDSA private key is out of range 1..n".into(),
        ));
    }

    // RFC 6979 §3.2. Both the order and SHA-1's output are 160 bits here, so
    // the bit-length conversions the RFC describes are plain byte copies.
    let h1 = digest;
    let e = to_scalar(&(BigUint::from_bytes_be(h1) % n));

    let mut v = [0x01u8; 20];
    let mut k = [0x00u8; 20];

    k = hmac_sha1(&k, &[&v, &[0x00], private_key, &e]);
    v = hmac_sha1(&k, &[&v]);
    k = hmac_sha1(&k, &[&v, &[0x01], private_key, &e]);
    v = hmac_sha1(&k, &[&v]);

    // The RFC retries until the candidate is in range and yields a usable
    // signature. A retry is astronomically unlikely on this curve, but the
    // loop is what makes the construction correct rather than nearly correct.
    for _ in 0..1000 {
        v = hmac_sha1(&k, &[&v]);
        let candidate = BigUint::from_bytes_be(&v);

        if candidate != BigUint::ZERO && candidate < *n {
            // A rejection here means r = 0 or s = 0, which the RFC handles
            // by discarding the candidate and deriving the next one.
            if let Ok(signature) = sign(digest, private_key, &to_scalar(&candidate)) {
                return Ok(signature);
            }
        }

        k = hmac_sha1(&k, &[&v, &[0x00]]);
        v = hmac_sha1(&k, &[&v]);
    }

    Err(Error::Crypto(
        "RFC 6979 failed to produce a usable ECDSA nonce".into(),
    ))
}

/// Sign `digest` with `private_key`, using the one-time scalar `k`.
///
/// # Why `k` is a parameter
///
/// The reference implementation draws `k` from the KIRK PRNG, which is what
/// makes a signed archive irreproducible: sign the same bytes twice and the
/// signatures differ. Taking `k` from the caller keeps this function a pure
/// one, so it can be tested against fixed answers at all, and leaves the
/// choice of randomness to the layer that knows what it wants.
///
/// `k` must be unpredictable and must never be reused across two different
/// messages under the same key: two signatures sharing a `k` expose the
/// private key by elementary algebra.
pub fn sign(
    digest: &Digest160,
    private_key: &[u8; SCALAR_SIZE],
    k: &[u8; SCALAR_SIZE],
) -> Result<Signature> {
    let curve = curve();
    let n = &curve.n;

    let d = BigUint::from_bytes_be(private_key);
    let k = BigUint::from_bytes_be(k);
    if k == BigUint::ZERO || k >= *n {
        return Err(Error::Crypto("ECDSA nonce is out of range 1..n".into()));
    }
    if d == BigUint::ZERO || d >= *n {
        return Err(Error::Crypto(
            "ECDSA private key is out of range 1..n".into(),
        ));
    }

    let e = BigUint::from_bytes_be(digest) % n;

    let Some((x, _)) = curve
        .mul_g(&k)
        .coords()
        .map(|(x, y)| (x.clone(), y.clone()))
    else {
        return Err(Error::Crypto(
            "ECDSA nonce produced the point at infinity".into(),
        ));
    };
    let r = x % n;
    if r == BigUint::ZERO {
        return Err(Error::Crypto("ECDSA nonce produced r = 0".into()));
    }

    let k_inv =
        mod_inverse(&k, n).ok_or_else(|| Error::Crypto("ECDSA nonce is not invertible".into()))?;
    let s = (k_inv * ((e + &r * &d) % n)) % n;
    if s == BigUint::ZERO {
        return Err(Error::Crypto("ECDSA nonce produced s = 0".into()));
    }

    Ok(Signature {
        r: to_scalar(&r),
        s: to_scalar(&s),
    })
}

/// Check `signature` over `digest` against `public_key`.
///
/// Returns `false` for a bad signature and for a malformed or off-curve public
/// key alike — verifying against a point that is not on the curve proves
/// nothing, so it is not treated as a lesser failure.
pub fn verify(
    digest: &Digest160,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    signature: &Signature,
) -> bool {
    let curve = curve();
    let n = &curve.n;

    let q = Point::new(
        BigUint::from_bytes_be(&public_key[..SCALAR_SIZE]),
        BigUint::from_bytes_be(&public_key[SCALAR_SIZE..]),
    );
    if !curve.contains(&q) || q.is_infinity() {
        return false;
    }

    let r = BigUint::from_bytes_be(&signature.r);
    let s = BigUint::from_bytes_be(&signature.s);
    if r == BigUint::ZERO || s == BigUint::ZERO || r >= *n || s >= *n {
        return false;
    }

    let e = BigUint::from_bytes_be(digest) % n;
    let Some(w) = mod_inverse(&s, n) else {
        return false;
    };

    let u1 = (e * &w) % n;
    let u2 = (&r * &w) % n;

    let point = curve.add(&curve.mul_g(&u1), &curve.mul(&u2, &q));
    match point.coords() {
        None => false,
        Some((x, _)) => x % n == r,
    }
}

/// The public key for a private scalar, as `x || y`.
///
/// Useful mostly as a check: a private key and a public key that do not agree
/// are not a key pair, and no signature made with the one will verify under
/// the other.
pub fn public_key(private_key: &[u8; SCALAR_SIZE]) -> Result<[u8; PUBLIC_KEY_SIZE]> {
    let curve = curve();
    let d = BigUint::from_bytes_be(private_key);
    if d == BigUint::ZERO || d >= curve.n {
        return Err(Error::Crypto(
            "ECDSA private key is out of range 1..n".into(),
        ));
    }
    let point = curve.mul_g(&d);
    let (x, y) = point
        .coords()
        .ok_or_else(|| Error::Crypto("private key maps to the point at infinity".into()))?;

    let mut out = [0u8; PUBLIC_KEY_SIZE];
    out[..SCALAR_SIZE].copy_from_slice(&to_scalar(x));
    out[SCALAR_SIZE..].copy_from_slice(&to_scalar(y));
    Ok(out)
}

/// Big-endian, left-padded to the curve's width.
///
/// `BigUint::to_bytes_be` drops leading zeros, so a value that happens to be
/// short would otherwise be written misaligned — a rare, data-dependent
/// corruption that only appears for roughly one key in 256.
fn to_scalar(value: &BigUint) -> [u8; SCALAR_SIZE] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; SCALAR_SIZE];
    let start = SCALAR_SIZE.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(SCALAR_SIZE)..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npdrm::keys::{NPUMDIMG_PRIVATE_KEY, NPUMDIMG_PUBLIC_KEY};

    fn digest_of(data: &[u8]) -> Digest160 {
        crate::crypto::sha1::sha1(data)
    }

    /// The curve parameters have to hold together, or everything above them is
    /// arithmetic on nonsense. All three of these are cheap and none of them
    /// were assumed.
    #[test]
    fn the_curve_parameters_are_self_consistent() {
        let c = curve();

        // a = p - 3, the usual choice for a curve of this shape.
        assert_eq!(c.a, &c.p - 3u32);

        // The base point satisfies the curve equation.
        assert!(c.contains(&c.g), "G is not on the curve");

        // And n really is its order.
        assert!(c.mul(&c.n, &c.g).is_infinity(), "n * G is not infinity");

        // p and n are both 160-bit, as the 20-byte fields require.
        assert_eq!(c.p.bits(), 160);
        assert_eq!(c.n.bits(), 160);
    }

    /// The two vendored keys must actually be a pair. This is the check that
    /// makes vendoring them defensible: if they disagreed, every signature
    /// produced here would be silently unverifiable.
    #[test]
    fn the_vendored_keys_are_a_matching_pair() {
        assert_eq!(
            public_key(&NPUMDIMG_PRIVATE_KEY).unwrap(),
            NPUMDIMG_PUBLIC_KEY,
            "the private key does not generate the published public key"
        );
    }

    #[test]
    fn the_public_key_is_on_the_curve() {
        let c = curve();
        let q = Point::new(
            BigUint::from_bytes_be(&NPUMDIMG_PUBLIC_KEY[..SCALAR_SIZE]),
            BigUint::from_bytes_be(&NPUMDIMG_PUBLIC_KEY[SCALAR_SIZE..]),
        );
        assert!(c.contains(&q));
    }

    #[test]
    fn a_signature_verifies_under_its_own_key() {
        let digest = digest_of(b"the quick brown fox");
        for nonce in [1u8, 7, 0x5A, 0xFF] {
            let mut k = [0u8; SCALAR_SIZE];
            k[SCALAR_SIZE - 1] = nonce;
            k[0] = nonce; // keep it comfortably large as well as non-zero
            let sig = sign(&digest, &NPUMDIMG_PRIVATE_KEY, &k).unwrap();
            assert!(
                verify(&digest, &NPUMDIMG_PUBLIC_KEY, &sig),
                "nonce {nonce:#04X} produced a signature that will not verify"
            );
        }
    }

    #[test]
    fn a_different_nonce_gives_a_different_signature() {
        let digest = digest_of(b"same message");
        let mut k1 = [0x11u8; SCALAR_SIZE];
        let mut k2 = [0x11u8; SCALAR_SIZE];
        k1[SCALAR_SIZE - 1] = 1;
        k2[SCALAR_SIZE - 1] = 2;

        let a = sign(&digest, &NPUMDIMG_PRIVATE_KEY, &k1).unwrap();
        let b = sign(&digest, &NPUMDIMG_PRIVATE_KEY, &k2).unwrap();
        assert_ne!(a, b, "signing is supposed to depend on the nonce");
        assert!(verify(&digest, &NPUMDIMG_PUBLIC_KEY, &a));
        assert!(verify(&digest, &NPUMDIMG_PUBLIC_KEY, &b));
    }

    #[test]
    fn a_changed_message_does_not_verify() {
        let k = [0x42u8; SCALAR_SIZE];
        let sig = sign(&digest_of(b"original"), &NPUMDIMG_PRIVATE_KEY, &k).unwrap();
        assert!(!verify(&digest_of(b"tampered"), &NPUMDIMG_PUBLIC_KEY, &sig));
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let digest = digest_of(b"message");
        let k = [0x42u8; SCALAR_SIZE];
        let sig = sign(&digest, &NPUMDIMG_PRIVATE_KEY, &k).unwrap();

        for byte in [0usize, 19, 20, 39] {
            let mut bytes = sig.to_bytes();
            bytes[byte] ^= 0x01;
            let bad = Signature::from_bytes(&bytes).unwrap();
            assert!(
                !verify(&digest, &NPUMDIMG_PUBLIC_KEY, &bad),
                "a flipped bit at {byte} still verified"
            );
        }
    }

    /// Verifying against a point that is not on the curve must fail outright,
    /// not fall through to arithmetic that might accidentally agree.
    #[test]
    fn an_off_curve_public_key_is_rejected() {
        let digest = digest_of(b"message");
        let k = [0x42u8; SCALAR_SIZE];
        let sig = sign(&digest, &NPUMDIMG_PRIVATE_KEY, &k).unwrap();

        let mut bogus = NPUMDIMG_PUBLIC_KEY;
        bogus[0] ^= 0x01;
        assert!(!verify(&digest, &bogus, &sig));

        assert!(!verify(&digest, &[0u8; PUBLIC_KEY_SIZE], &sig));
    }

    #[test]
    fn out_of_range_scalars_are_refused() {
        let digest = digest_of(b"message");
        let zero = [0u8; SCALAR_SIZE];
        let too_big = [0xFFu8; SCALAR_SIZE];

        assert!(sign(&digest, &NPUMDIMG_PRIVATE_KEY, &zero).is_err());
        assert!(sign(&digest, &NPUMDIMG_PRIVATE_KEY, &too_big).is_err());
        assert!(sign(&digest, &zero, &[0x42u8; SCALAR_SIZE]).is_err());
        assert!(public_key(&zero).is_err());
    }

    #[test]
    fn a_signature_round_trips_through_its_byte_form() {
        let k = [0x42u8; SCALAR_SIZE];
        let sig = sign(&digest_of(b"message"), &NPUMDIMG_PRIVATE_KEY, &k).unwrap();
        assert_eq!(Signature::from_bytes(&sig.to_bytes()).unwrap(), sig);
        assert!(Signature::from_bytes(&[0u8; 39]).is_err());
        assert!(Signature::from_bytes(&[0u8; 41]).is_err());
    }

    /// Signatures with r or s zero are rejected on the way in, so a verifier
    /// cannot be talked into accepting a degenerate pair.
    #[test]
    fn degenerate_signatures_are_rejected() {
        let digest = digest_of(b"message");
        let zero = Signature {
            r: [0u8; SCALAR_SIZE],
            s: [0u8; SCALAR_SIZE],
        };
        assert!(!verify(&digest, &NPUMDIMG_PUBLIC_KEY, &zero));
    }

    /// A deterministic signature is still an ordinary signature.
    #[test]
    fn a_deterministic_signature_verifies() {
        let digest = digest_of(b"a message to sign");
        let signature = sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY).unwrap();
        assert!(verify(&digest, &NPUMDIMG_PUBLIC_KEY, &signature));
    }

    /// The whole point: the same input always produces the same nonce, so
    /// there is no random number generator whose failure could leak the key.
    #[test]
    fn the_same_message_always_signs_identically() {
        let digest = digest_of(b"stability");
        let a = sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY).unwrap();
        let b = sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    /// And the other half of the property: different messages must not share
    /// a nonce, which shows up as a shared `r`.
    #[test]
    fn different_messages_do_not_share_a_nonce() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..32u32 {
            let digest = digest_of(&i.to_le_bytes());
            let signature = sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY).unwrap();
            assert!(
                seen.insert(signature.r),
                "message {i} reused a nonce, which would expose the private key"
            );
            assert!(verify(&digest, &NPUMDIMG_PUBLIC_KEY, &signature));
        }
    }

    /// The nonce depends on the key as well as the message, so the same
    /// message under two keys must not collide either.
    #[test]
    fn the_private_key_changes_the_nonce() {
        let digest = digest_of(b"same message");
        let mut other = NPUMDIMG_PRIVATE_KEY;
        other[19] ^= 0x01;

        let a = sign_deterministic(&digest, &NPUMDIMG_PRIVATE_KEY).unwrap();
        let b = sign_deterministic(&digest, &other).unwrap();
        assert_ne!(a.r, b.r);
    }

    #[test]
    fn a_degenerate_private_key_is_refused() {
        assert!(sign_deterministic(&digest_of(b"x"), &[0u8; SCALAR_SIZE]).is_err());
        assert!(sign_deterministic(&digest_of(b"x"), &[0xFFu8; SCALAR_SIZE]).is_err());
    }
}
