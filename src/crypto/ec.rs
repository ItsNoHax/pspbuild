//! Elliptic curve arithmetic over a prime field.
//!
//! A short Weierstrass curve `y^2 = x^3 + ax + b (mod p)` in affine
//! coordinates, with the curve supplied by the caller. Nothing here is
//! PSP-specific; the KIRK curve and the ECDSA wiring live in
//! [`crate::npdrm::ecdsa`].
//!
//! # Why this is not a crate dependency
//!
//! Every general-purpose Rust ECDSA implementation is built around a fixed set
//! of standard curves — NIST P-256, secp256k1 and friends. KIRK signs on a
//! 160-bit curve of Sony's own choosing, which none of them expose, so the
//! curve arithmetic has to exist here. The *integer* arithmetic underneath it
//! does not, and is `num-bigint`'s.
//!
//! # Not constant time
//!
//! `num-bigint` is variable-time, and the scalar multiplication below branches
//! on key bits. That is a deliberate, bounded decision rather than an
//! oversight:
//!
//! - The NPUMDIMG private key is a *published* value, recovered years ago and
//!   present in every tool that signs this format. There is no secret to leak.
//! - Signing happens once per archive, offline, on the machine that already
//!   holds the key.
//!
//! If this code is ever pointed at a key that is actually secret, this note
//! stops being adequate and the implementation needs replacing.

use num_bigint::BigUint;
use num_integer::Integer;

/// A short Weierstrass curve over `F_p`.
#[derive(Debug, Clone)]
pub struct Curve {
    /// Field characteristic.
    pub p: BigUint,
    /// Curve coefficient `a`.
    pub a: BigUint,
    /// Curve coefficient `b`.
    pub b: BigUint,
    /// Order of the base point.
    pub n: BigUint,
    /// Base point.
    pub g: Point,
}

/// An affine point, or the point at infinity.
///
/// Infinity is represented as its own variant rather than as a sentinel
/// coordinate pair, so it cannot be confused with a real point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine { x: BigUint, y: BigUint },
}

impl Point {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Point::Affine { x, y }
    }

    pub fn is_infinity(&self) -> bool {
        matches!(self, Point::Infinity)
    }

    /// The affine coordinates, or `None` at infinity.
    pub fn coords(&self) -> Option<(&BigUint, &BigUint)> {
        match self {
            Point::Infinity => None,
            Point::Affine { x, y } => Some((x, y)),
        }
    }
}

impl Curve {
    /// Whether `point` satisfies the curve equation.
    ///
    /// Worth calling on any point that arrived from outside: a signature
    /// verified against a point that is not on the curve proves nothing.
    pub fn contains(&self, point: &Point) -> bool {
        let Some((x, y)) = point.coords() else {
            return true;
        };
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let lhs = y.modpow(&BigUint::from(2u32), &self.p);
        let rhs = (x.modpow(&BigUint::from(3u32), &self.p) + &self.a * x + &self.b) % &self.p;
        lhs == rhs
    }

    /// Add two points.
    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        let (Some((x1, y1)), Some((x2, y2))) = (p1.coords(), p2.coords()) else {
            // Infinity is the identity, so adding it returns the other point.
            return if p1.is_infinity() {
                p2.clone()
            } else {
                p1.clone()
            };
        };

        if x1 == x2 {
            // Either a doubling, or a point plus its own negation.
            if (y1 + y2) % &self.p == BigUint::ZERO {
                return Point::Infinity;
            }
            return self.double_at(x1, y1);
        }

        // lambda = (y2 - y1) / (x2 - x1)
        let num = self.sub_mod(y2, y1);
        let den = self.sub_mod(x2, x1);
        let Some(inv) = self.inv_mod(&den) else {
            return Point::Infinity;
        };
        self.point_from_slope(&(num * inv % &self.p), x1, y1, x2)
    }

    /// Double a point.
    pub fn double(&self, point: &Point) -> Point {
        match point.coords() {
            None => Point::Infinity,
            Some((x, y)) => {
                if y == &BigUint::ZERO {
                    return Point::Infinity;
                }
                self.double_at(x, y)
            }
        }
    }

    fn double_at(&self, x: &BigUint, y: &BigUint) -> Point {
        // lambda = (3x^2 + a) / 2y
        let num = (BigUint::from(3u32) * x * x + &self.a) % &self.p;
        let den = (BigUint::from(2u32) * y) % &self.p;
        let Some(inv) = self.inv_mod(&den) else {
            return Point::Infinity;
        };
        self.point_from_slope(&(num * inv % &self.p), x, y, x)
    }

    /// Build the result point from a chord/tangent slope.
    fn point_from_slope(
        &self,
        lambda: &BigUint,
        x1: &BigUint,
        y1: &BigUint,
        x2: &BigUint,
    ) -> Point {
        let x3 = self.sub_mod(&self.sub_mod(&(lambda * lambda % &self.p), x1), x2);
        let y3 = self.sub_mod(&(lambda * self.sub_mod(x1, &x3) % &self.p), y1);
        Point::Affine { x: x3, y: y3 }
    }

    /// Multiply `point` by `scalar`, left to right over the scalar's bits.
    pub fn mul(&self, scalar: &BigUint, point: &Point) -> Point {
        let mut result = Point::Infinity;
        if scalar == &BigUint::ZERO {
            return result;
        }
        for i in (0..scalar.bits()).rev() {
            result = self.double(&result);
            if scalar.bit(i) {
                result = self.add(&result, point);
            }
        }
        result
    }

    /// `scalar * G`.
    pub fn mul_g(&self, scalar: &BigUint) -> Point {
        self.mul(scalar, &self.g.clone())
    }

    /// `(a - b) mod p`, without going through signed arithmetic.
    fn sub_mod(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let a = a % &self.p;
        let b = b % &self.p;
        if a >= b { a - b } else { &self.p - (b - a) }
    }

    /// Modular inverse, or `None` when `value` is not invertible.
    fn inv_mod(&self, value: &BigUint) -> Option<BigUint> {
        mod_inverse(value, &self.p)
    }
}

/// Modular inverse by the extended Euclidean algorithm.
///
/// Returns `None` when `value` shares a factor with `modulus`, which for a
/// prime modulus means only `value == 0`.
pub fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;

    let g = BigInt::from(value.clone()).extended_gcd(&BigInt::from(modulus.clone()));
    if g.gcd != BigInt::from(1u32) {
        return None;
    }
    let m = BigInt::from(modulus.clone());
    Some((((g.x % &m) + &m) % &m).to_biguint().expect("non-negative"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny curve with known-by-hand structure: y^2 = x^3 + 2x + 3 mod 97,
    /// which has order 5 at the point (3, 6).
    fn toy() -> Curve {
        Curve {
            p: BigUint::from(97u32),
            a: BigUint::from(2u32),
            b: BigUint::from(3u32),
            n: BigUint::from(5u32),
            g: Point::new(BigUint::from(3u32), BigUint::from(6u32)),
        }
    }

    #[test]
    fn the_base_point_is_on_the_curve() {
        let c = toy();
        assert!(c.contains(&c.g));
        assert!(c.contains(&Point::Infinity));
    }

    /// The multiples of G must cycle with period n, and n*G must be infinity.
    #[test]
    fn the_group_closes_at_the_stated_order() {
        let c = toy();
        assert!(c.mul(&c.n, &c.g).is_infinity());

        // Every intermediate multiple is a real point on the curve.
        for i in 1u32..5 {
            let p = c.mul(&BigUint::from(i), &c.g);
            assert!(!p.is_infinity(), "{i}*G collapsed early");
            assert!(c.contains(&p), "{i}*G is off the curve");
        }
        // And it wraps: (n+1)*G == G.
        assert_eq!(c.mul(&(c.n.clone() + 1u32), &c.g), c.g);
    }

    #[test]
    fn addition_is_commutative_and_associative() {
        let c = toy();
        let g2 = c.mul(&BigUint::from(2u32), &c.g);
        let g3 = c.mul(&BigUint::from(3u32), &c.g);

        assert_eq!(c.add(&c.g, &g2), c.add(&g2, &c.g));
        assert_eq!(c.add(&c.add(&c.g, &g2), &g3), c.add(&c.g, &c.add(&g2, &g3)));
    }

    #[test]
    fn doubling_agrees_with_adding_to_itself() {
        let c = toy();
        assert_eq!(c.double(&c.g), c.add(&c.g, &c.g));
    }

    #[test]
    fn infinity_is_the_identity() {
        let c = toy();
        assert_eq!(c.add(&c.g, &Point::Infinity), c.g);
        assert_eq!(c.add(&Point::Infinity, &c.g), c.g);
        assert_eq!(c.mul(&BigUint::ZERO, &c.g), Point::Infinity);
        assert!(c.double(&Point::Infinity).is_infinity());
    }

    /// A point plus its own negation is infinity, which is the case the
    /// x1 == x2 branch has to distinguish from a doubling.
    #[test]
    fn a_point_plus_its_negation_is_infinity() {
        let c = toy();
        let (x, y) = c.g.coords().unwrap();
        let neg = Point::new(x.clone(), &c.p - y);
        assert!(c.add(&c.g, &neg).is_infinity());
    }

    #[test]
    fn a_point_off_the_curve_is_rejected() {
        let c = toy();
        assert!(!c.contains(&Point::new(BigUint::from(3u32), BigUint::from(7u32))));
        // Coordinates at or beyond p are out of the field.
        assert!(!c.contains(&Point::new(BigUint::from(97u32), BigUint::from(6u32))));
    }

    #[test]
    fn modular_inverse_round_trips() {
        let m = BigUint::from(97u32);
        for v in 1u32..97 {
            let v = BigUint::from(v);
            let inv = mod_inverse(&v, &m).expect("prime modulus, non-zero value");
            assert_eq!(v * inv % &m, BigUint::from(1u32));
        }
        assert!(mod_inverse(&BigUint::ZERO, &m).is_none());
    }
}
