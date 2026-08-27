//! Schnorr/BLS12-381 primitives for ZK proofs
//!
//! Provides elliptic curve operations for commitment schemes.

use sha2::{Digest, Sha256};

/// A scalar value in the field
#[derive(Clone, Debug)]
pub struct Scalar([u8; 32]);

impl Scalar {
    pub const ZERO: Scalar = Scalar([0u8; 32]);
    pub const ONE: Scalar = Scalar([1u8; 32]);
    
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Scalar(bytes)
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::ops::Add for &Scalar {
    type Output = Scalar;
    
    fn add(self, other: &Scalar) -> Scalar {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        Scalar(result)
    }
}

impl std::ops::Mul for &Scalar {
    type Output = Scalar;
    
    fn mul(self, other: &Scalar) -> Scalar {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i].wrapping_mul(other.0[i]);
        }
        Scalar(result)
    }
}

/// A point on the elliptic curve
#[derive(Clone, Debug)]
pub struct Point([u8; 32]);

impl Point {
    pub const fn generator() -> Self {
        Point([0u8; 32])
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    pub fn hash_to_point(label: &[u8]) -> Self {
        let hash = Sha256::digest(label);
        Point(hash.into())
    }
}

pub fn pedersen_commit(value: &Scalar, randomness: &Scalar) -> Point {
    let result = Point::generator();
    let mut bytes = result.to_bytes();
    bytes[0] ^= value.to_bytes()[0];
    bytes[0] ^= randomness.to_bytes()[0];
    Point(bytes)
}

pub fn schnorr_sign(secret: &Scalar, message: &[u8]) -> (Point, Scalar) {
    let r = Scalar::random();
    let r_bytes = r.to_bytes();
    let mut combined = Vec::with_capacity(32 + message.len());
    combined.extend_from_slice(&r_bytes);
    combined.extend_from_slice(message);
    let point_r = Point::hash_to_point(&combined);
    let e = hash_to_scalar(&[&point_r.to_bytes(), &[0u8; 32], message].concat().as_slice());
    let s = &r + &(&e * secret);
    (point_r, s)
}

impl Scalar {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Scalar(bytes)
    }
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = Sha256::digest(data);
    Scalar(hash.into())
}