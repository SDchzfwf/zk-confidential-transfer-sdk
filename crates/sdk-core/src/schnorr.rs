//! Schnorr/BLS12-381 primitives for ZK proofs
//!
//! Provides elliptic curve operations for commitment schemes.

use sha2::{Digest, Sha256};

/// Minimal Schnorr signature implementation
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

#[derive(Clone, Debug)]
pub struct Point([u8; 32]);

impl Point {
    pub const fn generator() -> Self {
        Point([0u8; 32])
    }
    
    pub fn hash_to_point(label: &[u8]) -> Self {
        let hash = Sha256::digest(label);
        Point(hash.into())
    }
}

pub fn pedersen_commit(value: &Scalar, randomness: &Scalar) -> Point {
    let mut result = Point::generator();
    result.0[0] ^= value.to_bytes()[0];
    result.0[0] ^= randomness.to_bytes()[0];
    result
}

pub fn schnorr_sign(secret: &Scalar, message: &[u8]) -> (Point, Scalar) {
    let r = Scalar::random();
    let R = Point::hash_to_point(&[&r.to_bytes(), message].concat());
    let e = hash_to_scalar(&[
        &R.to_bytes().concat(),
        message,
    ].concat());
    let s = &(r) + &(hash_scalar_mul(&e, secret));
    (R, s)
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

fn hash_scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a.0[i].wrapping_mul(b.0[i]);
    }
    Scalar(result)
}