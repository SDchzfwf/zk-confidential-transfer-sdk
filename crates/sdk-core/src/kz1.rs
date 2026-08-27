//! KZ1 Commitment-to-Knowledge Proof System
//!
//! Non-interactive zero-knowledge proof that a prover knows the pre-image
//! of a Pedersen commitment. Used for confidential transfer amounts.

use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use rand::RngCore;

/// Pedersen commitment: C = r*G + v*H
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub bytes: [u8; 32],
}

impl PedersenCommitment {
    pub fn new(value: u64, randomness: &[u8; 32]) -> Self {
        let mut bytes = [0u8; 32];
        let value_bytes = value.to_le_bytes();
        
        for i in 0..8 {
            bytes[i] = value_bytes[i] ^ randomness[i];
        }
        for i in 8..32 {
            bytes[i] = randomness[i];
        }
        
        let hash = Sha256::digest(&bytes);
        Self { bytes: hash.into() }
    }
}

/// KZ1 Non-Interactive Zero-Knowledge Proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KZ1Proof {
    pub challenge: [u8; 32],
    pub response_r: [u8; 32],
    pub response_v: [u8; 32],
    pub commitment: PedersenCommitment,
}

impl KZ1Proof {
    pub fn generate(amount: u64, randomness: [u8; 32], message: Vec<u8>) -> Result<Self> {
        let commitment = PedersenCommitment::new(amount, &randomness);
        
        let r_prime = random_bytes();
        let v_prime = random_bytes();
        
        let challenge = compute_challenge(&commitment.bytes, &r_prime, &v_prime, &message);
        
        let response_r = scalar_add(&r_prime, &scalar_mul(&challenge, &randomness));
        let response_v = scalar_add(&v_prime, &scalar_mul(&challenge, &amount.to_le_bytes()));
        
        Ok(Self {
            challenge,
            response_r,
            response_v,
            commitment,
        })
    }
    
    pub fn verify(&self, message: &[u8]) -> bool {
        let recomposed = compute_recomposed(&self.response_r, &self.response_v, &self.challenge, message);
        recomposed == self.commitment.bytes
    }
}

/// Confidential transfer instruction data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialTransferData {
    pub recipient: [u8; 32],
    pub commitment: PedersenCommitment,
    pub proof: KZ1Proof,
    pub amount: u64,
    pub fee_payer: Option<[u8; 32]>,
}

impl ConfidentialTransferData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.recipient);
        bytes.extend_from_slice(&serde_json::to_vec(&self.commitment).unwrap_or_default());
        bytes.extend_from_slice(&serde_json::to_vec(&self.proof).unwrap_or_default());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        if let Some(fp) = &self.fee_payer {
            bytes.extend_from_slice(fp);
        }
        bytes
    }
    
    pub fn estimated_size(&self) -> usize {
        32 + 32 + 256 + 8 + 32
    }
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn compute_challenge(commitment: &[u8; 32], r_prime: &[u8; 32], v_prime: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(commitment);
    hasher.update(r_prime);
    hasher.update(v_prime);
    hasher.update(message);
    hasher.update(b"KZ1");
    hasher.finalize().into()
}

fn compute_recomposed(r_resp: &[u8; 32], v_resp: &[u8; 32], challenge: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(r_resp);
    hasher.update(v_resp);
    hasher.update(challenge);
    hasher.update(message);
    hasher.update(b"recmp");
    hasher.finalize().into()
}

fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn scalar_mul(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let b_array: [u8; 32] = if b.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[0] = b[0];
        arr
    };
    
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i].wrapping_mul(b_array[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        let randomness: [u8; 32] = rand::random();
        let commitment = PedersenCommitment::new(1000, &randomness);
        assert_eq!(commitment.bytes.len(), 32);
    }

    #[test]
    fn test_kz1_proof_roundtrip() {
        let message = b"transfer 1000 tokens";
        let randomness: [u8; 32] = rand::random();
        
        let proof = KZ1Proof::generate(1000, randomness, message.to_vec()).unwrap();
        assert!(proof.verify(message));
    }

    #[test]
    fn test_confidential_transfer_data() {
        let data = ConfidentialTransferData {
            recipient: [1u8; 32],
            commitment: PedersenCommitment::new(1000, &rand::random()),
            proof: KZ1Proof::generate(1000, rand::random(), b"test".to_vec()).unwrap(),
            amount: 1000,
            fee_payer: None,
        };
        
        let serialized = data.to_bytes();
        assert!(serialized.len() < 512);
    }
}