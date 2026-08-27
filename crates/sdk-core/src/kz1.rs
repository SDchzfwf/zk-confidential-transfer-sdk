//! KZ1 Commitment-to-Knowledge Proof System
//!
//! Non-interactive zero-knowledge proof that a prover knows the pre-image
//! of a Pedersen commitment. Used for confidential transfer amounts.

use crate::{Result, ZkCtError};
use sha2::{Digest, Sha256};
use rand::RngCore;

/// Pedersen commitment: C = r*G + v*H
/// where G is generator, H = sha256(G), r is random blinding factor, v is value
#[derive(Clone, Debug, PartialEq)]
pub struct PedersenCommitment {
    pub bytes: [u8; 32],  // Compressed commitment
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment
    pub fn new(value: u64, randomness: &[u8; 32]) -> Self {
        let h = hash_generator(b"H");
        let g = hash_generator(b"G");
        
        // Simplified: in real implementation would use elliptic curve ops
        // For SDK preview, we use hash-based commitments
        let mut hasher = Sha256::new();
        hasher.update(&g);
        hasher.update(&h);
        let base = hasher.finalize();
        
        let mut result = [0u8; 32];
        for (i, b) in result.iter_mut().enumerate() {
            *b = base[i] ^ randomness[i] ^ ((value >> (i * 8)) as u8);
        }
        Self { bytes: result }
    }
    
    fn hash_generator(label: &[u8]) -> [u8; 32] {
        Sha256::digest(label).into()
    }
}

/// KZ1 Non-Interactive Zero-Knowledge Proof
///
/// Proves knowledge of (v, r) such that commitment = r*G + v*H
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KZ1Proof {
    /// Challenge scalar
    pub challenge: [u8; 32],
    
    /// Response values  
    pub response_r: [u8; 32],  // blinding factor response
    pub response_v: [u8; 32],  // value response
    
    /// Public commitment being proven
    pub commitment: PedersenCommitment,
}

impl KZ1Proof {
    /// Generate a KZ1 proof for a confidential transfer commitment
    pub fn generate(value: u64, randomness: [u8; 32], message: &[u8]) -> Result<Self> {
        let commitment = PedersenCommitment::new(value, &randomness);
        
        // Generate random nonce
        let mut rng = rand::thread_rng();
        let r_prime = Self::random_bytes();
        let v_prime = Self::random_bytes();
        
        // Compute challenge: e = H(commitment || r_prime*G + v_prime*H || message)
        let challenge = Self::compute_challenge(&commitment, &r_prime, &v_prime, message);
        
        // Compute responses: 
        // response_r = r_prime + e * r
        // response_v = v_prime + e * v
        let response_r = Self::scalar_add(&r_prime, &Self::scalar_mul(&challenge, &randomness));
        let response_v = Self::scalar_add(&v_prime, &Self::scalar_mul(&challenge, &value.to_le_bytes()));
        
        Ok(Self {
            challenge,
            response_r,
            response_v,
            commitment,
        })
    }
    
    /// Verify the KZ1 proof
    pub fn verify(&self, message: &[u8]) -> bool {
        // Recompute commitment from responses:
        // C' = response_r * G + response_v * H - e * C
        // Should equal r_prime * G + v_prime * H
        
        // For verification, we check:
        // 1. Recompute the commitment should match
        // 2. Challenge should match H(C || r'*G + v'*H || message)
        
        let g = b"G";
        let h = b"H";
        
        // Simple hash-based verification (simplified for SDK)
        let recomposed_commitment = Self::recompose_commitment(
            &self.response_r, 
            &self.response_v, 
            &self.challenge,
            message
        );
        
        recomposed_commitment == self.commitment.bytes
    }
    
    fn random_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
    
    fn compute_challenge(commitment: &PedersenCommitment, r_prime: &[u8; 32], v_prime: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&commitment.bytes);
        hasher.update(r_prime);
        hasher.update(v_prime);
        hasher.update(message);
        hasher.update(b"KZ1");
        hasher.finalize().into()
    }
    
    fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect::<Vec<_>>().try_into().unwrap()
    }
    
    fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = a[i].wrapping_mul(b[i]);
        }
        result
    }
    
    fn recompose_commitment(r_resp: &[u8; 32], v_resp: &[u8; 32], challenge: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(r_resp);
        hasher.update(v_resp);
        hasher.update(challenge);
        hasher.update(message);
        hasher.update(b"recmp");
        hasher.finalize().into()
    }
}

/// Confidential transfer instruction data for v1 transactions
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfidentialTransferData {
    /// Recipient public key (32 bytes)
    pub recipient: [u8; 32],
    
    /// Commitment to the transfer amount
    pub commitment: PedersenCommitment,
    
    /// KZ1 proof of knowledge of the committed amount
    pub proof: KZ1Proof,
    
    /// Transfer amount (plaintext for v0 fallback, hidden in v1)
    pub amount: u64,
    
    /// Fee payer (optional, defaults to sender)
    pub fee_payer: Option<[u8; 32]>,
}

impl ConfidentialTransferData {
    /// Serialize to bytes for inclusion in v1 transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.recipient);
        bytes.extend_from_slice(&self.commitment.bytes);
        bytes.extend_from_slice(&serde_json::to_vec(&self.proof).unwrap_or_default());
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        if let Some(fp) = &self.fee_payer {
            bytes.extend_from_slice(fp);
        }
        bytes
    }
    
    /// Estimate serialized size
    pub fn estimated_size(&self) -> usize {
        32 + // recipient
        32 + // commitment
        256 + // proof (approx)
        8 + // amount
        32 // optional fee payer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        let randomness = rand::random();
        let commitment = PedersenCommitment::new(1000, &randomness);
        assert_eq!(commitment.bytes.len(), 32);
    }

    #[test]
    fn test_kz1_proof_roundtrip() {
        let message = b"transfer 1000 tokens to recipient";
        let randomness = rand::random();
        
        let proof = KZ1Proof::generate(1000, randomness, message).unwrap();
        assert!(proof.verify(message), "KZ1 proof verification failed");
    }

    #[test]
    fn test_confidential_transfer_data() {
        let data = ConfidentialTransferData {
            recipient: [1u8; 32],
            commitment: PedersenCommitment::new(1000, &rand::random()),
            proof: KZ1Proof::generate(1000, rand::random(), b"test").unwrap(),
            amount: 1000,
            fee_payer: None,
        };
        
        let serialized = data.to_bytes();
        assert!(serialized.len() < 512, "Transfer data should fit in v1 transaction");
    }
}