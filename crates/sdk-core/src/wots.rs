//! Winternitz One-Time Signature (WOTS+) Scheme
//!
//! Based on RFC 8391 (Lamport-Diffie WOTS+).
//! Used for post-quantum confidential transfers in Solana v1 transactions.

use crate::{Result, ZkCtError};
use sha2::{Digest, Sha256};
use rand::RngCore;

/// W = 16 (base for chains, 2^4 = 16)
/// Using base-16 chains for efficient signing
pub const WOTS_LOG_W: usize = 4;  // log_2(16) = 4
pub const WOTS_W: u8 = 16;        // 16-chains

/// Hash function output length for SHA-256
pub const WOTS_N: usize = 32;     // 256 bits = 32 bytes

/// Message digest length in bits (256 for SHA-256)
pub const WOTS_K: usize = 256;

/// Length of message representation in base-W
/// len1 = ceil(K / log_w) = ceil(256 / 4) = 64
pub const WOTS_LEN1: usize = 64;

/// Length of checksum representation in base-W
/// len2 = floor(log_w(len1) / log_w(W-1)) ≈ 2
/// For len1=64, w=16: checksum max = 64*15 = 960, log_w(960) ≈ 2.8
/// len2 = ceil(2.8 / 4) = 1 (simplified)
pub const WOTS_LEN2: usize = 2;

/// Total chain length
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;  // 66

/// Secret key length: LEN chains of N-byte values
pub const WOTS_SK_LEN: usize = WOTS_LEN * WOTS_N;

/// Public key length: LEN N-byte values
pub const WOTS_PK_LEN: usize = WOTS_LEN * WOTS_N;

/// Signature length: LEN N-byte values
pub const WOTS_SIG_LEN: usize = WOTS_LEN * WOTS_N;

/// Convert a single number to base-W representation (W=16, returns 16 values)
fn to_base_w(value: u64, w_power: usize, result: &mut [u8]) {
    for i in (0..w_power).rev() {
        let divisor = 16u64.pow(i as u32);
        result[w_power - 1 - i] = (value / divisor) as u8;
    }
}

/// Convert 256-bit message digest to base-W array
fn crunch(message: &[u8; 32]) -> [u8; WOTS_LEN1] {
    let mut crunch_array = [0u8; WOTS_LEN1];
    
    // Process 4 bits at a time from the message
    let message_bits: u64 = {
        let mut bits = 0u64;
        for (i, &byte) in message.iter().enumerate() {
            bits |= (byte as u64) << (i * 8);
        }
        bits
    };
    
    // Convert to base-16 (nibbles)
    for i in 0..WOTS_LEN1 {
        crunch_array[i] = ((message_bits >> (i * 4)) & 0xF) as u8;
    }
    
    crunch_array
}

/// Compute checksum of base-W array
fn checksum(crunch_array: &[u8; WOTS_LEN1]) -> [u8; WOTS_LEN2] {
    let mut csum: u64 = 0;
    for &val in crunch_array {
        csum += (WOTS_W - 1 - val) as u64;
    }
    
    let mut checksum_array = [0u8; WOTS_LEN2];
    to_base_w(csum, WOTS_LEN2, &mut checksum_array);
    checksum_array
}

/// Hash chain: hash N-bytes W times
fn chain(data: &[u8; 32], start: usize, stop: usize) -> [u8; 32] {
    if start >= stop {
        return *data;
    }
    
    let mut result = *data;
    for _ in start..stop {
        result = Sha256::digest(&result).into();
    }
    result
}

/// Winternitz One-Time Signature Keypair
#[derive(Clone, Debug)]
pub struct WOTSKeyPair {
    /// Secret key: array of WOTS_LEN chain seeds
    pub secret_key: [[u8; 32]; WOTS_LEN],
    
    /// Public key: array of chain endpoints
    pub public_key: [[u8; 32]; WOTS_LEN],
}

impl WOTSKeyPair {
    /// Generate a new random WOTS+ keypair
    pub fn generate() -> Result<Self> {
        let mut secret_key = [[0u8; 32]; WOTS_LEN];
        let mut rng = rand::thread_rng();
        
        // Fill secret key with random values
        for seed in &mut secret_key {
            rng.fill_bytes(seed);
        }
        
        // Compute public key: advance each chain by W=16 steps
        let public_key: [[u8; 32]; WOTS_LEN] = {
            let mut pk = [[0u8; 32]; WOTS_LEN];
            for (i, seed) in secret_key.iter().enumerate() {
                pk[i] = chain(seed, 0, WOTS_W as usize);
            }
            pk
        };
        
        Ok(Self { secret_key, public_key })
    }
    
    /// Create a keypair from an existing seed (for deterministic generation)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Derive WOTS_LEN secret key elements from seed
        let mut secret_key = [[0u8; 32]; WOTS_LEN];
        for i in 0..WOTS_LEN {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&[i as u8; 1]);
            secret_key[i] = hasher.finalize().into();
        }
        
        // Compute public key
        let public_key: [[u8; 32]; WOTS_LEN] = {
            let mut pk = [[0u8; 32]; WOTS_LEN];
            for (i, seed) in secret_key.iter().enumerate() {
                pk[i] = chain(seed, 0, WOTS_W as usize);
            }
            pk
        };
        
        Ok(Self { secret_key, public_key })
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [[u8; 32]; WOTS_LEN] {
        // Hash the message to 256 bits
        let message_hash = Sha256::digest(message);
        let message_digest: [u8; 32] = message_hash.into();
        
        // Convert to base-W
        let crunch_array = crunch(&message_digest);
        
        // Compute checksum
        let csum_array = checksum(&crunch_array);
        
        // Build message+checksum array
        let msg_csum: [u8; WOTS_LEN] = {
            let mut combined = [0u8; WOTS_LEN];
            combined[..WOTS_LEN1].copy_from_slice(&crunch_array);
            combined[WOTS_LEN1..].copy_from_slice(&csum_array);
            combined
        };
        
        // Build signature: for each position, hash the seed forward by the value
        let mut signature = [[0u8; 32]; WOTS_LEN];
        for (i, &chains) in msg_csum.iter().enumerate() {
            signature[i] = chain(&self.secret_key[i], 0, chains as usize);
        }
        
        signature
    }
    
    /// Verify a signature
    pub fn verify(message: &[u8], signature: &[[u8; 32]; WOTS_LEN]) -> bool {
        // Compute public key from signature
        let mut computed_pk = [[0u8; 32]; WOTS_LEN];
        
        // Hash the message
        let message_hash = Sha256::digest(message);
        let message_digest: [u8; 32] = message_hash.into();
        
        // Convert to base-W
        let crunch_array = crunch(&message_digest);
        let csum_array = checksum(&crunch_array);
        
        let msg_csum: [u8; WOTS_LEN] = {
            let mut combined = [0u8; WOTS_LEN];
            combined[..WOTS_LEN1].copy_from_slice(&crunch_array);
            combined[WOTS_LEN1..].copy_from_slice(&csum_array);
            combined
        };
        
        // For each signature element, chain forward (W - value) times
        for (i, sig_elem) in signature.iter().enumerate() {
            computed_pk[i] = chain(sig_elem, 0, (WOTS_W - msg_csum[i]) as usize);
        }
        
        // Compare with stored public key
        computed_pk == self.public_key
    }
    
    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.iter().flatten().copied().collect()
    }
}

/// Public key bytes
pub type PublicKeyBytes = [u8; WOTS_PK_LEN];

/// Secret key bytes  
pub type SecretKeyBytes = [u8; WOTS_SK_LEN];

/// Signature bytes
pub type SignatureBytes = [[u8; 32]; WOTS_LEN];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = WOTSKeyPair::generate().unwrap();
        assert_eq!(keypair.secret_key.len(), WOTS_LEN);
        assert_eq!(keypair.public_key.len(), WOTS_LEN);
    }
    
    #[test]
    fn test_sign_verify() {
        let keypair = WOTSKeyPair::generate().unwrap();
        let message = b"confidential transfer: 1000 tokens";
        
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));
    }
    
    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = WOTSKeyPair::generate().unwrap();
        let message1 = b"transfer 1000 tokens";
        let message2 = b"transfer 2000 tokens";
        
        let signature = keypair.sign(message1);
        assert!(!keypair.verify(message2, &signature));
    }
    
    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        let keypair1 = WOTSKeyPair::from_seed(&seed).unwrap();
        let keypair2 = WOTSKeyPair::from_seed(&seed).unwrap();
        
        assert_eq!(keypair1.secret_key, keypair2.secret_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }
    
    #[test]
    fn test_signature_size() {
        assert_eq!(WOTS_SIG_LEN, 66 * 32); // 2112 bytes
        assert_eq!(WOTS_PK_LEN, 66 * 32);  // 2112 bytes
    }
}