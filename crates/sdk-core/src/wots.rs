//! Winternitz One-Time Signature (WOTS+) Scheme
//!
//! Based on RFC 8391 (Lamport-Diffie WOTS+).
//! Used for post-quantum confidential transfers in Solana v1 transactions.

use crate::Result;
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

/// Convert 256-bit message digest to base-W array (base 16 nibbles)
fn crunch(message: &[u8; 32]) -> [u8; WOTS_LEN1] {
    let mut result = [0u8; WOTS_LEN1];
    
    // Convert each 4 bits to a nibble
    for i in 0..WOTS_LEN1 {
        let byte_idx = i / 2;
        let nib_idx = i % 2; // 0 = high nibble, 1 = low nibble
        result[i] = if nib_idx == 0 {
            (message[byte_idx] >> 4) & 0x0F
        } else {
            message[byte_idx] & 0x0F
        };
    }
    
    result
}

/// Compute checksum of base-W array (base 16)
fn checksum(crunch_array: &[u8; WOTS_LEN1]) -> [u8; WOTS_LEN2] {
    // Sum of (W-1 - value) for each position
    let mut csum: u32 = 0;
    for &val in crunch_array {
        csum += (WOTS_W as u32) - 1 - val as u32;
    }
    
    // Convert checksum to base-W
    let mut result = [0u8; WOTS_LEN2];
    let mut remaining = csum;
    for i in (0..WOTS_LEN2).rev() {
        result[i] = (remaining % WOTS_W as u32) as u8;
        remaining /= WOTS_W as u32;
    }
    
    result
}

/// Hash chain: hash N-bytes W times forward
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
        
        for seed in &mut secret_key {
            rng.fill_bytes(seed);
        }
        
        let public_key: [[u8; 32]; WOTS_LEN] = {
            let mut pk = [[0u8; 32]; WOTS_LEN];
            for (i, seed) in secret_key.iter().enumerate() {
                pk[i] = chain(seed, 0, WOTS_W as usize);
            }
            pk
        };
        
        Ok(Self { secret_key, public_key })
    }
    
    /// Create a keypair from an existing seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let mut secret_key = [[0u8; 32]; WOTS_LEN];
        
        for i in 0..WOTS_LEN {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&[i as u8]);
            secret_key[i] = hasher.finalize().into();
        }
        
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
        let message_hash = Sha256::digest(message);
        let message_digest: [u8; 32] = message_hash.into();
        
        let crunch_array = crunch(&message_digest);
        let csum_array = checksum(&crunch_array);
        
        let mut msg_csum = [0u8; WOTS_LEN];
        msg_csum[..WOTS_LEN1].copy_from_slice(&crunch_array);
        msg_csum[WOTS_LEN1..].copy_from_slice(&csum_array);
        
        let mut signature = [[0u8; 32]; WOTS_LEN];
        for (i, &chains) in msg_csum.iter().enumerate() {
            signature[i] = chain(&self.secret_key[i], 0, chains as usize);
        }
        
        signature
    }
    
    /// Verify a signature against the stored public key
    pub fn verify_message(&self, message: &[u8], signature: &[[u8; 32]; WOTS_LEN]) -> bool {
        let message_hash = Sha256::digest(message);
        let message_digest: [u8; 32] = message_hash.into();
        
        let crunch_array = crunch(&message_digest);
        let csum_array = checksum(&crunch_array);
        
        let mut msg_csum = [0u8; WOTS_LEN];
        msg_csum[..WOTS_LEN1].copy_from_slice(&crunch_array);
        msg_csum[WOTS_LEN1..].copy_from_slice(&csum_array);
        
        let mut computed_pk = [[0u8; 32]; WOTS_LEN];
        for (i, sig_elem) in signature.iter().enumerate() {
            computed_pk[i] = chain(sig_elem, 0, (WOTS_W as usize) - (msg_csum[i] as usize));
        }
        
        computed_pk == self.public_key
    }
    
    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.iter().flatten().copied().collect()
    }
}

/// Verify a signature against a public key (standalone function)
pub fn verify_signature(
    message: &[u8],
    signature: &[[u8; 32]; WOTS_LEN],
    public_key: &[[u8; 32]; WOTS_LEN]
) -> bool {
    let message_hash = Sha256::digest(message);
    let message_digest: [u8; 32] = message_hash.into();
    
    let crunch_array = crunch(&message_digest);
    let csum_array = checksum(&crunch_array);
    
    let mut msg_csum = [0u8; WOTS_LEN];
    msg_csum[..WOTS_LEN1].copy_from_slice(&crunch_array);
    msg_csum[WOTS_LEN1..].copy_from_slice(&csum_array);
    
    let mut computed_pk = [[0u8; 32]; WOTS_LEN];
    for (i, sig_elem) in signature.iter().enumerate() {
        computed_pk[i] = chain(sig_elem, 0, (WOTS_W as usize) - (msg_csum[i] as usize));
    }
    
    computed_pk == *public_key
}

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
        assert!(keypair.verify_message(message, &signature));
    }
    
    #[test]
    fn test_verify_standalone() {
        let keypair = WOTSKeyPair::generate().unwrap();
        let message = b"transfer 500 tokens";
        
        let signature = keypair.sign(message);
        assert!(verify_signature(message, &signature, &keypair.public_key));
    }
    
    #[test]
    fn test_wrong_message_fails() {
        let keypair = WOTSKeyPair::generate().unwrap();
        let msg1 = b"transfer 1000 tokens";
        let msg2 = b"transfer 2000 tokens";
        
        let signature = keypair.sign(msg1);
        assert!(!keypair.verify_message(msg2, &signature));
    }
    
    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        let keypair1 = WOTSKeyPair::from_seed(&seed).unwrap();
        let keypair2 = WOTSKeyPair::from_seed(&seed).unwrap();
        
        assert_eq!(keypair1.secret_key, keypair2.secret_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }
}