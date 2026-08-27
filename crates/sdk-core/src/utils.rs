//! Utility functions for ZK Confidential Transfer SDK

use crate::{Result, ZkCtError};
use sha2::{Digest, Sha256};
use base64::Engine;

/// Serialize a value to hex string
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Parse hex string to bytes
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| ZkCtError::SerializationError(e.to_string()))
}

/// Serialize bytes to base64
pub fn to_base64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Parse base64 string to bytes
pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s)
        .map_err(|e| ZkCtError::SerializationError(e.to_string()))
}

/// Hash bytes using SHA-256
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Calculate transaction fee estimate
pub fn estimate_fee(size_bytes: usize, compute_units: u32) -> u64 {
    let base_fee = 5000u64;
    let size_component = ((size_bytes as f64 / 1024.0).max(1.0) * 1000.0) as u64;
    let cu_cost = ((compute_units as f64 * 0.001)) as u64;
    
    base_fee + size_component + cu_cost
}

/// Check if transaction fits in v1 limit
pub fn validate_v1_size(size: usize, limit: usize) -> Result<()> {
    if size > limit {
        Err(ZkCtError::TransactionTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let hex = to_hex(&data);
        let decoded = from_hex(&hex).unwrap();
        assert_eq!(decoded, data.to_vec());
    }

    #[test]
    fn test_sha256() {
        let input = b"test";
        let hash = sha256_hash(input);
        assert_eq!(hash.len(), 32);
    }
}