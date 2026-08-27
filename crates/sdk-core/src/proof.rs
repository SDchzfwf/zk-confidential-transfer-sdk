//! Proof types and generation for ZK Confidential Transfers

use crate::{Result, PedersenCommitment, KZ1Proof};

/// Proof generator for confidential transfers
pub struct ProofGenerator {
    message: Vec<u8>,
    amount: u64,
}

impl ProofGenerator {
    /// Create a new proof generator
    pub fn new(amount: u64, message: &[u8]) -> Self {
        Self {
            message: message.to_vec(),
            amount,
        }
    }
    
    /// Generate complete confidential transfer setup
    pub fn generate(&self) -> Result<(PedersenCommitment, KZ1Proof, [u8; 32])> {
        // Generate randomness
        let randomness: [u8; 32] = rand::random();
        
        // Create commitment
        let commitment = PedersenCommitment::new(self.amount, &randomness);
        
        // Generate KZ1 proof
        let proof = KZ1Proof::generate(self.amount, randomness, self.message.clone())?;
        
        Ok((commitment, proof, randomness))
    }
}

/// Batch proof generation for multiple transfers
pub struct BatchProofGenerator {
    transfers: Vec<(u64, Vec<u8>)>, // (amount, message) pairs
}

impl BatchProofGenerator {
    pub fn new() -> Self {
        Self { transfers: Vec::new() }
    }
    
    pub fn add_transfer(&mut self, amount: u64, message: &[u8]) {
        self.transfers.push((amount, message.to_vec()));
    }
    
    pub fn generate_all(&self) -> Result<Vec<(PedersenCommitment, KZ1Proof, [u8; 32])>> {
        self.transfers
            .iter()
            .map(|(amount, msg)| {
                ProofGenerator::new(*amount, msg).generate()
            })
            .collect()
    }
}

impl Default for BatchProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}