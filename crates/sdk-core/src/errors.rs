//! Error types for ZK Confidential Transfer SDK

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkCtError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureFailed(String),
    
    #[error("Transaction exceeds 4096 byte limit")]
    TransactionTooLarge,
    
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),
    
    #[error("Randomness error: {0}")]
    RandomnessError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Compute unit limit not set for v1 transaction")]
    MissingComputeLimit,
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),
    
    #[error("Account limit exceeded: {0}")]
    AccountLimitExceeded(String),
}

impl ZkCtError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self, ZkCtError::InvalidCommitment(_) | ZkCtError::MissingField(_))
    }
    
    /// Get error code for API responses
    pub fn code(&self) -> &'static str {
        match self {
            ZkCtError::InvalidProof(_) => "INVALID_PROOF",
            ZkCtError::SignatureFailed(_) => "SIGNATURE_FAILED",
            ZkCtError::TransactionTooLarge => "TX_TOO_LARGE",
            ZkCtError::InvalidCommitment(_) => "INVALID_COMMITMENT",
            ZkCtError::RandomnessError(_) => "RANDOMNESS_ERROR",
            ZkCtError::SerializationError(_) => "SERIALIZATION_ERROR",
            ZkCtError::MissingComputeLimit => "MISSING_COMPUTE_LIMIT",
            ZkCtError::MissingField(_) => "MISSING_FIELD",
            ZkCtError::InvalidRecipient(_) => "INVALID_RECIPIENT",
            ZkCtError::AccountLimitExceeded(_) => "ACCOUNT_LIMIT_EXCEEDED",
        }
    }
}

/// Type alias for Results with specific error type
pub type Result<T> = std::result::Result<T, ZkCtError>;