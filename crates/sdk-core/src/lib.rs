//! ZK Confidential Transfer SDK for Solana v1 transactions
//!
//! Provides post-quantum confidential transfers using Winternitz one-time
//! signatures and KZ1 commitment-to-knowledge proofs.

pub mod wots;
pub mod kz1;
pub mod schnorr;
pub mod proof;
pub mod transaction;
pub mod errors;
pub mod utils;

// Re-exports
pub use errors::{ZkCtError, Result};
pub use wots::WOTSKeyPair;
pub use kz1::{KZ1Proof, PedersenCommitment, ConfidentialTransferData};
pub use transaction::{ZkTransferTxBuilder, V1Transaction};
pub use proof::ProofGenerator;

/// Constants for Winternitz one-time signatures (WOTS+ with W=16)
pub const WOTS_PARAM: u8 = 16;        // base for chains
pub const WOTS_LOG_W: u8 = 4;         // log_2(16)
pub const WOTS_N: usize = 32;         // 256-bit hash output
pub const WOTS_K: usize = 256;         // message digest bits

/// WOTS+ length calculations:
/// len_1 = ceil(K / log_w) = ceil(256 / 4) = 64
/// len_2 = floor(log_2(len_1) / log_2(W-1)) ≈ 2
/// len = len_1 + len_2 = 66
pub const WOTS_LEN1: usize = 64;
pub const WOTS_LEN2: usize = 2;
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
pub const WOTS_SK_LEN: usize = WOTS_LEN * WOTS_N;   // 2112 bytes
pub const WOTS_PK_LEN: usize = WOTS_LEN * WOTS_N;   // 2112 bytes
pub const WOTS_SIG_LEN: usize = WOTS_LEN * WOTS_N;  // 2112 bytes

/// Maximum transaction size for v1 format (SIMD-0385)
pub const MAX_TRANSACTION_SIZE: usize = 4096;