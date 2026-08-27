//! v1 Transaction Builder for Solana
//!
//! Builds confidential transfer transactions compatible with SIMD-0385 v1 format.

use crate::{Result, ZkCtError, MAX_TRANSACTION_SIZE, WOTSKeyPair, KZ1Proof, ConfidentialTransferData, PedersenCommitment};
use solana_program::{
    pubkey::Pubkey,
    instruction::{Instruction, AccountMeta},
};
use rand;

/// Maximum accounts in a v1 transaction
pub const MAX_ACCOUNTS: usize = 64;

/// Compute unit limits for v1 transactions
const DEFAULT_COMPUTE_UNITS: u32 = 200_000;
const DEFAULT_HEAP_FRAME: u32 = 32_768;
const DEFAULT_LOADED_DATA_SIZE: u32 = 0;

/// v1 Transaction configuration (SIMD-0385)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionConfig {
    /// Compute unit limit - REQUIRED for v1
    pub compute_units: u32,
    
    /// Loaded accounts data size limit
    pub loaded_accounts_data_size: u32,
    
    /// Heap frame size
    pub heap_frame: u32,
    
    /// Priority fee in micro-lamports
    pub priority_fee: u64,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            compute_units: DEFAULT_COMPUTE_UNITS,
            loaded_accounts_data_size: DEFAULT_LOADED_DATA_SIZE,
            heap_frame: DEFAULT_HEAP_FRAME,
            priority_fee: 0,
        }
    }
}

/// Builder for v1 confidential transfer transactions
pub struct ZkTransferTxBuilder {
    amount: Option<u64>,
    recipient: Option<Pubkey>,
    sender_keypair: Option<WOTSKeyPair>,
    proof: Option<KZ1Proof>,
    config: TransactionConfig,
    accounts: Vec<AccountMeta>,
    randomness: Option<[u8; 32]>,
    message: Option<Vec<u8>>,
}

impl ZkTransferTxBuilder {
    /// Create a new builder
   pub fn new() -> Self {
        Self {
            amount: None,
            recipient: None,
            sender_keypair: None,
            proof: None,
            config: TransactionConfig::default(),
            accounts: Vec::new(),
            randomness: None,
            message: None,
        }
    }
    
    /// Set the transfer amount
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }
    
    /// Set recipient public key
    pub fn with_recipient(mut self, recipient: Pubkey) -> Self {
        self.recipient = Some(recipient);
        self
    }
    
    /// Set sender's WOTS keypair
    pub fn with_sender_keypair(mut self, keypair: &WOTSKeyPair) -> Self {
        self.sender_keypair = Some(keypair.clone());
        self
    }
    
    /// Set the KZ1 proof
    pub fn with_proof(mut self, proof: &KZ1Proof) -> Self {
        self.proof = Some(proof.clone());
        self
    }
    
    /// Set compute unit limit (REQUIRED for v1 transactions)
    pub fn with_compute_units(mut self, units: u32) -> Self {
        self.config.compute_units = units;
        self
    }
    
    /// Set priority fee
    pub fn with_priority_fee(mut self, fee: u64) -> Self {
        self.config.priority_fee = fee;
        self
    }
    
    /// Set the message being transferred
    pub fn with_message(mut self, message: Vec<u8>) -> Self {
        self.message = Some(message);
        self
    }
    
    /// Add an account to the transaction
    pub fn with_account(mut self, meta: AccountMeta) -> Self {
        self.accounts.push(meta);
        self
    }
    
    /// Build the confidential transfer data
    fn build_transfer_data(&self) -> Result<ConfidentialTransferData> {
        let amount = self.amount.ok_or(ZkCtError::InvalidProof("amount not set".into()))?;
        let recipient = self.recipient.ok_or_else(|| ZkCtError::InvalidProof("recipient not set".into()))?;
        let randomization = self.randomness.ok_or_else(|| ZkCtError::InvalidProof("randomness not set".into()))?;
        let message = self.message.as_deref().unwrap_or(&[]);
        
        // Generate commitment and proof if not provided
        let commitment = PedersenCommitment::new(amount, &randomization);
        let proof = self.proof.as_ref().unwrap_or_else(|| {
            // Generate in place - simplified for this example
            &KZ1Proof::generate(amount, randomization, message).unwrap()
        });
        
        // Verify commitment matches proof
        if proof.commitment != commitment {
            return Err(ZkCtError::InvalidProof("proof commitment mismatch".into()));
        }
        
        Ok(ConfidentialTransferData {
            recipient: recipient.to_bytes(),
            commitment,
            proof: proof.clone(),
            amount,
            fee_payer: None,
        })
    }
    
    /// Build the v1 transaction
    pub fn build(mut self) -> Result<V1Transaction> {
        // Generate randomness if not provided
        if self.amount.is_some() && self.randomness.is_none() {
            self.randomness = Some(rand::random());
        }
        
        let transfer_data = self.build_transfer_data()?;
        
        // Check size limit
        let size = Self::estimate_size(&transfer_data, &self.accounts, &self.config);
        if size > MAX_TRANSACTION_SIZE {
            return Err(ZkCtError::TransactionTooLarge);
        }
        
        Ok(V1Transaction {
            transfer_data,
            config: self.config,
            accounts: self.accounts,
            size_limit: MAX_TRANSACTION_SIZE,
        })
    }
    
    /// Estimate transaction size
    fn estimate_size(data: &ConfidentialTransferData, accounts: &[AccountMeta], config: &TransactionConfig) -> usize {
        let tx_data_size = data.estimated_size();
        let accounts_size = accounts.len().min(MAX_ACCOUNTS) * 32;
        
        // v1 format overhead
        let overhead = 1 +      // discriminator
            4 +                 // data length
            4 +                 // mask
            4 + 4 + 4 + 8;      // config values
        
        overhead + tx_data_size + accounts_size
    }
}

impl Default for ZkTransferTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A v1 confidential transfer transaction
#[derive(Clone, Debug)]
pub struct V1Transaction {
    /// Transfer data
    pub transfer_data: ConfidentialTransferData,
    
    /// Transaction configuration
    pub config: TransactionConfig,
    
    /// Additional accounts
    pub accounts: Vec<AccountMeta>,
    
    /// Maximum transaction size
    pub size_limit: usize,
}

impl V1Transaction {
    /// Get transaction size in bytes
    pub fn size(&self) -> usize {
        ZkTransferTxBuilder::estimate_size(&self.transfer_data, &self.accounts, &self.config)
    }
    
    /// Check if transaction fits in v1 limit
    pub fn is_valid_size(&self) -> bool {
        self.size() <= self.size_limit
    }
    
    /// Serialize for v1 wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // v1 discriminator (0x81)
        bytes.push(0x81);
        
        // Transfer data length
        let tx_data = self.transfer_data.to_bytes();
        let len_bytes = u32::to_le_bytes(tx_data.len() as u32);
        bytes.extend_from_slice(&len_bytes);
        bytes.extend(tx_data);
        
        // Config mask (all fields present)
        bytes.push(0x0F);
        
        // Config values
        bytes.extend_from_slice(&u32::to_le_bytes(self.config.compute_units));
        bytes.extend_from_slice(&u32::to_le_bytes(self.config.loaded_accounts_data_size));
        bytes.extend_from_slice(&u32::to_le_bytes(self.config.heap_frame));
        bytes.extend_from_slice(&u64::to_le_bytes(self.config.priority_fee));
        
        bytes
    }
    
    /// Create Solana Instruction for confidential transfer program
    pub fn to_instruction(&self) -> Instruction {
        let program_id = PUBLIC_TRANSFER_PROGRAM_ID;
        
        Instruction {
            program_id,
            accounts: self.accounts.clone(),
            data: self.transfer_data.to_bytes(),
        }
    }
    
    /// Estimate gas fee
    pub fn estimate_gas(&self) -> u64 {
        let size_factor = (self.size() as f64 / 1024.0).max(1.0);
        (BASE_FEE as f64 * size_factor) as u64
    }
}

const PUBLIC_TRANSFER_PROGRAM_ID: Pubkey = pubkey!("ConfTransfer111111111111111111111111");
const BASE_FEE: u64 = 5000;

/// Derive sender pubkey from commitment
pub fn derive_sender_pubkey(commitment_bytes: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[commitment_bytes, b"sender"],
        &PUBLIC_TRANSFER_PROGRAM_ID
    ).0
}

/// Create a Pedersen commitment (helper for standalone use)
impl PedersenCommitment {
    pub fn create(amount: u64, randomness: &[u8; 32]) -> Self {
        Self::new(amount, randomness)
    }
}