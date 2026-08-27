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

/// Program ID for confidential transfers (test ID)
pub const CONFIDENTIAL_TRANSFER_ID: Pubkey = Pubkey::new_from_array([
    69, 63, 78, 86, 90, 88, 86, 90, 86, 88, 86, 90, 86, 88, 86, 90,
    86, 78, 77, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66
]);

/// v1 Transaction configuration (SIMD-0385)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionConfig {
    pub compute_units: u32,
    pub loaded_accounts_data_size: u32,
    pub heap_frame: u32,
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
    
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }
    
    pub fn with_recipient(mut self, recipient: Pubkey) -> Self {
        self.recipient = Some(recipient);
        self
    }
    
    pub fn with_sender_keypair(mut self, keypair: &WOTSKeyPair) -> Self {
        self.sender_keypair = Some(keypair.clone());
        self
    }
    
    pub fn with_proof(mut self, proof: &KZ1Proof) -> Self {
        self.proof = Some(proof.clone());
        self
    }
    
    pub fn with_compute_units(mut self, units: u32) -> Self {
        self.config.compute_units = units;
        self
    }
    
    pub fn with_priority_fee(mut self, fee: u64) -> Self {
        self.config.priority_fee = fee;
        self
    }
    
    pub fn with_message(mut self, message: Vec<u8>) -> Self {
        self.message = Some(message);
        self
    }
    
    pub fn with_account(mut self, meta: AccountMeta) -> Self {
        self.accounts.push(meta);
        self
    }
    
    fn build_transfer_data(&self) -> Result<ConfidentialTransferData> {
        let amount = self.amount.ok_or(ZkCtError::InvalidProof("amount not set".into()))?;
        let recipient = self.recipient.ok_or_else(|| ZkCtError::InvalidProof("recipient not set".into()))?;
        let randomness = self.randomness.ok_or_else(|| ZkCtError::InvalidProof("randomness not set".into()))?;
        let message = self.message.clone().unwrap_or_default();
        
        let commitment = PedersenCommitment::new(amount, &randomness);
        let proof = self.proof.clone().unwrap_or_else(|| {
            KZ1Proof::generate(amount, randomness, message).expect("proof generation failed")
        });
        
        if proof.commitment != commitment {
            return Err(ZkCtError::InvalidProof("proof commitment mismatch".into()));
        }
        
        Ok(ConfidentialTransferData {
            recipient: recipient.to_bytes(),
            commitment,
            proof,
            amount,
            fee_payer: None,
        })
    }
    
    pub fn build(mut self) -> Result<V1Transaction> {
        if self.amount.is_some() && self.randomness.is_none() {
            self.randomness = Some(rand::random());
        }
        
        let transfer_data = self.build_transfer_data()?;
        
        let size = Self::estimate_size(&transfer_data, &self.accounts);
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
    
    fn estimate_size(data: &ConfidentialTransferData, accounts: &[AccountMeta]) -> usize {
        let tx_data_size = data.estimated_size();
        let accounts_size = accounts.len().min(MAX_ACCOUNTS) * 32;
        let overhead = 1 + 4 + 4 + 4 + 4 + 8;
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
    pub transfer_data: ConfidentialTransferData,
    pub config: TransactionConfig,
    pub accounts: Vec<AccountMeta>,
    pub size_limit: usize,
}

impl V1Transaction {
    pub fn size(&self) -> usize {
        ZkTransferTxBuilder::estimate_size(&self.transfer_data, &self.accounts)
    }
    
    pub fn is_valid_size(&self) -> bool {
        self.size() <= self.size_limit
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.push(0x81);
        
        let tx_data = self.transfer_data.to_bytes();
        bytes.extend_from_slice(&(tx_data.len() as u32).to_le_bytes());
        bytes.extend(tx_data);
        
        bytes.push(0x0F);
        
        bytes.extend_from_slice(&self.config.compute_units.to_le_bytes());
        bytes.extend_from_slice(&self.config.loaded_accounts_data_size.to_le_bytes());
        bytes.extend_from_slice(&self.config.heap_frame.to_le_bytes());
        bytes.extend_from_slice(&self.config.priority_fee.to_le_bytes());
        
        bytes
    }
    
    pub fn to_instruction(&self) -> Instruction {
        Instruction {
            program_id: CONFIDENTIAL_TRANSFER_ID,
            accounts: self.accounts.clone(),
            data: self.transfer_data.to_bytes(),
        }
    }
    
    pub fn estimate_gas(&self) -> u64 {
        let size_factor = (self.size() as f64 / 1024.0).max(1.0);
        (BASE_FEE as f64 * size_factor) as u64
    }
}

const BASE_FEE: u64 = 5000;

pub fn derive_sender_pubkey(commitment_bytes: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[commitment_bytes, b"sender"],
        &CONFIDENTIAL_TRANSFER_ID
    ).0
}