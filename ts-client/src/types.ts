/**
 * Types for ZK Confidential Transfer SDK
 * 
 * TypeScript implementation leveraging @solana/kit v8.0.0 for v1 transactions
 */

import type { 
    Address, 
    SecretKey, 
    PublicKey, 
    TransactionMeta 
} from '@solana/kit';

// ============================================================================
// Core Crypto Types
// ============================================================================

/** Winternitz One-Time Signature Keypair */
export interface WOTSKeypair {
    /** 32-byte secret key (actual secret is 67 bytes, split into 67 chains of 32 bits each) */
    secretKey: Uint8Array;
    
    /** 32-byte public key (hash of all chains advanced W=16 times) */
    publicKey: Uint8Array;
}

/** Pedersen Commitment to a confidential value */
export interface PedersenCommitment {
    /** 32-byte commitment C = r*G + v*H */
    commitment: Uint8Array;
}

/** KZ1 Commitment-to-Knowledge Proof */
export interface KZ1Proof {
    /** Challenge scalar (32 bytes) */
    challenge: Uint8Array;
    
    /** Response blinding factor (32 bytes) */
    responseR: Uint8Array;
    
    /** Response value (32 bytes) */
    responseV: Uint8Array;
    
    /** Public commitment being proven */
    commitment: PedersenCommitment;
}

// ============================================================================
// Transaction Types
// ============================================================================

/** v1 Transaction Configuration (SIMD-0385) */
export interface TransactionConfig {
    /** Compute unit limit - REQUIRED for v1 transactions */
    computeUnits: number;
    
    /** Loaded accounts data size limit */
    loadedAccountsDataSize?: number;
    
    /** Heap frame size in bytes */
    heapFrame?: number;
    
    /** Priority fee in micro-lamports */
    priorityFee?: number;
    
    /** Authorization seed for PDA derivation */
    seed?: string;
}

/** Confidential Transfer Instruction Data */
export interface ConfidentialTransferData {
    /** Recipient public key */
    recipient: Address;
    
    /** Commitment to the transfer amount */
    commitment: PedersenCommitment;
    
    /** KZ1 proof of knowledge of the committed amount */
    proof: KZ1Proof;
    
    /** Transfer amount (in lamports) */
    amount: bigint;
    
    /** Optional fee payer */
    feePayer?: Address;
}

/** v1 Transaction wrapper */
export interface V1Transaction {
    /** Transfer data */
    transferData: ConfidentialTransferData;
    
    /** Transaction configuration */
    config: TransactionConfig;
    
    /** Maximum transaction size (4096 bytes) */
    sizeLimit: number;
}

// ============================================================================
// Client Types
// ============================================================================

/** Client configuration */
export interface ZkCtClientConfig {
    /** RPC URL for Solana cluster */
    rpcUrl: string;
    
    /** Fee payer keypair */
    payer: SecretKey | PublicKey;
    
    /** Commitment level */
    commitment?: 'processed' | 'confirmed' | 'finalized';
}

/** Transfer options */
export interface TransferOptions {
    /** Compute units for v1 transaction */
    computeUnits?: number;
    
    /** Priority fee (micro-lamports) */
    priorityFee?: bigint;
    
    /** Additional signers for multisig */
    additionalSigners?: Array<{
        address: Address;
        weight?: number;
    }>;
}

/** Transfer result */
export interface TransferResult {
    /** Transaction signature */
    signature: string;
    
    /** Transaction hash */
    hash: string;
    
    /** Block time (if confirmed) */
    blockTime?: number;
    
    /** Slot (if confirmed) */
    slot?: number;
    
    /** Transaction meta */
    meta?: TransactionMeta;
}

/** Proof generation options */
export interface ProofOptions {
    /** Transfer amount */
    amount: bigint;
    
    /** Message to commit to */
    message?: string;
    
    /** Custom randomness (for testing) */
    randomness?: Uint8Array;
}

/** Batch transfer options */
export interface BatchTransferOptions {
    /** List of transfer amounts */
    amounts: bigint[];
    
    /** Corresponding messages */
    messages?: string[];
}

// ============================================================================
// Solana Constants
// ============================================================================

/** Maximum transaction size for v1 format (SIMD-0385) */
export const MAX_TRANSACTION_SIZE = 4096;

/** Maximum accounts per v1 transaction */
export const MAX_ACCOUNTS = 64;

/** Default compute units for confidential transfer */
export const DEFAULT_COMPUTE_UNITS = 200_000;

/** Default heap frame size */
export const DEFAULT_HEAP_FRAME = 32_768;

/** Base transaction fee (lamports) */
export const BASE_TRANSACTION_FEE = 5000;

// ============================================================================
// Type Guards
// ============================================================================

export function isValidAddress(address: unknown): address is Address {
    return typeof address === 'string' && address.length === 44;
}

export function isValidV1Transaction(tx: V1Transaction): boolean {
    return tx.size() <= MAX_TRANSACTION_SIZE;
}