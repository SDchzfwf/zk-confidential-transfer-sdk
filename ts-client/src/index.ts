/**
 * ZK Confidential Transfer SDK - TypeScript Client
 * 
 * @see https://github.com/SDchzfwq/zk-confidential-transfer-sdk
 */

// Types
export {
    type ZkCtClientConfig,
    type TransactionConfig,
    type ConfidentialTransferData,
    type TransferResult,
    type TransferOptions,
    type ProofOptions,
    type BatchTransferOptions,
    type PedersenCommitment,
    type KZ1Proof,
    type V1Transaction,
    
    MAX_TRANSACTION_SIZE,
    MAX_ACCOUNTS,
    DEFAULT_COMPUTE_UNITS,
    DEFAULT_HEAP_FRAME,
    BASE_TRANSACTION_FEE,
} from './types';

// Main client and builder
export { ConfidentialTransferClient, V1TransactionBuilder } from './zk-transfer';

// Constants for convenience
export const SDK_VERSION = '1.0.0';
export const SVM_V1_SUPPORTED = true;