# ZK Confidential Transfer SDK

[![-solana-1.9.14](https://img.shields.io/badge/Solana-1.9.14-C90368?logo=solana)](https://solana.com)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-c51c2d?logo=rust)](https://www.rust-lang.org)
[![TypeScript](https://img.shields.io/badge/typescript-4.9%2B-3178c5?logo=typescript)](https://www.typescriptlang.org)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![version](https://img.shields.io/badge/version-1.0.0-007ec8)]

**Zero-Knowledge Confidential Transfers for Solana (v1 Transactions)**

A Rust + TypeScript SDK for building privacy-preserving applications on Solana using Winternitz one-time signatures and ZK proofs, enabled by the v1 transaction format upgrade.

---

## Why This SDK?

The Solana v1 transaction format ([SIMD-0385](https://simd.solana.com/simd-0385)) raises the maximum transaction size from **1,232 bytes to 4,096 bytes**. Combined with [SIMD-0296](https://simd.solana.com/simd-0296), this enables:

- **Winternitz one-time signatures** for post-quantum confidential transfers
- **Batch operations** with ZK proofs for privacy scaling
- **Onchain proof verification** without lookup tables

---

## Quick Install

```bash
# Rust
cargo add zk-ct-sdk

# TypeScript
npm install @zk-ct/sdk
```

---

## Architecture

```
zk-confidential-transfer-sdk/
├── crates/
│   ├── sdk-core/          # Core crypto primitives (WOTS, KZ1 proofs)
│   │   ├── src/wots.rs      # Winternitz one-time signature scheme
│   │   ├── src/kz1.rs       # KZ1 commitment-to-knowledge proof system
│   │   ├── src/schnorr.rs   # Schnorr/BLS12-381 primitives
│   │   └── Cargo.toml
│   └── cli/               # CLI tool for mint/transfer
│       └── src/main.rs
├── ts-client/             # TypeScript bindings (@solana/kit 8.0.0)
│   ├── src/zk-transfer.ts
│   ├── src/proof-client.ts
│   └── package.json
├── examples/              # Example applications
│   └── confidential-transfer.ts
└── tests/                 # Integration tests
    └── local-validator.ts
```

---

## Core Components

### 1. Winternitz One-Time Signature (WOTS)

Post-quantum signature scheme using SHA-256 chaining:

```rust
// 256-bit security parameter
const WOTS_PARAMS: usize = 16;  // base-16 chaining
const WOTS_SK_SIZE: usize = 64;   // 256 bits / log2(16)
```

### 2. KZ1 Proof System

Commitment-to-knowledge proofs for transfer amounts:

```typescript
interface KZ1Proof {
  commitment: PedersenCommitment;
  challenge: Scalar;
  response: Scalar;
}
```

### 3. v1 Transaction Builder

Builds 4KB transactions with ZK proofs inline using @solana/kit:

```typescript
const tx = await buildConfidentialTransfer({
  amount,
  recipient,
  proof,
  senderKeypair,
});
```

---

## Usage

### TypeScript

```typescript
import { ConfidentialTransferClient } from '@zk-ct/sdk';

const client = new ConfidentialTransferClient({
  rpcUrl: 'https://api.mainnet-beta.solana.com',
  payer: payerKeypair,
});

// Create confidential transfer
const transfer = await client.createTransfer({
  amount: 1000,
  recipient: recipientPubkey,
  proof: generateKZ1Proof(amount, randomness),
});

await transfer.send();
```

### Rust

```rust
use zk_ct_sdk::{ConfidentialTransfer, WOTSKeypair, KZ1Proof};

let keypair = WOTSKeypair::generate();
let proof = KZ1Proof::new(amount, secret_randomness);

let transfer = ConfidentialTransfer::builder()
    .amount(amount)
    .recipient(recipient_pubkey)
    .sender_keypair(&keypair)
    .proof(&proof)
    .build()?;

transfer.send(&client).await?;
```

### CLI

```bash
# Generate a WOTS keypair
zk-ct-cli keypair --output keypair.json

# Create a confidential transfer
zk-ct-cli transfer \
  --amount 1000 \
  --recipient <RECIPIENT_PUBKEY> \
  --keypair ./keypair.json \
  --proof ./proof.json
```

---

## Development

### Prerequisites

- Rust 1.75+ with wallet-tools feature
- Node.js 18+
- Solana CLI v4.2+ (for v1 transaction support)

### Local Testing

```bash
# Start local validator with v1 support
solana-test-validator --reset

# Run Rust tests
cargo test

# Run TypeScript tests
npm run test:integration
```

### Build

```bash
cargo build --release
npm run build
```

---

## Solana v1 Feature Support

| Feature | Status | Notes |
|---------|--------|-------|
| `@solana/kit` v8.0.0+ | ✅ | Full read/send support |
| `solana-*` Rust 4.2.x | ✅ | Build and send v1 transactions |
| Transaction size ≤ 4096 bytes | ✅ | Enforced at construction |
| Inline addresses | ✅ | Required for v1 flat format |
| Explicit compute limits | ✅ | Must set explicitly in v1 |

---

## Specification References

- [SIMD-0296](https://simd.solana.com/simd-0296) - Transaction size increase
- [SIMD-0385](https://simd.solana.com/simd-0385) - v1 transaction format
- [SOL-REC-2022-01](https://solana.com/sol-rec/sol-rec-2022-01) - Winternitz signatures

---

## Community

- **GitHub**: https://github.com/SDchzfwf/zk-confidential-transfer-sdk
- **X/Twitter**: https://x.com/SDchzfwf

---

## License

Apache-2.0 — research preview for confidential transfers on Solana.