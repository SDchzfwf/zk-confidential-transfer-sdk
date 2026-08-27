//! WOTS Key Pair CLI Tool
//!
//! Demonstrates Winternitz One-Time Signature generation, signing, and verification.
//! Run with: cargo run --example wots-cli

use std::env;
use std::fs;
use std::path::PathBuf;

const PUBKEY_PATH: &str = "wots_pubkey.json";
const SECRETKEY_PATH: &str = "wots_secret.json";
const SIGNATURE_PATH: &str = "wots_signature.json";

const CHAINS: usize = 66;
const BYTES_PER_CHAIN: usize = 32;
const SIGNATURE_BYTES: usize = CHAINS * BYTES_PER_CHAIN;

fn hex_print(label: &str, data: &[u8]) {
    println!("{}: {}", label, hex::encode(data));
}

fn load_or_create_keypair() -> Result<zk_ct_sdk::WOTSKeyPair, zk_ct_sdk::ZkCtError> {
    let pubkey_path = PathBuf::from(PUBKEY_PATH);
    let secret_path = PathBuf::from(SECRETKEY_PATH);
    
    if pubkey_path.exists() && secret_path.exists() {
        println!("⚠️  Keypair already exists. Delete {} and {} to generate new keypair", 
            PUBKEY_PATH, SECRETKEY_PATH);
        
        let secret_str = fs::read_to_string(&secret_path).map_err(|e| {
            zk_ct_sdk::ZkCtError::SerializationError(e.to_string())
        })?;
        let pubkey_str = fs::read_to_string(&pubkey_path).map_err(|e| {
            zk_ct_sdk::ZkCtError::SerializationError(e.to_string())
        })?;
        
        let secret_bytes: Vec<u8> = hex::decode(secret_str.trim()).map_err(|e| {
            zk_ct_sdk::ZkCtError::SerializationError(e.to_string())
        })?;
        let pubkey_bytes: Vec<u8> = hex::decode(pubkey_str.trim()).map_err(|e| {
            zk_ct_sdk::ZkCtError::SerializationError(e.to_string())
        })?;
        
        let secret_key: [[u8; 32]; 66] = {
            let mut arr = [[0u8; 32]; 66];
            let flat: [u8; 2112] = secret_bytes.try_into().map_err(|_| {
                zk_ct_sdk::ZkCtError::InvalidCommitment("Invalid secret key length".to_string())
            })?;
            arr.copy_from_slice(&flat);
            arr
        };
        
        let public_key: [[u8; 32]; 66] = {
            let mut arr = [[0u8; 32]; 66];
            let flat: [u8; 2112] = pubkey_bytes.try_into().map_err(|_| {
                zk_ct_sdk::ZkCtError::InvalidCommitment("Invalid public key length".to_string())
            })?;
            arr.copy_from_slice(&flat);
            arr
        };
        
        return Ok(zk_ct_sdk::WOTSKeyPair { secret_key, public_key });
    }
    
    // Generate new keypair
    let keypair = zk_ct_sdk::WOTSKeyPair::generate()?;
    
    // Save keys
    fs::write(SECRETKEY_PATH, hex::encode(&keypair.secret_key)).ok();
    fs::write(PUBKEY_PATH, hex::encode(&keypair.public_key)).ok();
    
    println!("✅ Generated new WOTS+ keypair:");
    println!("   Secret key: {} (saved to {})", SECRETKEY_PATH, SECRETKEY_PATH);
    println!("   Public key: {} (saved to {})", PUBKEY_PATH, PUBKEY_PATH);
    
    Ok(keypair)
}

fn cmd_generate() {
    println!("🔐 Winternitz One-Time Signature (WOTS+) Key Generation");
    println!("=========================================================\n");
    
    match load_or_create_keypair() {
        Ok(keypair) => {
            println!("\n📊 Public Key ({} bytes):", SIGNATURE_BYTES);
            hex_print("   ", &keypair.public_key_bytes());
            
            println!("\n🔑 Secret Key ({} bytes):", SECRET_BYTES);
            println!("   (saved to {}) - DO NOT SHARE", SECRETKEY_PATH);
            
            println!("\n✅ WOTS+ Key Pair Ready");
            println!("   Use 'cargo run --example wots-cli -- sign <message>' to sign");
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_sign(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: cargo run --example wots-cli -- sign <message>");
        eprintln!("       cargo run --example wots-cli -- sign \"transfer 1000 tokens\"");
        std::process::exit(1);
    }
    
    let message = args.join(" ");
    println!("📝 Signing message: \"{}\"\n", message);
    
    match load_or_create_keypair() {
        Ok(keypair) => {
            let signature = keypair.sign(message.as_bytes());
            
            // Parse [[u8; 32]; 66] for hex encoding
            let sig_bytes: [u8; 2112] = signature.into();
            
            fs::write(SIGNATURE_PATH, hex::encode(&sig_bytes)).ok();
            
            println!("✅ Signature generated:");
            println!("   Size: {} bytes ({} chains × 32 bytes)", 
                SIGNATURE_BYTES, CHAINS);
            println!("   Saved to: {}", SIGNATURE_PATH);
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: cargo run --example wots-cli -- verify <signature_file> <message>");
        std::process::exit(1);
    }
    
    let signature_path = &args[0];
    let message = if args.len() > 1 {
        args[1..].join(" ")
    } else {
        String::new()
    };
    
    println!("🔍 Verifying signature: {}\n", signature_path);
    println!("   Message: \"{}\"", message);
    
    // Load public key
    let pubkey_str = fs::read_to_string(PUBKEY_PATH).expect("Public key file not found");
    let pubkey_bytes: Vec<u8> = hex::decode(pubkey_str.trim()).expect("Invalid public key hex");
    let public_key: [[u8; 32]; 66] = {
        let arr: [u8; 2112] = pubkey_bytes.try_into().expect("Invalid public key length");
        let mut pk = [[0u8; 32]; 66];
        pk.copy_from_slice(&arr);
        pk
    };
    
    // Create a minimal keypair for verification
    let keypair = zk_ct_sdk::WOTSKeyPair {
        secret_key: [[0u8; 32]; 66],
        public_key,
    };
    
    // Load signature
    let sig_str = fs::read_to_string(signature_path).expect("Signature file not found");
    let sig_bytes: Vec<u8> = hex::decode(sig_str.trim()).expect("Invalid signature hex");
    let signature: [[u8; 32]; 66] = {
        let arr: [u8; 2112] = sig_bytes.try_into().expect("Invalid signature length");
        let mut sig = [[0u8; 32]; 66];
        sig.copy_from_slice(&arr);
        sig
    };
    
    if keypair.verify(message.as_bytes(), &signature) {
        println!("\n✅ VERIFICATION SUCCESSFUL");
        println!("   Signature is valid for the given message and public key");
    } else {
        println!("\n❌ VERIFICATION FAILED");
        println!("   Signature does not match message/public key");
        std::process::exit(1);
    }
}

fn cmd_demo() {
    println!("🚀 WOTS+ Confidential Transfer Demo");
    println!("====================================\n");
    
    // Clean up existing files
    let _ = fs::remove_file(PUBKEY_PATH);
    let _ = fs::remove_file(SECRETKEY_PATH);
    let _ = fs::remove_file(SIGNATURE_PATH);
    
    // Step 1: Generate keypair
    println!("⏳ Step 1: Generate keypair...");
    cmd_generate();
    
    // Step 2: Sign a message
    println!("\n⏳ Step 2: Sign a confidential transfer message...");
    cmd_sign(&["transfer", "1000", "tokens", "to", "recipient".to_string()]);
    
    // Step 3: Verify signature
    println!("\n⏳ Step 3: Verify signature...");
    cmd_verify(&[SIGNATURE_PATH.to_string(), "transfer 1000 tokens to recipient".to_string()]);
    
    // Step 4: Show wrong message verification fails
    println!("\n⏳ Step 4: Verify with wrong message (should fail)...");
    cmd_verify(&[SIGNATURE_PATH.to_string(), "transfer 2000 tokens to recipient".to_string()]);
}

fn print_help() {
    println!("ZK Confidential Transfer SDK - WOTS CLI");
    println!("==========================================\n");
    println!("Commands:");
    println!("  generate    Generate a new WOTS+ keypair");
    println!("  sign <msg>  Sign a message and save signature");
    println!("  verify <file> <msg>  Verify a signature file");
    println!("  demo        Run complete demo workflow");
    println!("  help        Show this help\n");
    println!("Files:");
    println!("  {}   - Public key ({})", PUBKEY_PATH, SIGNATURE_BYTES);
    println!("  {}   - Secret key ({}", SECRETKEY_PATH, SECRET_BYTES);
    println!("  {}      - Signature ({}", SIGNATURE_PATH, SIGNATURE_BYTES);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_help();
        return;
    }
    
    let command = &args[1];
    let command_args = &args[2..];
    
    match command.as_str() {
        "generate" | "gen" => cmd_generate(),
        "sign" | "sig" => cmd_sign(command_args),
        "verify" | "check" => cmd_verify(command_args),
        "demo" => cmd_demo(),
        "help" | "-h" | "--help" => print_help(),
        _ => {
            eprintln!("❌ Unknown command: {}", command);
            print_help();
            std::process::exit(1);
        }
    }
}