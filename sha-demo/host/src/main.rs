use methods::{SHA_GUEST_ELF, SHA_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// File where we store the proof package (seller -----> buyer).
const PROOF_FILE: &str = "proof.bin";

/// What gets sent from seller to buyer.
#[derive(Serialize, Deserialize, Debug)]
struct ProofPackage {
    /// H = SHA256(secret), hex-encoded
    hash_hex: String,
    /// zk proof (Risc0 receipt)
    receipt: Receipt,
}

/// Seller: prove “I know secret s.t. SHA256(secret) = hash_hex”
fn seller_prove(secret: &str) -> ProofPackage {
    println!("[SELLER] Secret string: {secret}");

    // Build environment and send secret to guest
    let env = ExecutorEnv::builder()
        .write(&secret.to_string())
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let receipt = prover
        .prove(env, SHA_GUEST_ELF)
        .expect("Proving failed")
        .receipt;

    // Read hash from journal (this is H = SHA256(secret))
    let hash_hex: String = receipt
        .journal
        .decode()
        .expect("Failed to decode journal as String");

    println!("[SELLER] Computed hash H = {hash_hex}");

    ProofPackage { hash_hex, receipt }
}

/// Buyer: verify that the proof is valid and the hash matches the expected value.
fn buyer_verify(expected_hash: &str, pkg: &ProofPackage) -> bool {
    println!("[BUYER] Expected H = {expected_hash}");
    println!("[BUYER] Package claims H = {}", pkg.hash_hex);

    // 1) Verify zk-proof against the guest program image ID
    if let Err(e) = pkg.receipt.verify(SHA_GUEST_ID) {
        eprintln!("[BUYER] Receipt verification FAILED: {e}");
        return false;
    }
    println!("[BUYER] Receipt verification OK.");

    // Ensure the journal's hash equals the hash inside the package
    let journal_hash: String = pkg
        .receipt
        .journal
        .decode()
        .expect("Failed to decode journal as String");

    println!("[BUYER] Journal hash = {journal_hash}");

    let ok = journal_hash == pkg.hash_hex && journal_hash == expected_hash;
    if ok {
        println!("[BUYER] Proof is valid and matches expected hash.");
    } else {
        eprintln!("[BUYER] Hash mismatch.");
    }
    ok
}

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        eprintln!(
            "Usage:
  seller <secret_string>        # generate proof and write {PROOF_FILE}
  buyer  <expected_hash_hex>    # read {PROOF_FILE} and verify"
        );
        std::process::exit(1);
    }

    let role = args.remove(0);

    match role.as_str() {
        "seller" => {
            // seller <secret_string>
            if args.is_empty() {
                eprintln!("Usage: seller <secret_string>");
                std::process::exit(1);
            }
            let secret = &args[0];

            // Run prover
            let pkg = seller_prove(secret);

            // Serialize to file
            let bytes = bincode::serialize(&pkg).expect("Failed to serialize ProofPackage");
            fs::write(PROOF_FILE, &bytes).expect("Failed to write proof file");

            println!(
                "[SELLER] Saved proof package to {file}",
                file = Path::new(PROOF_FILE).display()
            );
            println!("[SELLER] Send H and {PROOF_FILE} to the buyer.");
        }

        "buyer" => {
            // buyer <expected_hash_hex>
            if args.is_empty() {
                eprintln!("Usage: buyer <expected_hash_hex>");
                std::process::exit(1);
            }
            let expected_hash = &args[0];

            // Read package from file
            let bytes = fs::read(PROOF_FILE).expect("Failed to read proof file");
            let pkg: ProofPackage =
                bincode::deserialize(&bytes).expect("Failed to deserialize ProofPackage");

            println!(
                "[BUYER] Loaded proof package from {file}",
                file = Path::new(PROOF_FILE).display()
            );

            let ok = buyer_verify(expected_hash, &pkg);
            if !ok {
                std::process::exit(1);
            }
        }

        _ => {
            eprintln!(
                "Unknown role: {role}
Usage:
  seller <secret_string>
  buyer  <expected_hash_hex>"
            );
            std::process::exit(1);
        }
    }
}
