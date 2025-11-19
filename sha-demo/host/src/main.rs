use methods::{SHA_GUEST_ELF, SHA_GUEST_ID};
use rand::RngCore;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const PROOF_FILE: &str = "proof.bin";

/// Public outputs from the guest (must match guest's PublicJournal)
#[derive(Serialize, Deserialize, Debug)]
struct PublicJournal {
    hash_hex: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// What the seller sends to the buyer
#[derive(Serialize, Deserialize, Debug)]
struct ProofPackage {
    journal: PublicJournal,
    receipt: Receipt,
}

/// Seller: prove “I know k and an image such that:
///   hash_hex = SHA256(k)
///   ciphertext = Enc_k(image, nonce)”
fn seller_prove(secret: &str, image_path: &str) -> ProofPackage {
    println!("[SELLER] Secret key k (string form): {secret}");

    let k_bytes = secret.as_bytes().to_vec();
    if k_bytes.len() != 32 {
        eprintln!("WARNING: ChaCha20Poly1305 requires k to be exactly 32 bytes.");
    }

    println!("[SELLER] Secret string: {secret}");
    println!("[SELLER] Reading image from: {image_path}");

    // Read image bytes
    let image = fs::read(image_path).expect("Failed to read image file");

    println!("[SELLER] Image size: {} bytes", image.len());

    // Generate a random 12-byte nonce
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    println!("[SELLER] Nonce (hex): {}", hex::encode(nonce));

    // Convert secret k into raw bytes
    let k_bytes = secret.as_bytes().to_vec();

    // Build executor environment and send inputs to the guest
    let env = ExecutorEnv::builder()
        .write(&k_bytes) // k
        .unwrap()
        .write(&image) // image bytes
        .unwrap()
        .write(&nonce) // nonce
        .unwrap()
        .build()
        .unwrap();

    println!("[SELLER] Starting proof generation...");
    // Run the prover
    let prover = default_prover();
    let receipt = prover
        .prove(env, SHA_GUEST_ELF)
        .expect("Proving failed")
        .receipt;
    println!("[SELLER] Proof generation completed.");

    println!("[SELLER] Verifying receipt...");
    // Decode journal from the receipt
    let journal: PublicJournal = receipt
        .journal
        .decode()
        .expect("Failed to decode journal as PublicJournal");

    //println!("[SELLER] Guest reported hash H = {}", journal.hash_hex);
    println!(
        "[SELLER] Guest ciphertext length: {} bytes",
        journal.ciphertext.len()
    );

    ProofPackage { journal, receipt }
}

/// Buyer: verify proof and check the hash matches expected H
fn buyer_verify(expected_hash: &str, pkg: &ProofPackage) -> bool {
    println!("[BUYER] Expected H = {}", expected_hash);
    println!("[BUYER] Package hash H = {}", pkg.journal.hash_hex);
    println!("[BUYER] Package nonce (hex) = {}", hex::encode(pkg.journal.nonce));
    println!(
        "[BUYER] Ciphertext length in package: {} bytes",
        pkg.journal.ciphertext.len()
    );

    // Verify zk-proof against the guest image
    if let Err(e) = pkg.receipt.verify(SHA_GUEST_ID) {
        eprintln!("[BUYER] Receipt verification FAILED: {e}");
        return false;
    }
    println!("[BUYER] Receipt verification OK.");

    // Ensure journal hash equals package hash and expected hash
    let journal_from_receipt: PublicJournal = pkg
        .receipt
        .journal
        .decode()
        .expect("Failed to decode journal from receipt");

    let ok = journal_from_receipt.hash_hex == pkg.journal.hash_hex
        && journal_from_receipt.hash_hex == expected_hash;

    if ok {
        println!("[BUYER] Proof is valid and H matches expected value.");
    } else {
        eprintln!("[BUYER] Hash mismatch between receipt/package/expected.");
    }

    ok
}

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        eprintln!(
            "Usage:
  seller <secret_string> <image_path>     # generate proof, encrypt image, write {file}
  buyer  <expected_hash_hex>             # read {file} and verify",
            file = PROOF_FILE
        );
        std::process::exit(1);
    }

    let role = args.remove(0);

    match role.as_str() {
        "seller" => {
            if args.len() < 2 {
                eprintln!("Usage: seller <secret_string> <image_path>");
                std::process::exit(1);
            }
            let secret = &args[0];
            let image_path = &args[1];

            let pkg = seller_prove(secret, image_path);

            let bytes = bincode::serialize(&pkg).expect("Failed to serialize ProofPackage");
            fs::write(PROOF_FILE, &bytes).expect("Failed to write proof file");

            println!(
                "[SELLER] Saved proof package to {file}",
                file = Path::new(PROOF_FILE).display()
            );
            println!("[SELLER] Send H, nonce, ciphertext (inside {PROOF_FILE}) to the buyer.");
        }

        "buyer" => {
            if args.len() < 1 {
                eprintln!("Usage: buyer <expected_hash_hex>");
                std::process::exit(1);
            }
            let expected_hash = &args[0];

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
  seller <secret_string> <image_path>
  buyer  <expected_hash_hex>"
            );
            std::process::exit(1);
        }
    }
}
