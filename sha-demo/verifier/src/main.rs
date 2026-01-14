// Verify a RISC Zero receipt (proof) against an ImageID computed from a guest bin file.
//
// Usage:
//   cargo run --release -- <guest.bin> <proof.bin> [--no-verify-journal]
// Example:
//   cargo run --release -- ./guest.bin ./proof.bin



use risc0_binfmt::compute_image_id;
use risc0_zkvm::Receipt;
use std::{env, fs};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Journal {
    hk: [u8; 32],
    himg: [u8; 32],
    nonce: [u8; 12],
    stride: u32,
    down_w: u32,
    down_h: u32,
    downgraded: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <guest.elf> <proof.bin> [--no-verify-journal]",
            args[0]
        );
        std::process::exit(1);
    }

    let elf_path = &args[1];
    let proof_path = &args[2];
    let no_journal = args.iter().any(|a| a == "--no-verify-journal");

    // Read ELF
    let method_blob = fs::read(elf_path).unwrap_or_else(|e| {
        eprintln!("Failed to read method binary {}: {}", elf_path, e);
        std::process::exit(1);
    });

    // Compute ImageID from ELF
    let image_id = compute_image_id(&method_blob).unwrap_or_else(|e| {
        eprintln!("compute_image_id failed (is this a ProgramBinary blob?): {:#}", e);
        std::process::exit(1);
    });

    println!("Computed ImageID: {}", hex::encode(image_id.as_bytes()));

    // Read proof (receipt)
    let proof_bytes = fs::read(proof_path).unwrap_or_else(|e| {
        eprintln!("Failed to read proof {}: {}", proof_path, e);
        std::process::exit(1);
    });

    let receipt: Receipt = bincode::deserialize(&proof_bytes).unwrap_or_else(|e| {
        eprintln!("Failed to deserialize proof as Receipt (bincode): {}", e);
        std::process::exit(1);
    });

    //Verify receipt against computed ImageID
    receipt.verify(image_id).unwrap_or_else(|e| {
        eprintln!("Receipt verification FAILED: {:#}", e);
        std::process::exit(1);
    });

    println!("Receipt verified OK against computed ImageID.");

    //decode journal 
    if !no_journal {
        println!("Decoding journal...");
        let journal: Journal = receipt.journal.decode().unwrap_or_else(|e| {
            eprintln!("Failed to decode journal into Journal struct: {:#}", e);
            std::process::exit(1);
        });

        println!("Journal bytes: {}", receipt.journal.bytes.len());

        println!("\n--- Journal ---");
        println!("H(k)   = {}", hex::encode(journal.hk));
        println!("H(img) = {}", hex::encode(journal.himg));
        println!("nonce  = {}", hex::encode(journal.nonce));
        println!("stride = {}", journal.stride);
        println!("down_w = {}", journal.down_w);
        println!("down_h = {}", journal.down_h);

    }
}
