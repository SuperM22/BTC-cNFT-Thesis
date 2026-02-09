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

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use image::{ImageBuffer, Rgb};

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

//helpers for decryption and output of the image

fn parse_key_32(hex_str: &str) -> [u8; 32] {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let raw = hex::decode(s).expect("invalid hex key");
    if raw.len() != 32 {
        panic!("key must be 32 bytes (64 hex chars)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn decrypt_ciphertext(j: &Journal, k: [u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
    let nonce = Nonce::from_slice(&j.nonce);

    cipher.decrypt(nonce, j.ciphertext.as_ref()).expect("decrypt failed")
}

fn plaintext_rgb_to_png(plaintext_rgb: Vec<u8>, w: u32, h: u32, out_png: &str) {
    let expected = (w as usize) * (h as usize) * 3usize;
    if plaintext_rgb.len() != expected {
        panic!(
            "plaintext length mismatch: got {}, expected {} (= {}*{}*3)",
            plaintext_rgb.len(),
            expected,
            w,
            h
        );
    }

    let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
        ImageBuffer::from_raw(w, h, plaintext_rgb).expect("failed to build image from raw bytes");
    img.save(out_png).expect("failed to save png");
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

        // decrypt-image mode:
        //   verifier <method.bin> <proof.bin> decrypt-image --key <hex32> --w <W> --h <H> [--out out.png]
        if args.len() >= 4 && args[3] == "decrypt-image" {
            let mut key_hex: Option<String> = None;
            let mut w: Option<u32> = None;
            let mut h: Option<u32> = None;
            let mut out_png: String = "decrypted.png".to_string();

            let mut i = 4;
            while i < args.len() {
                match args[i].as_str() {
                    "--key" => {
                        i += 1;
                        key_hex = args.get(i).cloned();
                    }
                    "--w" => {
                        i += 1;
                        w = args.get(i).and_then(|s| s.parse::<u32>().ok());
                    }
                    "--h" => {
                        i += 1;
                        h = args.get(i).and_then(|s| s.parse::<u32>().ok());
                    }
                    "--out" => {
                        i += 1;
                        if let Some(v) = args.get(i) {
                            out_png = v.clone();
                        }
                    }
                    other => {
                        panic!("unknown flag: {}", other);
                    }
                }
                i += 1;
            }

            let key_hex = key_hex.expect("missing --key");
            let w = w.expect("missing --w");
            let h = h.expect("missing --h");

            let k = parse_key_32(&key_hex);
            let plaintext = decrypt_ciphertext(&journal, k);

            plaintext_rgb_to_png(plaintext, w, h, &out_png);

            println!("wrote {}", out_png);
        }
    }
}
