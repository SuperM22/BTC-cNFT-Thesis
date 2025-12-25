use methods::{SHA_GUEST_ELF, SHA_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use std::fs;
use rand::RngCore;
use std::time::Instant;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Header {
    width: u32,
    height: u32,
    channels: u8, // 3
    stride: u32,
    nonce: [u8; 12],
    k: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
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

fn parse_k_32(hex_str: &str) -> [u8; 32] {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let raw = hex::decode(s).expect("invalid hex key");
    assert_eq!(raw.len(), 32, "k must be 32 bytes (64 hex chars)");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn main() {
    // Usage:
    // cargo run --release -- <rgb.bin> <width> <height> <k_hex32> <stride>
    //
    // Example:
    // cargo run --release -- rgb.bin 1024 768 0xf56c...e896b 8
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "Usage: {} <rgb.bin> <width> <height> <k_hex32> <stride>",
            args[0]
        );
        std::process::exit(1);
    }

    let bin_path = &args[1];
    let width: u32 = args[2].parse().expect("width must be int");
    let height: u32 = args[3].parse().expect("height must be int");
    let k = parse_k_32(&args[4]);
    let stride: u32 = args[5].parse().expect("stride must be int");
    if stride == 0 {
        eprintln!("stride must be >= 1");
        std::process::exit(1);
    }

    // Read raw RGB bytes
    let rgb = fs::read(bin_path).expect("failed to read rgb.bin");

    let expected = width as usize * height as usize * 3usize;
    if rgb.len() != expected {
        eprintln!(
            "rgb.bin size mismatch: got {} bytes, expected {} (= {}*{}*3)",
            rgb.len(),
            expected,
            width,
            height
        );
        std::process::exit(1);
    }

    // Nonce from host

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let header = Header {
        width,
        height,
        channels: 3,
        stride,
        nonce,
        k,
    };

    // IMPORTANT: small header via write(), big matrix via write_slice()
    let mut builder = ExecutorEnv::builder();
    builder.write(&header).expect("write header failed");
    builder.write_slice(&rgb);
    let env = builder.build().expect("build env failed");

    println!("Proving... (this may take a while)");
    let prover = default_prover();
    let start = Instant::now();
    let receipt = prover.prove(env, SHA_GUEST_ELF).expect("prove failed").receipt;
    let duration = start.elapsed();
    println!("Proving done in: {:?}", duration);

    receipt.verify(SHA_GUEST_ID).expect("receipt verify failed");

    let journal: Journal = receipt.journal.decode().expect("decode journal failed");

    println!("H(k)   = {}", hex::encode(journal.hk));
    println!("H(img) = {}", hex::encode(journal.himg));
    println!("nonce  = {}", hex::encode(journal.nonce));
    println!("ciphertext bytes = {}", journal.ciphertext.len());
    println!(
        "downgraded: {}x{} (RGB) bytes={}",
        journal.down_w,
        journal.down_h,
        journal.downgraded.len()
    );

    // If you want, you can save outputs:
    // fs::write("ciphertext.bin", &journal.ciphertext).unwrap();
    // fs::write("preview_rgb.bin", &journal.downgraded).unwrap();
}
