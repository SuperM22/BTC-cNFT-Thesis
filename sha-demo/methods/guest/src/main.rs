use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct PublicJournal {
    /// H = SHA256(k), hex-encoded
    hash_hex: String,
    /// 12-byte AEAD nonce
    nonce: [u8; 12],
    /// ciphertext = Enc(k, image)
    ciphertext: Vec<u8>,
}

fn main() {
    // Inputs from the host
    // MUST match host.write() order
    let k: Vec<u8> = env::read();         // secret encryption key
    let image: Vec<u8> = env::read();     // image bytes
    let nonce_bytes: [u8; 12] = env::read();

    //
    // H = SHA256(k)
    //
    let mut hasher = Sha256::new();
    hasher.update(&k);
    let h = hasher.finalize(); // 32 bytes

    let hash_hex = format!("{:x}", h);

    //
    // Encryption key = k
    //    used as ChaCha20-Poly1305 key
    //
    if k.len() != 32 {
        panic!("Encryption key k must be exactly 32 bytes for ChaCha20Poly1305");
    }

    let key = Key::from_slice(&k); // &[u8; 32]
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes); // &[u8; 12]

    //
    // ciphertext = Enc(k, image, nonce)
    //
    println!("[GUEST] Encrypting image");
    let ciphertext = cipher
        .encrypt(nonce, image.as_ref())
        .expect("encryption failed inside zkVM");
    println!("[GUEST] Image encrypted, ciphertext size: {} bytes", ciphertext.len());
    //
    // Commit the public outputs
    //
    let journal = PublicJournal {
        hash_hex,
        nonce: nonce_bytes,
        ciphertext,
    };

    env::commit(&journal);
    println!("[GUEST] Committed public journal to host.");
}
