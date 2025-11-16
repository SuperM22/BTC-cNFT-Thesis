use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};



fn main() {
    // Read the input string from the host
    let input: String = env::read();

    // Compute SHA-256(input)
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();        // 32-byte digest

    // Convert digest to lowercase hex string
    let output = format!("{:x}", result);

    // Commit public output to the journal
    env::commit(&output);
}
