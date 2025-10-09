pragma circom 2.1.9;

// Prove knowledge of a 32-byte secret K such that sha256(K) equals the public hash H.

include "./circomlib/circuits/sha256/sha256.circom";

template Sha256Preimage() {
    // Private input
    signal input K[32];          

    // Public output
    signal output H[32];

    component sha = Sha256(32);  // 32 input bytes
    for (var i = 0; i < 32; i++) {
        // Sha256 expects bytes (0..255)
        sha.in[i] <== K[i];
    }

    for (var j = 0; j < 32; j++) {
        H[j] <== sha.out[j];
    }
}

component main = Sha256Preimage();
