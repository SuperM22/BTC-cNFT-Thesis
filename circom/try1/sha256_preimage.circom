pragma circom 2.1.9;

// Prove knowledge of a 32-byte secret K such that sha256(K) equals the public hash H.

include "./circomlib/circuits/sha256/sha256.circom";

template Sha256Preimage() {
    // Private input
    signal input K[256];          

    // Public output
    signal output H[256];

    component sha = Sha256(256);  // 32 input bits
    for (var i = 0; i < 256; i++) {
        sha.in[i] <== K[i];
    }

    for (var j = 0; j < 256; j++) {
        H[j] <== sha.out[j];
    }
}

component main = Sha256Preimage();
