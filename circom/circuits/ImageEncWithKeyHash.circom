pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";

template ImageEncWithKeyHash(N, CHUNK_BITS) {
    signal input keyBits[256];
    signal input nonce;
    signal input msg[N];

    signal output hkBits[256];
    signal output hkPacked[2];
    signal output ct[N];

    // -------------------------------
    // 1) SHA256(keyBits) with padding
    // -------------------------------
    // Build one 512-bit block = keyBits || 1 || zeros || len(=256)
    signal block[512];

    // message = 256 bits
    for (var i = 0; i < 256; i++) {
        block[i] <== keyBits[i];
    }

    // append the '1' bit
    block[256] <== 1;

    // zeros until last 64 bits
    for (var z = 257; z < 448; z++) {
        block[z] <== 0;
    }

    // length = 256 (bits) encoded as 64-bit big-endian
    // We'll create 64-bit little-endian then reverse to big-endian.
    component lenBitsLE = Num2Bits(64);
    lenBitsLE.in <== 256;

    // Reverse to big-endian for SHA length field (common convention)
    for (var b = 0; b < 64; b++) {
        block[448 + b] <== lenBitsLE.out[63 - b];
    }

    // Now hash the 512-bit padded block
    component sha = Sha256(512);
    for (var j = 0; j < 512; j++) {
        sha.in[j] <== block[j];
    }

    for (var o = 0; o < 256; o++) {
        hkBits[o] <== sha.out[o];
    }

    // Pack hkBits into 2 field elements (128 bits each) for convenience
    component hk0 = Bits2Num(128);
    component hk1 = Bits2Num(128);
    for (var p = 0; p < 128; p++) {
        hk0.in[p] <== hkBits[p];
        hk1.in[p] <== hkBits[p + 128];
    }
    hkPacked[0] <== hk0.out;
    hkPacked[1] <== hk1.out;

    // -------------------------------
    // 2) Derive Poseidon key limbs from keyBits
    // -------------------------------
    component kLo = Bits2Num(128);
    component kHi = Bits2Num(128);
    for (var k = 0; k < 128; k++) {
        kLo.in[k] <== keyBits[k];
        kHi.in[k] <== keyBits[k + 128];
    }
    signal keyLo;
    signal keyHi;
    keyLo <== kLo.out;
    keyHi <== kHi.out;

    // -------------------------------
    // 3) Range-check msg chunks
    // -------------------------------
    component msgRange[N];
    for (var m = 0; m < N; m++) {
        msgRange[m] = Num2Bits(CHUNK_BITS);
        msgRange[m].in <== msg[m];
    }

    // -------------------------------
    // 4) Encrypt: ct[i] = msg[i] + Poseidon(keyLo, keyHi, nonce, i)
    // -------------------------------
    component prg[N];
    for (var t = 0; t < N; t++) {
        prg[t] = Poseidon(4);
        prg[t].inputs[0] <== keyLo;
        prg[t].inputs[1] <== keyHi;
        prg[t].inputs[2] <== nonce;
        prg[t].inputs[3] <== t;

        ct[t] <== msg[t] + prg[t].out;
    }
}

// small test
component main = ImageEncWithKeyHash(825, 248);
