// src/main.nr

// Fixed sizes must be compile-time constants (use `global`, not `const`).
global KEY_LEN: u32 = 16u32;
global MSG_LEN: u32 = 32u32;


fn toy_hash(k: [u8; KEY_LEN]) -> Field {
    let mut acc: Field = 0;
    for i in 0..KEY_LEN {
        acc = acc + (k[i] as Field);
    }
    acc
}


fn xor_repeat_key(s: [u8; MSG_LEN], k: [u8; KEY_LEN]) -> [u8; MSG_LEN] {
    let mut out: [u8; MSG_LEN] = [0u8; MSG_LEN];
    for i in 0..MSG_LEN {
        let kb: u8 = k[i % KEY_LEN];
        out[i] = s[i] ^ kb;
    }
    out
}

// Entry point: inputs are private by default; return type must be public.
// Docs: main visibility & public types, and for-loop control-flow. 
// :contentReference[oaicite:1]{index=1}
fn main(k: [u8; KEY_LEN], s: [u8; MSG_LEN]) -> pub (Field, [u8; MSG_LEN]) {
    let h: Field = toy_hash(k);
    let ct: [u8; MSG_LEN] = xor_repeat_key(s, k);
    (h, ct)
}
