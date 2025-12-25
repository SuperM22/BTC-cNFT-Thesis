#![no_main]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};



risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Header {
    width: u32,
    height: u32,
    channels: u8,   // must be 3 (RGB)
    stride: u32,    // NN downsample stride
    nonce: [u8; 12],
    k: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
struct Journal {
    hk: [u8; 32],         // SHA256(k)
    himg: [u8; 32],       // SHA256(img bytes)
    nonce: [u8; 12],
    stride: u32,
    down_w: u32,
    down_h: u32,
    downgraded: Vec<u8>,  // RGB bytes after downsample
    ciphertext: Vec<u8>,  // ChaCha20-Poly1305 ciphertext+tag of full img bytes
}

fn nn_downsample_rgb(img: &[u8], w: u32, h: u32, stride: u32) -> (Vec<u8>, u32, u32) {
    assert!(stride >= 1, "stride must be >= 1");
    let c = 3usize;

    let out_w = (w + stride - 1) / stride;
    let out_h = (h + stride - 1) / stride;

    let mut out = vec![0u8; (out_w * out_h) as usize * c];

    for oy in 0..out_h {
        let iy = oy * stride;
        if iy >= h { break; }
        for ox in 0..out_w {
            let ix = ox * stride;
            if ix >= w { break; }

            let in_idx = ((iy * w + ix) as usize) * c;
            let out_idx = ((oy * out_w + ox) as usize) * c;

            out[out_idx..out_idx + c].copy_from_slice(&img[in_idx..in_idx + c]);
        }
    }
    (out, out_w, out_h)
}

pub fn main() {
    // 1) Read header (small typed input)
    let header: Header = env::read();

    if header.channels != 3 {
        panic!("expected channels=3 (RGB), got {}", header.channels);
    }
    if header.width == 0 || header.height == 0 {
        panic!("width/height must be > 0");
    }

    // 2) Read raw RGB matrix bytes (big input)
    let img_len = header.width as usize * header.height as usize * 3usize;
    let mut img = vec![0u8; img_len];
    env::read_slice(&mut img);

    // 3) Hashes
    println!("Computing hashes...");
    let hk: [u8; 32] = Sha256::digest(&header.k).into();
    println!("hk: {:x?}", hk);

    let himg: [u8; 32] = Sha256::digest(&img).into();

    println!("himg calulated");

    // 4) Downgrade: NN downsample
    let (downgraded, down_w, down_h) = nn_downsample_rgb(&img, header.width, header.height, header.stride);
    println!("downsampled ");
    // 5) Encrypt full image bytes with ChaCha20-Poly1305
    let key = Key::from_slice(&header.k);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&header.nonce);
    println!("encrypting full image...");
    let ciphertext = cipher.encrypt(nonce, img.as_ref()).expect("encrypt failed");
    println!("encryption done");
    // 6) Commit outputs publicly
    env::commit(&Journal {
        hk,
        himg,
        nonce: header.nonce,
        stride: header.stride,
        down_w,
        down_h,
        downgraded,
        ciphertext,
    });
}
