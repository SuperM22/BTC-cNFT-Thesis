#!/usr/bin/env node
/**
 * build_input_from_image.js
 *
 * AUTO-N input builder for ImageEncWithKeyHash(N, 248)
 *
 * - Reads PNG/JPEG/any binary file
 * - Packs bytes into 31-byte chunks (248 bits)
 * - Computes N = ceil(fileBytes / 31) automatically
 * - Pads msg[] to exactly N
 * - Generates keyBits[256] and nonce
 * - Writes input.json and meta.json
 *
 * IMPORTANT:
 *   The circuit must be compiled with the printed N.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CHUNK_BYTES = 31;   // 31 bytes = 248 bits
const NONCE_BYTES = 16;   // 128-bit nonce

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const v = argv[i + 1];
      if (!v || v.startsWith("--")) {
        args[k] = true;
      } else {
        args[k] = v;
        i++;
      }
    }
  }
  return args;
}

function bytesToBitsLE(buf) {
  const bits = [];
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    for (let j = 0; j < 8; j++) {
      bits.push((b >> j) & 1);
    }
  }
  return bits;
}

function packChunkLE(bytes) {
  let x = 0n;
  for (let i = 0; i < bytes.length; i++) {
    x += BigInt(bytes[i]) << (8n * BigInt(i));
  }
  return x;
}

function bigIntFromBufferBE(buf) {
  let x = 0n;
  for (const byte of buf.values()) {
    x = (x << 8n) + BigInt(byte);
  }
  return x;
}

function main() {
  const args = parseArgs(process.argv);

  const file = args.file || args.f;
  const out = args.out || "input.json";
  const metaOut = args.meta || "meta.json";
  const keyHex = args.keyhex;
  const nonceArg = args.nonce;

  if (!file) {
    console.error("Missing --file <path>");
    process.exit(1);
  }

  const bytes = fs.readFileSync(file);
  const fileSize = bytes.length;

  // Key
  const key = keyHex
    ? Buffer.from(keyHex.replace(/^0x/, ""), "hex")
    : crypto.randomBytes(32);

  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes");
  }

  const keyBits = bytesToBitsLE(key);

  // Nonce
  const nonce = nonceArg
    ? BigInt(nonceArg).toString(10)
    : bigIntFromBufferBE(crypto.randomBytes(NONCE_BYTES)).toString(10);

  // Chunking
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
    const slice = bytes.subarray(offset, offset + CHUNK_BYTES);
    chunks.push(packChunkLE(slice));
  }

  const N = chunks.length;

  const msg = chunks.map(x => x.toString(10));

  // Write input.json
  const input = { keyBits, nonce, msg };
  fs.writeFileSync(out, JSON.stringify(input, null, 2));

  // Write meta.json
  const meta = {
    file: path.resolve(file),
    fileSizeBytes: fileSize,
    chunkBytes: CHUNK_BYTES,
    chunkCountN: N,
    packing: "little-endian: sum(byte[i] * 256^i)",
    keyHex: "0x" + key.toString("hex"),
    nonceDecimal: nonce
  };
  fs.writeFileSync(metaOut, JSON.stringify(meta, null, 2));

  // Console output
    console.log("Input generated");
    console.log("File size (bytes):", fileSize);
    console.log("Chunk size (bytes):", CHUNK_BYTES);
    console.log("Computed N:", N);
    console.log("Encryption key (hex):", "0x" + key.toString("hex"));
    console.log("Nonce (decimal):", nonce);
    console.log("Compile the circuit with:");
    console.log("component main = ImageEncWithKeyHash(" + N + ", 248);");
}

main();
