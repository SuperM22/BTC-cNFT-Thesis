// run with: node ordinal_buyer_claim_p2.js

const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
bitcoin.initEccLib(ecc);

const { ECPairFactory } = require('ecpair');
const crypto = require('crypto');
const ECPair = ECPairFactory(ecc);

const network = bitcoin.networks.testnet;

// ====== HARDCODED INPUTS ======
const PSBT_BASE64 = 'cHNidP8BALICAAAAAlY/X3ON2Od9Un8aTnqrU6NaRK5dIheBMVP+KUYXsERkAAAAAAD/////mN9cTlJOkfyu8aSnt81Sua/E8FV+RfAIKbtu4BdSRW0AAAAAAP////8CECcAAAAAAAAiUSCt7rY7G08pkRBcuULGDwHJhQz6VxuIq4zA/X/XIDCdXEAfAAAAAAAAIlEgrIxe3iLqxeynTv5Q7nRfH7HtChWIJ+kYnQZcAUU/EUkAAAAAAAEBKxAnAAAAAAAAIgAglFiABzov1NxTprT0Ew3zFb4w7Xc6K3tpRVeiff/OLNkAAQCJAgAAAAGHmAfFiwO1VvvrCgvVx98/99OcFszCij5aO1coThpWrQAAAAAA/f///wI0GQYAAAAAACJRIKhFGW6QPYFcYvWCKdEMMW1P//vofyR8yECJcjnbGGFGoIYBAAAAAAAiACBMHY/eU/aeVzFi0Jx2Opqt4hIsLJgjMafNAnHc7YNGE+6mAQABASs0GQYAAAAAACJRIKhFGW6QPYFcYvWCKdEMMW1P//vofyR8yECJcjnbGGFGAQhCAUDmXnLpP/ZF6jVXCWEjSAnQy35s8X39kL4CgDT20DK4eJ9OxNCaAybeFDk/AdOsIox6WryK/H+6BpzF5hzLj1wxAAEFIPMpdgEPJRH9CPY9Id8X3GGJMjGxIYkwt68sv+/Mrk1WIQfzKXYBDyUR/Qj2PSHfF9xhiTIxsSGJMLevLL/vzK5NVhkAGP4dZlYAAIABAACAAAAAgAAAAAAAAAAAAAEFIOm9pHgQTOQo7oxk2YMlCGHeMTRk5m7FKtr7+rS4hSnGIQfpvaR4EEzkKO6MZNmDJQhh3jE0ZOZuxSra+/q0uIUpxhkAGP4dZlYAAIABAACAAAAAgAEAAAACAAAAAA=='; // from: bitcoin-cli -testnet4 walletprocesspsbt ... | jq -r .psbt
const BUYER_WIF = 'cQvzrfSD41ys5t22uSJ86Sb2AmjiBUxWd8H3Zt5TMj1t3f2UeBKY';

// You may keep 0x prefix; 
const SECRET_HEX = 'f56c1a8ef50e1fc0feaa27c7d927f2bd03a9a4d040944e72e58b2aaeb20e896b';

const WITNESS_SCRIPT_HEX =
  '63a820a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe679029886428821026b90d183cf3d06ed659ecde81bf47279c1eee0859b25b1d538980ae3de9d4290ac670381d501b1752102e435ca35d0e151026c1f0c8517358d9636a345664ba88dfff9688c42dfe0d9a4ac68';
// ==============================

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function normalizeHex(s, label) {
  if (typeof s !== 'string') throw new Error(`${label} must be a string`);
  let t = s.trim().toLowerCase();
  if (t.startsWith('0x')) t = t.slice(2);
  if (t.length === 0) throw new Error(`${label} is empty after normalization`);
  if (t.length % 2 !== 0) throw new Error(`${label} must have even-length hex`);
  if (!/^[0-9a-f]+$/.test(t)) throw new Error(`${label} contains non-hex characters`);
  return t;
}

// ---- minimal witness serialization (BIP141) ----
function encodeVarInt(n) {
  // n is a JS number (safe here because witness items are small)
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5);
    b[0] = 0xfe;
    b.writeUInt32LE(n, 1);
    return b;
  }
  // not needed for our use
  const b = Buffer.alloc(9);
  b[0] = 0xff;
  // write BigInt LE
  let x = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[1 + i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

function serializeWitnessStack(stack) {
  // stack: Buffer[]
  const parts = [encodeVarInt(stack.length)];
  for (const item of stack) {
    const buf = Buffer.isBuffer(item) ? item : Buffer.from(item);
    parts.push(encodeVarInt(buf.length));
    parts.push(buf);
  }
  return Buffer.concat(parts);
}

function extractHFromWitnessScript(witnessScriptBuf) {
  const chunks = bitcoin.script.decompile(witnessScriptBuf);
  if (!chunks) throw new Error('Cannot decompile witnessScript');

  const shaPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_SHA256);
  if (shaPos < 0) throw new Error('OP_SHA256 not found in witnessScript');

  const next = chunks[shaPos + 1];
  if (!Buffer.isBuffer(next) || next.length !== 32) {
    throw new Error('Expected 32-byte H immediately after OP_SHA256 in witnessScript');
  }
  return next;
}

function main() {
  const psbt = bitcoin.Psbt.fromBase64(PSBT_BASE64, { network });

  const buyerKey = ECPair.fromWIF(BUYER_WIF, network);

  const secretNorm = normalizeHex(SECRET_HEX, 'SECRET_HEX');
  const secretBuf = Buffer.from(secretNorm, 'hex');

  const wsNorm = normalizeHex(WITNESS_SCRIPT_HEX, 'WITNESS_SCRIPT_HEX');
  const witnessScriptBuf = Buffer.from(wsNorm, 'hex');

  // Optional sanity: your secret should be 32 bytes
  if (secretBuf.length !== 32) {
    throw new Error(`SECRET_HEX decoded to ${secretBuf.length} bytes (expected 32). Got: ${secretBuf.toString('hex')}`);
  }

  // Attach witnessScript so bitcoinjs can compute segwit-v0 sighash correctly for input 0
  psbt.updateInput(0, { witnessScript: witnessScriptBuf });

  // Check hashlock: sha256(secret) must equal H in script
  const H = extractHFromWitnessScript(witnessScriptBuf);
  const Hs = sha256(secretBuf);
  if (!Hs.equals(H)) {
    throw new Error(
      `secret sha256 mismatch: H(script)=${H.toString('hex')} H(secret)=${Hs.toString('hex')}`
    );
  }

  // Sign escrow input 0 (P2WSH)
  psbt.signInput(0, buyerKey);

  // Finalize input 0 with witness stack: [sig, secret, TRUE, witnessScript]
  psbt.finalizeInput(0, (idx, input) => {
    const sig = input.partialSig?.[0]?.signature;
    if (!sig) throw new Error('Missing partialSig for escrow input 0');

    const witnessStack = [sig, secretBuf, Buffer.from([1]), witnessScriptBuf];
    const finalScriptWitness = serializeWitnessStack(witnessStack);

    return { finalScriptSig: Buffer.alloc(0), finalScriptWitness };
  });

  process.stdout.write(psbt.toBase64());
}

try {
  main();
} catch (e) {
  console.error('Error:', e?.message || e);
  process.exit(1);
}
