// decode_witness_script.js
//
// Usage:
//   node decode_witness_script.js <witnessScriptHex>
//
// Prints a readable decode + extracts hashlock H, buyer pubkey, CLTV locktime, seller pubkey.

const bitcoin = require('bitcoinjs-lib');

function normalizeHex(s) {
  let t = (s || '').trim().toLowerCase();
  if (t.startsWith('0x')) t = t.slice(2);
  if (t.length === 0) throw new Error('empty hex');
  if (t.length % 2 !== 0) throw new Error('hex must have even length');
  if (!/^[0-9a-f]+$/.test(t)) throw new Error('non-hex characters present');
  return t;
}

// Decode ScriptNum (CScriptNum-style): little-endian sign-magnitude.
// For CLTV we expect a non-negative number.
function decodeScriptNum(buf) {
  if (!buf || buf.length === 0) return 0n;

  // little-endian bytes to BigInt
  let x = 0n;
  for (let i = 0; i < buf.length; i++) {
    x |= BigInt(buf[i]) << (8n * BigInt(i));
  }

  // sign bit is the highest bit of the last byte
  const last = buf[buf.length - 1];
  const negative = (last & 0x80) !== 0;

  if (!negative) return x;

  // clear sign bit
  const signMask = ~(0x80n << (8n * BigInt(buf.length - 1)));
  const abs = x & signMask;
  return -abs;
}

function opName(n) {
  // Minimal mapping for the opcodes we care about.
  const map = {
    [bitcoin.opcodes.OP_IF]: 'OP_IF',
    [bitcoin.opcodes.OP_ELSE]: 'OP_ELSE',
    [bitcoin.opcodes.OP_ENDIF]: 'OP_ENDIF',
    [bitcoin.opcodes.OP_SHA256]: 'OP_SHA256',
    [bitcoin.opcodes.OP_EQUALVERIFY]: 'OP_EQUALVERIFY',
    [bitcoin.opcodes.OP_CHECKSIG]: 'OP_CHECKSIG',
    [bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY]: 'OP_CHECKLOCKTIMEVERIFY',
    [bitcoin.opcodes.OP_DROP]: 'OP_DROP',
  };
  return map[n] || `OP_${n}`;
}

function main() {
  const arg = process.argv[2];
  const hex = normalizeHex(arg);
  const scriptBuf = Buffer.from(hex, 'hex');

  const chunks = bitcoin.script.decompile(scriptBuf);
  if (!chunks) throw new Error('Failed to decompile script');

  console.log('--- Script chunks (decoded) ---');
  chunks.forEach((c, i) => {
    if (Buffer.isBuffer(c)) {
      console.log(`${i}: PUSH(${c.length}) ${c.toString('hex')}`);
    } else {
      console.log(`${i}: ${opName(c)} (${c})`);
    }
  });

  // Extract fields according to your template:
  // OP_IF OP_SHA256 PUSH32(H) OP_EQUALVERIFY PUSH33(buyerPK) OP_CHECKSIG
  // OP_ELSE PUSH(locktime) OP_CLTV OP_DROP PUSH33(sellerPK) OP_CHECKSIG OP_ENDIF

  const shaPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_SHA256);
  if (shaPos < 0) throw new Error('OP_SHA256 not found');

  const H = chunks[shaPos + 1];
  if (!Buffer.isBuffer(H) || H.length !== 32) throw new Error('Expected 32-byte H after OP_SHA256');

  // buyer pubkey: next 33-byte push after OP_EQUALVERIFY
  const eqvPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_EQUALVERIFY);
  if (eqvPos < 0) throw new Error('OP_EQUALVERIFY not found');

  const buyerPK = chunks[eqvPos + 1];
  if (!Buffer.isBuffer(buyerPK) || buyerPK.length !== 33) throw new Error('Expected 33-byte buyer pubkey after OP_EQUALVERIFY');

  // locktime: push immediately before OP_CLTV
  const cltvPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY);
  if (cltvPos < 0) throw new Error('OP_CHECKLOCKTIMEVERIFY not found');

  const lockPush = chunks[cltvPos - 1];
  if (!Buffer.isBuffer(lockPush)) throw new Error('Expected locktime push immediately before OP_CHECKLOCKTIMEVERIFY');

  const locktime = decodeScriptNum(lockPush);

  // seller pubkey: push after OP_DROP
  const dropPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_DROP);
  if (dropPos < 0) throw new Error('OP_DROP not found');

  const sellerPK = chunks[dropPos + 1];
  if (!Buffer.isBuffer(sellerPK) || sellerPK.length !== 33) throw new Error('Expected 33-byte seller pubkey after OP_DROP');

  console.log('\n--- Extracted contract parameters ---');
  console.log('H (sha256 preimage hash):', H.toString('hex'));
  console.log('Buyer pubkey:', buyerPK.toString('hex'));

  console.log('CLTV locktime (script num):', locktime.toString());
  const lockAsNumber = Number(locktime);
  const isHeight = lockAsNumber >= 0 && lockAsNumber < 500_000_000;
  console.log('CLTV interpreted as:', isHeight ? 'block height' : 'UNIX time');

  console.log('Seller pubkey:', sellerPK.toString('hex'));
}

main();
