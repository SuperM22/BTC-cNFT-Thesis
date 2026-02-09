
// npm install bitcoinjs-lib ecpair tiny-secp256k1
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

// locktime is expressed as a block height
// choose (current height + delta) to have time to confirm funding
const REFUND_LOCKTIME = 120188 + 5;

// buyer creates address knowing only H = sha256(k)
const H_HEX = 'a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe67902988642';
const H = Buffer.from(H_HEX, 'hex');

console.log('H (sha256 of secret):', H.toString('hex'));

// Seller keys (refund branch)
const sellerKeyPair = ECPair.makeRandom({ network });
const sellerWif = sellerKeyPair.toWIF();
const sellerPubkey = sellerKeyPair.publicKey;
const sellerPubkeyHex = Buffer.from(sellerPubkey).toString('hex');

console.log('Seller WIF (KEEP SECRET):', sellerWif);
console.log('Seller pubkey:', sellerPubkeyHex);

// Buyer keys (claim branch)
const buyerKeyPair = ECPair.makeRandom({ network });
const buyerWif = buyerKeyPair.toWIF();
const buyerPubkey = buyerKeyPair.publicKey;
const buyerPubkeyHex = Buffer.from(buyerPubkey).toString('hex');

console.log('Buyer WIF (KEEP SECRET):', buyerWif);
console.log('Buyer pubkey:', buyerPubkeyHex);

console.log('Refund CLTV locktime:', REFUND_LOCKTIME);

// witness script:
//   OP_IF
//      OP_SHA256 <H> OP_EQUALVERIFY <buyer_pubkey> OP_CHECKSIG
//   OP_ELSE
//      <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <seller_pubkey> OP_CHECKSIG
//   OP_ENDIF
//


const witnessScript = bitcoin.script.compile([
  bitcoin.opcodes.OP_IF,

  bitcoin.opcodes.OP_SHA256,
  H,
  bitcoin.opcodes.OP_EQUALVERIFY,
  buyerPubkey,
  bitcoin.opcodes.OP_CHECKSIG,

  bitcoin.opcodes.OP_ELSE,

  bitcoin.script.number.encode(REFUND_LOCKTIME),
  bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
  bitcoin.opcodes.OP_DROP,
  sellerPubkey,
  bitcoin.opcodes.OP_CHECKSIG,

  bitcoin.opcodes.OP_ENDIF,
]);

const witnessScriptHex = Buffer.from(witnessScript).toString('hex');
console.log('witnessScript hex:', witnessScriptHex);

// P2WSH output/address
const p2wsh = bitcoin.payments.p2wsh({
  redeem: { output: witnessScript },
  network,
});

console.log('P2WSH scriptPubKey hex:', Buffer.from(p2wsh.output).toString('hex'));
console.log('P2WSH address:', p2wsh.address);
