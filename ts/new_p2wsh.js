// npm install bitcoinjs-lib ecpair tiny-secp256k1
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

//the locktime is expressed as a block height
//that s the current block height + a small delta to allow the funding tx to confirm
//one block is ~10 minutes, so delta of 2 is ~15/20 minutes
const REFUND_LOCKTIME = 113596 + 2; // ~15 minutes later than funding tx block height 

//here the secret should not be hardcoded, because the buyer should create the address just knwoing the value H(k).

//const SECRET_HEX = 'f56c1a8ef50e1fc0feaa27c7d927f2bd03a9a4d040944e72e58b2aaeb20e896b'; 
//const secretBuf = Buffer.from(SECRET_HEX, 'hex');

const H_HEX = 'a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe67902988642';





//const H = crypto.createHash('sha256').update(secretBuf).digest('hex');
const H = Buffer.from(H_HEX, 'hex');
//console.log('H (sha256 of secret):', H);
console.log('H (sha256 of secret):', H.toString('hex'));
// Seller keys

const keyPair = ECPair.makeRandom({ network });
const sellerWif = keyPair.toWIF();
const sellerPubkey = keyPair.publicKey;           // Buffer
const sellerPubkeyHex = Buffer.from(keyPair.publicKey).toString('hex');

console.log('Seller WIF (KEEP SECRET):', sellerWif);
console.log('Seller pubkey:', sellerPubkeyHex);

// Buyer keys

const buyerKeyPair = ECPair.makeRandom({ network });
const buyerWif = buyerKeyPair.toWIF();
const buyerPubkey = buyerKeyPair.publicKey;
const buyerPubkeyHex = Buffer.from(buyerPubkey).toString('hex');

console.log('Buyer WIF (KEEP SECRET):', buyerWif);
console.log('Buyer pubkey:', buyerPubkeyHex);
console.log('Refund CLTV locktime:', REFUND_LOCKTIME);

// build the witness script:
//    OP_SHA256 <H> OP_EQUALVERIFY <seller_pubkey> OP_CHECKSIG
const witnessScript = bitcoin.script.compile([
  bitcoin.opcodes.OP_IF,

  bitcoin.opcodes.OP_SHA256,
  //Buffer.from(H, 'hex'),
  H,
  bitcoin.opcodes.OP_EQUALVERIFY,
  sellerPubkey,
  bitcoin.opcodes.OP_CHECKSIG,

  bitcoin.opcodes.OP_ELSE,

  bitcoin.script.number.encode(REFUND_LOCKTIME),
  bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
  bitcoin.opcodes.OP_DROP,
  buyerPubkey,
  bitcoin.opcodes.OP_CHECKSIG,

  bitcoin.opcodes.OP_ENDIF,
]);

const witnessScriptHex = Buffer.from(witnessScript).toString('hex');
console.log('witnessScript hex:', witnessScriptHex);

// turn it into a P2WSH address
const p2wsh = bitcoin.payments.p2wsh({
  redeem: { output: witnessScript },
  network,
});

console.log('P2WSH scriptPubKey hex:', Buffer.from(p2wsh.output).toString('hex')); 
console.log('P2WSH address:', p2wsh.address);


