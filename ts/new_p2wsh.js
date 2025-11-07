// npm install bitcoinjs-lib ecpair tiny-secp256k1
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;


const SECRET_HEX = 'f56c1a8ef50e1fc0feaa27c7d927f2bd03a9a4d040944e72e58b2aaeb20e896b'; 
const secretBuf = Buffer.from(SECRET_HEX, 'hex');


const H = crypto.createHash('sha256').update(secretBuf).digest('hex');
console.log('H (sha256 of secret):', H);


const keyPair = ECPair.makeRandom({ network });
const sellerWif = keyPair.toWIF();
const sellerPubkey = keyPair.publicKey;           // Buffer
const sellerPubkeyHex = Buffer.from(keyPair.publicKey).toString('hex');

console.log('Seller WIF (KEEP SECRET):', sellerWif);
console.log('Seller pubkey:', sellerPubkeyHex);

// build the witness script:
//    OP_SHA256 <H> OP_EQUALVERIFY <seller_pubkey> OP_CHECKSIG
const witnessScript = bitcoin.script.compile([
  bitcoin.opcodes.OP_SHA256,
  Buffer.from(H, 'hex'),
  bitcoin.opcodes.OP_EQUALVERIFY,
  sellerPubkey,
  bitcoin.opcodes.OP_CHECKSIG,
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


