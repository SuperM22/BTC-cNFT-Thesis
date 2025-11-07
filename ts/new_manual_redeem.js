// npm install bitcoinjs-lib ecpair tiny-secp256k1

const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet; 


const WITNESS_SCRIPT_HEX =
  'a820a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe679029886428821032fb23d2b944cc1986dda6047f092aac987d0b1d1f2bd9f7af1fc08d464539d14ac';

// Information about the UXTO we are redeeming
const FUND_TXID = '32cbe7241b2ac8830a22c672e2186ef19ef77e682aff58e70933afd7c8ea6a83';
const FUND_VOUT = 1;            // output index of funding tx usually the hex should be 0020 and the receiver the address of the p2wsh
const FUND_AMOUNT_SATS = 397680; //exact amount (in sats) of that output

// the secret
const SECRET_HEX = 'f56c1a8ef50e1fc0feaa27c7d927f2bd03a9a4d040944e72e58b2aaeb20e896b';

// WIF for the pubkey in the script
const SELLER_WIF = 'cTShDrKtShxhLiERY8kBD5cdFrLW3XmkysVPRH9QhkhkLFoehVTY';

// actually we can send the money to any address, so no need to match the pubkey in the script
const DEST_ADDR = 'tb1qswn95gn7h3zmcawkrhz22srak2tt29zj7c3sgm';

//maybe there could be a better way to set the fee
const FEE_SATS = 1000;


// helper: scriptPubKey (0020 + sha256(witnessScript))
function scriptPubKeyFromWitnessScript(wsHex) {
  const wsBuf = Buffer.from(wsHex, 'hex');
  const h = crypto.createHash('sha256').update(wsBuf).digest();
  return Buffer.concat([Buffer.from([0x00, 0x20]), h]);
}

// helper: extract H from script to check secret
function parseHashFromWitness(wsHex) {
  const h = wsHex.toLowerCase();
  if (!h.startsWith('a820')) throw new Error('witnessScript does not start with OP_SHA256 PUSH32');
  return h.slice(4, 4 + 64);
}

function main() {
  // check secret matches script, just done as a safety for this case in which I'm doing a simple sha256
  const H_onchain = parseHashFromWitness(WITNESS_SCRIPT_HEX);
  const secretBuf = Buffer.from(SECRET_HEX, 'hex');
  const H_secret = crypto.createHash('sha256').update(secretBuf).digest('hex');
  if (H_onchain !== H_secret) {
    throw new Error(
      `secret sha256 mismatch:\n  on-chain: ${H_onchain}\n  secret  : ${H_secret}`
    );
  }

  // 2) key
  const keyPair = ECPair.fromWIF(SELLER_WIF, network);
  const myPub = keyPair.publicKey;
  const myPubHex = Buffer.from(myPub).toString('hex');
  // also check that the pubkey inside script is this one
  const wsHex = WITNESS_SCRIPT_HEX.toLowerCase();
  const scriptPubkeyInScript = wsHex.slice(4 + 64 + 2 + 2, 4 + 64 + 2 + 2 + 66); // after a8 20 <H> 88 21
  if (scriptPubkeyInScript !== myPubHex) {
    throw new Error(
      `pubkey mismatch:\n  in script: ${scriptPubkeyInScript}\n  from WIF: ${myPubHex}`
    );
  }

  // 3) build transaction manually
  const tx = new bitcoin.Transaction();
  tx.version = 2;

  // input: txid must be little-endian in the tx
  // oc the input must refer to the funding tx output
  const txidBuf = Buffer.from(FUND_TXID, 'hex').reverse();
  tx.addInput(txidBuf, FUND_VOUT, 0xfffffffd); // last part used for RBF enabling

  // output
  const sendSats = FUND_AMOUNT_SATS - FEE_SATS;
  if (sendSats <= 0) throw new Error('fee too high for this input');
  const outScript = bitcoin.address.toOutputScript(DEST_ADDR, network);
  const BSats=BigInt(sendSats);
  tx.addOutput(outScript, BSats);

  // 4) sign the input for segwit v0
  const witnessScriptBuf = Buffer.from(WITNESS_SCRIPT_HEX, 'hex');

  const sighash = tx.hashForWitnessV0(
    0,                      // input index
    witnessScriptBuf,       // script we are satisfying
    BigInt(FUND_AMOUNT_SATS),       // amount of the utxo
    bitcoin.Transaction.SIGHASH_ALL
  );

  const signature = keyPair.sign(sighash);
  const derSig = bitcoin.script.signature.encode(signature, bitcoin.Transaction.SIGHASH_ALL);

  //final witness: [sig, secret, witnessScript]
  tx.ins[0].witness = [
    derSig,
    secretBuf,
    witnessScriptBuf,
  ];

  const finalHex = tx.toHex();
  console.log('\n final tx hex:\n');
  console.log(finalHex);
  console.log('\nBroadcast with:');
  console.log('bitcoin-cli -testnet4 sendrawtransaction', finalHex);
}

main();
