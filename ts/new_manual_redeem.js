// new_manual_redeem.js  

//
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;


const WITNESS_SCRIPT_HEX = '63a820a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe679029886428821032cf2be5331d17b843d4df5c0353e8da6f3b0bf030001b0012c22fa0ccf26bb91ac6703bebb01b175210261f3b9b4e37ff30563fecbc9860f8dc698a5b9706fe18ba55afd0ec9f343c97fac68';

// The UTXO you are spending (funded P2WSH output)
const FUND_TXID = '96ac29c7115d652fc0f210b3a32516737f9b596e80cd35a3d6d51e12af45e145';  // big-endian hex
const FUND_VOUT = 1;                          // output index
const FUND_AMOUNT_SATS = 123579;                   // MUST be exact amount of that UTXO

// Seller redeem data (IF branch)
const SECRET_HEX = 'f56c1a8ef50e1fc0feaa27c7d927f2bd03a9a4d040944e72e58b2aaeb20e896b';
const SELLER_WIF = 'cSimRiT5BbwTFmg6FLRTK2rrRLCuz61gbGFgwCDbMzrzyNFqbfvj';
const DEST_ADDR = 'tb1q0faus7uustav35hp06x4vje9jmmcwag55njesd';//it can be whatever 

// Fee
const FEE_SATS = 1000;


function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

/**
 * Parse the timelocked IF/ELSE witness script by decompiling Script chunks.
 *   structure is:
 *   OP_IF
 *      OP_SHA256 <H32> OP_EQUALVERIFY <sellerPub> OP_CHECKSIG
 *   OP_ELSE
 *      <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <buyerPub> OP_CHECKSIG
 *   OP_ENDIF
 *
 * I only need:
 *  - H (32 bytes) after OP_SHA256
 *  - seller pubkey before the first OP_CHECKSIG (in IF branch)
 */

//This function extracts H and seller pubkey from the witness script
//only needed for sanity check before building the tx
function parseSellerHAndPubkeyFromTimelockScript(witnessScriptBuf) {
  const chunks = bitcoin.script.decompile(witnessScriptBuf);
  if (!chunks) throw new Error('cannot decompile witnessScript');

  // Find OP_SHA256 then read next pushed buffer as H
  const shaPos = chunks.findIndex((c) => c === bitcoin.opcodes.OP_SHA256);
  if (
    shaPos < 0 ||
    !Buffer.isBuffer(chunks[shaPos + 1]) ||
    chunks[shaPos + 1].length !== 32
  ) {
    throw new Error('cannot find 32-byte H after OP_SHA256 in witnessScript');
  }
  const H = chunks[shaPos + 1];

  // Find the FIRST OP_CHECKSIG after OP_SHA256 (seller branch)
  const checksigPos = chunks.findIndex(
    (c, i) => c === bitcoin.opcodes.OP_CHECKSIG && i > shaPos
  );
  if (checksigPos < 0 || !Buffer.isBuffer(chunks[checksigPos - 1])) {
    throw new Error('cannot find seller pubkey before first OP_CHECKSIG');
  }
  const sellerPub = chunks[checksigPos - 1];

  return { H, sellerPub };
}

function main() {
  const witnessScriptBuf = Buffer.from(WITNESS_SCRIPT_HEX, 'hex');

  // Parse H + seller pubkey from script
  const { H, sellerPub } = parseSellerHAndPubkeyFromTimelockScript(witnessScriptBuf);

  // Check secret matches H
  const secretBuf = Buffer.from(SECRET_HEX, 'hex');
  const H_secret = sha256(secretBuf);
  if (!H_secret.equals(H)) {
    throw new Error(
      `secret sha256 mismatch:\n  H in script: ${H.toString('hex')}\n  H(secret) : ${H_secret.toString('hex')}`
    );
  }

  // Load seller key and verify pubkey matches the one embedded in script
  const sellerKey = ECPair.fromWIF(SELLER_WIF, network);
  const sellerKeyPub = Buffer.from(sellerKey.publicKey); 
  if (!sellerKeyPub.equals(sellerPub)) {
    throw new Error(
      `seller pubkey mismatch:\n  pubkey in script: ${sellerPub.toString('hex')}\n  pubkey from WIF : ${sellerKey.publicKey.toString('hex')}`
    );
  }

  // Build transaction
  const tx = new bitcoin.Transaction();
  tx.version = 2;

  // IMPORTANT: sequence must be non-final for locktime-enabled scripts.
  // Seller branch doesn't require locktime, but using non-final is safe and matches your previous style.
  const txidBuf = Buffer.from(FUND_TXID, 'hex').reverse();
  tx.addInput(txidBuf, FUND_VOUT, 0xfffffffd);

  // Seller redeem does NOT need locktime; keep it 0
  tx.locktime = 0;

  // Output
  const sendSats = FUND_AMOUNT_SATS - FEE_SATS;
  if (sendSats <= 0) throw new Error('fee too high for this input amount');

  const outScript = bitcoin.address.toOutputScript(DEST_ADDR, network);
  tx.addOutput(outScript, BigInt(sendSats));

  // SegWit v0 sighash (P2WSH)
  const sighash = tx.hashForWitnessV0(
    0,
    witnessScriptBuf,
    BigInt(FUND_AMOUNT_SATS),
    bitcoin.Transaction.SIGHASH_ALL
  );

  const sig = sellerKey.sign(sighash);
  const derSig = bitcoin.script.signature.encode(sig, bitcoin.Transaction.SIGHASH_ALL);

  // Witness stack for seller redeem (IF branch):
  //   [ sellerSig, secret, TRUE, witnessScript ]
  // TRUE selects the OP_IF branch.
  tx.ins[0].witness = [
    derSig,
    secretBuf,
    Buffer.from([1]),
    witnessScriptBuf,
  ];

  const finalHex = tx.toHex();

  console.log('\n[SELLER REDEEM] final tx hex:\n');
  console.log(finalHex);

  console.log('\nBroadcast with:');
  console.log('bitcoin-cli -testnet4 sendrawtransaction', finalHex);
}

main();
