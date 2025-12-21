// npm install bitcoinjs-lib ecpair tiny-secp256k1
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

const WITNESS_SCRIPT_HEX = '63a820a9674085e84fcc06fe764ff6f4f2c1e6a34c102e317898c4468fe679029886428821024f1af5a2ea274cdc130bfb0144ace9fb33ee69576e613d50f77dc48e21728281ac6703bebb01b17521032e12ce8008beee5676d59c45a676ff18c49b4968167c93f4985c52d4c6e62d21ac68';


const FUND_TXID = '9dc29101710175c56d0d0a7cc81f2db8182e62e0b4f1fc926e422f9b1ec1a32d';
const FUND_VOUT = 0;               // correct vout index
const FUND_AMOUNT_SATS = 107207;        // exact amount in sats locked in that UTXO


const BUYER_WIF = 'cNqDi4Y1JTeF1vhXmGJD7kLFk4p5owWg5ng6aBQmQxcmaMhFZ5wJ';
const BUYER_REFUND_ADDR = 'tb1q0faus7uustav35hp06x4vje9jmmcwag55njesd';//it can be whatever

// Must match the locktime value embedded in the witnessScript (the CLTV branch)
const REFUND_LOCKTIME = 113596 + 2;   // example block height (or unix time >= 500,000,000)

// Fee
const FEE_SATS = 1000;


function decompileOrThrow(buf) {
  const chunks = bitcoin.script.decompile(buf);
  if (!chunks) throw new Error('Cannot decompile witness script');
  return chunks;
}

function main() {
  const witnessScriptBuf = Buffer.from(WITNESS_SCRIPT_HEX, 'hex');
  const chunks = decompileOrThrow(witnessScriptBuf);

  // Optional sanity: check the script contains OP_CHECKLOCKTIMEVERIFY
  if (!chunks.includes(bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY)) {
    throw new Error('Witness script does not contain OP_CHECKLOCKTIMEVERIFY (CLTV)');
  }

  // Build tx
  const tx = new bitcoin.Transaction();
  tx.version = 2;

  // IMPORTANT for CLTV: sequence must be non-final (locktime must be enabled)
  // already use 0xfffffffd in seller script; same idea here.
  const txidBuf = Buffer.from(FUND_TXID, 'hex').reverse();
  tx.addInput(txidBuf, FUND_VOUT, 0xfffffffd);

  // IMPORTANT for CLTV: tx.locktime must be >= REFUND_LOCKTIME
  tx.locktime = REFUND_LOCKTIME;

  // Output: refund to buyer
  const sendSats = FUND_AMOUNT_SATS - FEE_SATS;
  if (sendSats <= 0) throw new Error('fee too high for this input');
  const outScript = bitcoin.address.toOutputScript(BUYER_REFUND_ADDR, network);
  tx.addOutput(outScript, BigInt(sendSats));

  // Sign (SegWit v0): digest covers the input amount (BIP143). :contentReference[oaicite:3]{index=3}
  const buyerKey = ECPair.fromWIF(BUYER_WIF, network);

  const sighash = tx.hashForWitnessV0(
    0,
    witnessScriptBuf,
    BigInt(FUND_AMOUNT_SATS),
    bitcoin.Transaction.SIGHASH_ALL
  );

  const sig = buyerKey.sign(sighash);
  const derSig = bitcoin.script.signature.encode(sig, bitcoin.Transaction.SIGHASH_ALL);

  // Witness stack for refund (ELSE branch):
  //   [buyerSig, 0, witnessScript]
  // The "0" selects the ELSE branch of OP_IF ... OP_ELSE ... OP_ENDIF.
  tx.ins[0].witness = [
    derSig,
    Buffer.alloc(0),
    witnessScriptBuf,
  ];

  const finalHex = tx.toHex();
  console.log('\n[BUYER REFUND] final tx hex:\n');
  console.log(finalHex);
  console.log('\nBroadcast with:');
  console.log('bitcoin-cli sendrawtransaction', finalHex);
}

main();
