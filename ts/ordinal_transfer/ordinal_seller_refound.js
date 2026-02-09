
const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

// ---------- Escrow (P2WSH) input holding the inscribed sat ----------
const WITNESS_SCRIPT_HEX = '...';
const ESCROW_TXID = '...';
const ESCROW_VOUT = 0;
const ESCROW_AMOUNT_SATS = 1;

// Must match the locktime embedded in the witness script
const REFUND_LOCKTIME = 113596 + 20;

// ---------- Fee (P2WPKH) input to pay mining fees ----------
const FEE_TXID = '...';
const FEE_VOUT = 0;
const FEE_AMOUNT_SATS = 20000;
const FEE_WIF = '...';                // seller fee key (P2WPKH)

// ---------- Seller refund signer (ELSE branch) ----------
const SELLER_WIF = '...';             // must match seller pubkey embedded in witnessScript

// ---------- Outputs ----------
const ORDINAL_REFUND_ADDR = 'tb1...';  // output0: seller gets the inscribed sat back (1 sat)
const FEE_CHANGE_ADDR = 'tb1...';      // output1: change back to fee payer

const FEE_SATS = 2500;

function main() {
  const witnessScriptBuf = Buffer.from(WITNESS_SCRIPT_HEX, 'hex');

  const sellerKey = ECPair.fromWIF(SELLER_WIF, network);
  const feeKey = ECPair.fromWIF(FEE_WIF, network);

  const tx = new bitcoin.Transaction();
  tx.version = 2;

  // input 0: escrow P2WSH holding ordinal
  tx.addInput(Buffer.from(ESCROW_TXID, 'hex').reverse(), ESCROW_VOUT, 0xfffffffd);

  // input 1: fee P2WPKH
  tx.addInput(Buffer.from(FEE_TXID, 'hex').reverse(), FEE_VOUT, 0xfffffffd);

  // Required for CLTV
  tx.locktime = REFUND_LOCKTIME;

  // outputs:
  tx.addOutput(bitcoin.address.toOutputScript(ORDINAL_REFUND_ADDR, network), 1n);

  const totalIn = BigInt(ESCROW_AMOUNT_SATS) + BigInt(FEE_AMOUNT_SATS);
  const change = totalIn - 1n - BigInt(FEE_SATS);
  if (change <= 0n) throw new Error('insufficient funds for fee');

  tx.addOutput(bitcoin.address.toOutputScript(FEE_CHANGE_ADDR, network), change);

  // -------- Sign input 0 (P2WSH escrow) --------
  const sighash0 = tx.hashForWitnessV0(
    0,
    witnessScriptBuf,
    BigInt(ESCROW_AMOUNT_SATS),
    bitcoin.Transaction.SIGHASH_ALL
  );
  const sig0 = sellerKey.sign(sighash0);
  const derSig0 = bitcoin.script.signature.encode(sig0, bitcoin.Transaction.SIGHASH_ALL);

  // ELSE branch witness:
  // [ sellerSig, FALSE, witnessScript ]
  tx.ins[0].witness = [derSig0, Buffer.alloc(0), witnessScriptBuf];

  // -------- Sign input 1 (P2WPKH fee input) --------
  const p2pkhScriptCode = bitcoin.payments.p2pkh({ pubkey: feeKey.publicKey, network }).output;
  if (!p2pkhScriptCode) throw new Error('failed to build p2pkh scriptCode for fee input');

  const sighash1 = tx.hashForWitnessV0(
    1,
    p2pkhScriptCode,
    BigInt(FEE_AMOUNT_SATS),
    bitcoin.Transaction.SIGHASH_ALL
  );

  const sig1 = feeKey.sign(sighash1);
  const derSig1 = bitcoin.script.signature.encode(sig1, bitcoin.Transaction.SIGHASH_ALL);

  tx.ins[1].witness = [derSig1, feeKey.publicKey];

  const finalHex = tx.toHex();

  console.log('\n[SELLER REFUND 2-IN] final tx hex:\n');
  console.log(finalHex);

  console.log('\nBroadcast with:');
  console.log('bitcoin-cli -testnet4 sendrawtransaction', finalHex);
}

main();
