const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
bitcoin.initEccLib(ecc);

const network = bitcoin.networks.testnet;



// Where the inscription must end up (output 0)
const BUYER_DEST_ADDR = 'tb1p4hhtvwcmfu5ezyzuh9pvvrcpexzse7jhrwy2hrxql4lawgpsn4wqvfn6d5';

// Buyer change address (output 1)
const CHANGE_ADDR = 'tb1p4jx9ah3zatz7ef6wlegwuazlr7c76zs43qn7jxyaqewqz3flz9ys4lkwgm';

// Fee you want to pay (sats)
const FEE_SATS = 2000n;

// ---- Escrow UTXO (external; funded P2WSH holding inscription) ----
const ESCROW_TXID = '6444b0174629fe53318117225dae445aa353ab7a4e1a7f527de7d88d735f3f56';
const ESCROW_VOUT = 0;
const ESCROW_VALUE = 10000n;
const ESCROW_SCRIPT_PUBKEY = '0020945880073a2fd4dc53a6b4f4130df315be30ed773a2b7b694557a27dffce2cd9'; // from funding tx vout scriptPubKey.hex

// ---- Buyer fee UTXO (from buyer wallet listunspent) ----
const FEE_TXID = '6d455217e06ebb2908f0457e55f0c4afb952cdb7a7a4f1aefc914e524e5cdf98';
const FEE_VOUT = 0;
const FEE_VALUE = 10000n;            // sats (convert from BTC)
const FEE_SCRIPT_PUBKEY = '5120a845196e903d815c62f58229d10c316d4ffffbe87f247cc840897239db186146'; // from listunspent scriptPubKey

function main() {
  const change = FEE_VALUE - FEE_SATS;
  if (change <= 0n) throw new Error('Fee input too small for chosen FEE_SATS');

  const psbt = new bitcoin.Psbt({ network });

  // input 0: escrow (P2WSH)
  psbt.addInput({
    hash: ESCROW_TXID,
    index: ESCROW_VOUT,
    witnessUtxo: {
      script: Buffer.from(ESCROW_SCRIPT_PUBKEY, 'hex'),
      value: ESCROW_VALUE,
    },
  });

  // input 1: buyer fee UTXO
  psbt.addInput({
    hash: FEE_TXID,
    index: FEE_VOUT,
    witnessUtxo: {
      script: Buffer.from(FEE_SCRIPT_PUBKEY, 'hex'),
      value: FEE_VALUE,
    },
  });

  // output 0 MUST be full 10k sats to keep ordinal safe
  psbt.addOutput({ address: BUYER_DEST_ADDR, value: ESCROW_VALUE });

  // output 1: buyer change
  psbt.addOutput({ address: CHANGE_ADDR, value: change });

  console.log(psbt.toBase64());
}

main();
