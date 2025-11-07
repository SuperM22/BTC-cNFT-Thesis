// 'usage: node check_secret.js <SECRET_HEX>'
const crypto = require('crypto');

const WITNESS_SCRIPT_HEX = 'a82094c6c858e0cbe5c8bce37a5565c10b727ee7c69017d6b4d3061513c0fb0bc92f882103594fb24289ab3851d8b05ef9b2b4e88837d9259e15b9c077b74f6f9de7aa10ddac';

// 1. extract on-chain hash
const H_onchain = WITNESS_SCRIPT_HEX.slice(4, 4 + 64);
console.log('H_onchain:', H_onchain);

// secret 
const SECRET_HEX = process.argv[2];  // pass on CLI
if (!SECRET_HEX) {
  console.log("Pass the secret as first argument");
  process.exit(1);
}

// 3. compute sha256(secret)
const secretBuf = Buffer.from(SECRET_HEX, 'hex');
const H_computed = crypto.createHash('sha256').update(secretBuf).digest('hex');

console.log('H_computed:', H_computed);

if (H_computed.toLowerCase() === H_onchain.toLowerCase()) {
  console.log(' match');
} else {
  console.log(' mismatch !!!!!!');
}
