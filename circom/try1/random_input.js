
const crypto = require("crypto");
const fs = require("fs");


const K_raw = crypto.randomBytes(32);


const K = [];
for (let i = 0; i < K_raw.length; i++) {
  const byte = K_raw[i];
  for (let b = 7; b >= 0; b--) {
    K.push((byte >> b) & 1);
  }
}



const inputObj = { K };
fs.writeFileSync("build/input.json", JSON.stringify(inputObj, null, 2));

console.log("K_RAW_HEX =", K_raw.toString("hex"));
console.log("Wrote build/input.json with", K.length, "bits");
