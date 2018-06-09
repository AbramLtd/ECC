const assert = require('assert');
const secp256k1 = require('secp256k1');

function getPublic(privateKey) {
  assert(privateKey.length === 32);
  const compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

module.exports = getPublic;
