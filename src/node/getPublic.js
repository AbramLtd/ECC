const assert = require('assert');
const secp256k1 = require('secp256k1');

function getPublic(privateKey) {
  assert(privateKey.length === 32, 'private key needs to be 32 bytes long');
  const compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

module.exports = getPublic;
