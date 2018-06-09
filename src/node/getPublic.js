const secp256k1 = require('secp256k1');

function getPublic(privateKey) {
  const compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.publicKeyConvert(compressed, false);
}

module.exports = getPublic;
