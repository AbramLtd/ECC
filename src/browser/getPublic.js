const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

const { Buffer } = require('buffer/');

function getPublic(privateKey) {
  console.assert(privateKey.length === 32, 'Bad private key');
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic('arr'));
}

module.exports = getPublic;
