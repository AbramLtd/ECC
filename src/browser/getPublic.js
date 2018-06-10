const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

const { Buffer } = require('buffer/');

function getPublic(privateKey) {
  if (privateKey.length !== 32) {
    throw new Error('Bad private key');
  }
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic('arr'));
}

module.exports = getPublic;
