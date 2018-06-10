const assert = require('assert');
const secp256k1 = require('secp256k1');
const pad32 = require('../pad32');

function sign(privateKey, msg) {
  assert(msg.length > 0);
  assert(msg.length <= 32);
  msg = pad32(msg); // eslint-disable-line no-param-reassign
  const sig = secp256k1.sign(msg, privateKey).signature;
  return secp256k1.signatureExport(sig);
}

module.exports = sign;
