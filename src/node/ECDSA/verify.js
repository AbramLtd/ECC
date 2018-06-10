const assert = require('assert');
const secp256k1 = require('secp256k1');
const pad32 = require('../pad32');

function verify(publicKey, msg, sig) {
  assert(msg.length > 0);
  assert(msg.length <= 32);
  msg = pad32(msg); // eslint-disable-line no-param-reassign
  sig = secp256k1.signatureImport(sig); // eslint-disable-line no-param-reassign
  if (secp256k1.verify(msg, sig, publicKey)) {
    return true;
  }
  return false;
}

module.exports = verify;
