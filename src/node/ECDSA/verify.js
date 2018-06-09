const assert = require('assert');
const secp256k1 = require('secp256k1');
const pad32 = require('../pad32');

function verify(publicKey, msg, sig) {
  return new Promise(((resolve, reject) => {
    assert(msg.length > 0);
    assert(msg.length <= 32);
    msg = pad32(msg); // eslint-disable-line no-param-reassign
    sig = secp256k1.signatureImport(sig); // eslint-disable-line no-param-reassign
    if (secp256k1.verifySync(msg, sig, publicKey)) {
      resolve(null);
    } else {
      reject(new Error('Bad signature'));
    }
  }));
}

module.exports = verify;
