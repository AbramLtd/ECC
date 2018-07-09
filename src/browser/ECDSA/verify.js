var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
const assert = require('assert');

function verify(publicKey, msg, sig) {
  assert(publicKey.length === 65, "Bad public key");
  assert(publicKey[0] === 4, "Bad public key");
  assert(msg.length > 0, "Message should not be empty");
  assert(msg.length <= 32, "Message is too long");
  if (ec.verify(msg, sig, publicKey)) {
    return true;
  } else {
    return false;
  }
}

module.exports = verify;
