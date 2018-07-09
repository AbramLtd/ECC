var EC = require("elliptic").ec;
var ec = new EC("secp256k1");
const assert = require('assert');

function sign(privateKey, msg) {
  assert(privateKey.length === 32, "Bad private key");
  assert(msg.length > 0);
  assert(msg.length <= 32);
  return new Buffer(ec.sign(msg, privateKey, {canonical: true}).toDER());
}

module.exports = sign;
